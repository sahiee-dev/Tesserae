"""
agentops_sdk/client.py - Main SDK Entry Point
"""
from __future__ import annotations


import json
import uuid
from typing import Any

from agentops_sdk.buffer import RingBuffer
from agentops_sdk.envelope import build_event, GENESIS_HASH
from agentops_sdk.events import EventType


class AgentOpsClient:
    """
    Main entry point for the AgentOps Replay SDK.

    Two modes:
    - local_authority=True (default): Flush to JSONL file. No server required.
      Evidence class: NON_AUTHORITATIVE_EVIDENCE.
    - local_authority=False: POST to Ingestion Service.
      Evidence class: AUTHORITATIVE_EVIDENCE (if no LOG_DROP).

    CRITICAL: Never raises exceptions that propagate to caller.
    All errors are handled internally and recorded as LOG_DROP.
    """

    def __init__(
        self,
        local_authority: bool = True,
        server_url: str | None = None,
        buffer_size: int = 1000,
        agent_id: str | None = None,
    ) -> None:
        self._local_authority = local_authority
        self._server_url = server_url
        self._agent_id = agent_id or str(uuid.uuid4())
        self._buffer = RingBuffer(capacity=max(buffer_size, 1))
        self._session_id: str | None = None
        self._finished_session_id: str | None = None
        self._next_seq: int = 1
        self._last_hash: str = GENESIS_HASH
        self._private_key = None
        self._public_key_b64: str | None = None

    @property
    def session_id(self) -> str | None:
        """Current or most recent session ID."""
        return self._session_id or self._finished_session_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_session(
        self,
        agent_id: str | None = None,
        metadata: dict | None = None,
    ) -> str:
        """
        Start a new recording session. Emits SESSION_START as seq=1.
        If a session is already active, ends it with status='error' first.
        Never raises.
        """
        if self._session_id is not None:
            # FIX 1: double-call must not raise — end previous session cleanly
            self.end_session(status="error")

        self._session_id = str(uuid.uuid4())
        self._next_seq = 1
        self._last_hash = GENESIS_HASH

        # Generate a fresh Ed25519 keypair for this session.
        # The public key travels in SESSION_START so the verifier is self-contained.
        try:
            from agentops_sdk.signing import generate_keypair
            self._private_key, self._public_key_b64 = generate_keypair()
        except Exception:
            self._private_key = None
            self._public_key_b64 = None

        payload: dict[str, Any] = {
            "agent_id": agent_id or self._agent_id,
        }
        if self._public_key_b64:
            payload["sdk_public_key"] = self._public_key_b64
        if metadata:
            payload.update(metadata)

        self._append_event(EventType.SESSION_START.value, payload)
        return self._session_id

    def record(
        self,
        event_type: EventType,
        payload: dict,
    ) -> None:
        """
        Record an event in the current session. Never raises.
        Server-authority event types are silently dropped as LOG_DROP.
        """
        # FIX 2: no active session — return silently
        if self._session_id is None:
            return

        from agentops_sdk.events import EventType
        if isinstance(event_type, EventType) and not event_type.is_sdk_authority:
            # Treat as a buffer overflow / LOG_DROP
            self._emit_log_drop(reason="SERVER_AUTHORITY_VIOLATION")
            return

        # Flush any pending buffer overflow drops first
        if self._buffer.has_pending_drops():
            self._emit_log_drop(reason="buffer_overflow")

        self._append_event(event_type.value, payload)

    def end_session(
        self,
        status: str = "success",
        duration_ms: int | None = None,
        exit_reason: str | None = None,
    ) -> None:
        """
        End the current session. Emits SESSION_END as the last SDK event.
        FIX 3: Never emits CHAIN_SEAL — that is server-only.
        Never raises.

        SESSION_END is a terminal invariant: if the buffer is full, pending
        drops are flushed first to make room, then SESSION_END is force-appended
        directly to guarantee it always lands in the chain.
        """
        if self._session_id is None:
            return

        # If buffer is full, flush pending drop record first to make room
        if self._buffer.has_pending_drops():
            self._emit_log_drop(reason="buffer_overflow")

        payload: dict[str, Any] = {"status": status}
        if duration_ms is not None:
            payload["duration_ms"] = duration_ms
        if exit_reason is not None:
            payload["exit_reason"] = exit_reason

        # Compute Merkle root over all events buffered so far (not including SESSION_END).
        # Root is sealed inside SESSION_END payload, which is then Ed25519-signed.
        # This gives a compact 32-byte commitment to the entire session that can be
        # published externally independent of the full JSONL file.
        try:
            from agentops_sdk.merkle import compute_merkle_root
            with self._buffer._lock:
                buffered = sorted(self._buffer._events, key=lambda e: e.get("seq", 0))
            hashes = [e["event_hash"] for e in buffered if "event_hash" in e]
            payload["merkle_root"] = compute_merkle_root(hashes)
            payload["merkle_leaf_count"] = len(hashes)
        except Exception:
            pass  # Merkle failure must never crash the agent

        try:
            event = build_event(
                seq=self._next_seq,
                event_type=EventType.SESSION_END.value,
                session_id=self._session_id,
                payload=payload,
                prev_hash=self._last_hash,
                private_key=self._private_key,
            )
            # Force-append: SESSION_END must always be the last event in the chain
            self._buffer._events.append(event)
            self._next_seq += 1
            self._last_hash = event["event_hash"]
        except Exception:
            pass  # Never crash the agent on end_session

        # FIX 3: session_id cleared — no CHAIN_SEAL emitted
        self._finished_session_id = self._session_id
        self._session_id = None

    def flush_to_jsonl(self, path: str) -> None:
        """
        Write all buffered events to a JSONL file. Each line is one JSON event.
        Events are ordered by seq ascending.
        """
        events = self._buffer.drain()
        with open(path, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")

    def send_to_server(self) -> dict:
        """
        POST all buffered events to the Ingestion Service.
        Raises ValueError if local_authority=True.
        Raises ConnectionError after 3 failed retries.
        """
        if self._local_authority:
            raise ValueError("Cannot send to server in local_authority mode.")

        if self._server_url is None:
            raise ValueError("server_url is required when local_authority=False.")

        from agentops_sdk.sender import EventSender  # FIX 5: no httpx/remote_client
        sender = EventSender(server_url=self._server_url)
        events = self._buffer.drain()
        session_id = self._session_id or self._finished_session_id or "unknown"
        return sender.send_batch(
            session_id=session_id,
            events=events,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _append_event(self, event_type: str, payload: dict) -> None:
        """Build an event envelope and push it to the buffer."""
        try:
            event = build_event(
                seq=self._next_seq,
                event_type=event_type,
                session_id=self._session_id or "unknown",
                payload=payload,
                prev_hash=self._last_hash,
                private_key=self._private_key,
            )
            pushed = self._buffer.push(event)
            if pushed:
                self._next_seq += 1
                self._last_hash = event["event_hash"]
            # If not pushed: drop record is accumulated in the buffer.
            # LOG_DROP will be emitted lazily in end_session when space is freed.
        except Exception:
            self._emit_log_drop(reason="internal_error")

    def _emit_log_drop(self, reason: str = "buffer_overflow") -> None:
        """Internal: emit a LOG_DROP event. Never raises.

        Force-appends directly to the buffer's internal list to guarantee
        LOG_DROP always lands even when the buffer is at capacity.
        """
        try:
            drop_record = self._buffer.get_and_clear_drop_record()
            if drop_record is None and reason == "buffer_overflow":
                # No drops accumulated — nothing to report
                return
            payload = {
                "count": drop_record.count if drop_record else 1,
                "reason": reason,
                "seq_range_start": drop_record.seq_start if drop_record else self._next_seq,
                "seq_range_end": drop_record.seq_end if drop_record else self._next_seq,
            }
            event = build_event(
                seq=self._next_seq,
                event_type=EventType.LOG_DROP.value,
                session_id=self._session_id or "unknown",
                payload=payload,
                prev_hash=self._last_hash,
                private_key=self._private_key,
            )
            # Force-append: LOG_DROP must land even when buffer is full
            self._buffer._events.append(event)
            self._next_seq += 1
            self._last_hash = event["event_hash"]
        except Exception:
            pass  # LOG_DROP must never crash the agent
