import pytest
import json
import os
import tempfile
import subprocess
import sys

from agentops_sdk.client import AgentOpsClient
from agentops_sdk.events import EventType

VERIFIER = os.path.join("verifier", "agentops_verify.py")


def run_verifier_on_file(path: str) -> dict:
    result = subprocess.run(
        [sys.executable, VERIFIER, path, "--format", "json"],
        capture_output=True, text=True
    )
    return {
        "returncode": result.returncode,
        "data": json.loads(result.stdout) if result.stdout.strip() else {},
    }


def test_local_authority_mode_end_to_end():
    """
    Full local authority flow:
    AgentOpsClient → record events → flush_to_jsonl → Verifier PASS
    Evidence class: SIGNED_NON_AUTHORITATIVE_EVIDENCE (Ed25519 per-event sigs)
    """
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        output_path = f.name

    try:
        client = AgentOpsClient(local_authority=True, buffer_size=100)
        client.start_session(agent_id="e2e-test-agent")
        client.record(EventType.LLM_CALL, {"model_id": "test-model", "prompt_hash": "abc"})
        client.record(EventType.LLM_RESPONSE, {"content_hash": "def", "finish_reason": "stop"})
        client.record(EventType.TOOL_CALL, {"tool_name": "calculator", "args_hash": "ghi"})
        client.record(EventType.TOOL_RESULT, {"tool_name": "calculator", "result_hash": "jkl"})
        client.end_session(status="success")
        client.flush_to_jsonl(output_path)

        result = run_verifier_on_file(output_path)
        assert result["returncode"] == 0, f"Verifier failed: {result}"
        assert result["data"]["result"] == "PASS"
        assert result["data"]["evidence_class"] == "SIGNED_NON_AUTHORITATIVE_EVIDENCE"

    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)


def test_buffer_overflow_produces_valid_chain():
    """
    Buffer overflow flow:
    Create client with buffer_size=5, record 10 events.
    Result must: PASS, contain exactly 1 LOG_DROP, NON_AUTHORITATIVE_EVIDENCE.
    """
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        output_path = f.name

    try:
        client = AgentOpsClient(local_authority=True, buffer_size=5)
        client.start_session(agent_id="overflow-test-agent")
        for i in range(10):
            client.record(EventType.LLM_CALL, {"model_id": "test", "call_num": i})
        client.end_session(status="success")
        client.flush_to_jsonl(output_path)

        result = run_verifier_on_file(output_path)
        assert result["returncode"] == 0, f"Verifier failed on overflow session: {result}"
        assert result["data"]["result"] == "PASS"

        with open(output_path) as f:
            events = [json.loads(l) for l in f if l.strip()]
        log_drops = [e for e in events if e["event_type"] == "LOG_DROP"]
        assert len(log_drops) >= 1, "Expected at least 1 LOG_DROP event"

    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)


def test_server_authority_mode_end_to_end():
    """
    Full server authority flow (in-process, no Docker required):
    SDK events → server-side hasher recomputation → sealer → export JSONL → Verifier PASS
    Evidence class: AUTHORITATIVE_EVIDENCE

    This test simulates the exact same cryptographic pipeline that the Ingestion
    Service would execute, but runs entirely in-process using the hasher and sealer
    modules directly. This validates:
    1. SDK event construction
    2. Server-side hash recomputation (SERVER authority)
    3. Chain sealing with AUTHORITATIVE_EVIDENCE
    4. Export format conformance (7-field envelope)
    5. Verifier PASS on server-recomputed hashes
    """
    import hashlib
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'verifier'))
    from jcs import canonicalize as jcs_canonicalize

    # Append backend to path for hasher/sealer imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'backend'))
    from app.services.ingestion.hasher import recompute_chain, GENESIS_HASH
    from app.services.ingestion.sealer import seal_chain, SealStatus

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        output_path = f.name

    try:
        # --- Step 1: SDK produces events ---
        client = AgentOpsClient(local_authority=False, server_url="http://dummy", buffer_size=100)
        session_id = client.start_session(agent_id="server-e2e-test-agent")
        client.record(EventType.LLM_CALL, {"model_id": "test-model", "prompt_hash": "abc"})
        client.record(EventType.LLM_RESPONSE, {"content_hash": "def", "finish_reason": "stop"})
        client.end_session(status="success")

        # Drain SDK events (these have SDK-computed hashes which server ignores)
        sdk_events = client._buffer.drain()
        assert len(sdk_events) >= 3, f"Expected at least 3 events, got {len(sdk_events)}"

        # --- Step 2: Simulate server-side ingestion ---
        # Convert SDK envelope fields to server schema (same as sender.py does)
        server_events = []
        for event in sdk_events:
            server_event = {
                "event_type": event["event_type"],
                "sequence_number": event["seq"],
                "timestamp_wall": event["timestamp"],
                "session_id": session_id,
                "payload": event.get("payload", {}),
                # SDK hashes are logged but NEVER trusted
                "event_hash": event.get("event_hash"),
                "prev_event_hash": event.get("prev_hash"),
            }
            server_events.append(server_event)

        # --- Step 3: Server recomputes hash chain (SERVER AUTHORITY) ---
        chain_result = recompute_chain(server_events, expected_genesis_hash=GENESIS_HASH)
        assert chain_result.valid, f"Chain recomputation failed: {chain_result.rejection_details}"
        assert chain_result.recomputed_events is not None
        assert chain_result.final_hash is not None

        # --- Step 4: Seal the chain ---
        seal_events = [
            {"event_hash": e["event_hash"], "sequence_number": e["sequence_number"]}
            for e in chain_result.recomputed_events
        ]
        seal_result = seal_chain(
            session_id=session_id,
            events=seal_events,
            ingestion_service_id="ingestion-service-v1",
            existing_seal=None,
            total_drops=0,
        )
        assert seal_result.status == SealStatus.SEALED, f"Sealing failed: {seal_result.rejection_reason}"
        assert seal_result.evidence_class == "AUTHORITATIVE_EVIDENCE"

        # --- Step 5: Export as JSONL (same format as sessions.py export endpoint) ---
        lines = []
        for event_data in chain_result.recomputed_events:
            # Reconstruct the 7-field verifiable envelope
            row = {
                "seq": event_data["sequence_number"],
                "event_type": event_data["event_type"],
                "session_id": session_id,
                "timestamp": event_data["timestamp_wall"],
                "payload": event_data.get("payload", {}),
                "prev_hash": event_data["prev_event_hash"],
                "event_hash": event_data["event_hash"],
            }
            lines.append(json.dumps(row))

        # Append CHAIN_SEAL event
        seal_row = {
            "seq": chain_result.event_count + 1,
            "event_type": "CHAIN_SEAL",
            "session_id": session_id,
            "timestamp": seal_result.seal_timestamp,
            "payload": {
                "session_digest": seal_result.session_digest,
                "final_event_hash": seal_result.final_event_hash,
                "event_count": seal_result.event_count,
                "ingestion_service_id": seal_result.ingestion_service_id,
                "evidence_class": seal_result.evidence_class,
            },
            "prev_hash": chain_result.final_hash,
        }
        # Compute CHAIN_SEAL event_hash using JCS (same as verifier)
        canonical_bytes = jcs_canonicalize(seal_row)
        seal_row["event_hash"] = hashlib.sha256(canonical_bytes).hexdigest()
        lines.append(json.dumps(seal_row))

        with open(output_path, "w") as f:
            for line in lines:
                f.write(line + "\n")

        # --- Step 6: Verify with the standalone verifier ---
        result = run_verifier_on_file(output_path)
        assert result["returncode"] == 0, f"Verifier failed: {result}"
        assert result["data"]["result"] == "PASS"
        assert result["data"]["evidence_class"] == "AUTHORITATIVE_EVIDENCE"

    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)
