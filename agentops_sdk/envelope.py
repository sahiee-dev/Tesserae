import hashlib
import datetime
import sys
import os
from typing import Optional

# CRITICAL: Import JCS from verifier — the single canonical copy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'verifier'))
from jcs import canonicalize as jcs_canonicalize


# The prev_hash value for the first event in any session (seq=1)
GENESIS_HASH = "0" * 64


def build_event(
    seq: int,
    event_type: str,
    session_id: str,
    payload: dict,
    prev_hash: str,
    private_key: Optional[object] = None,
) -> dict:
    """
    Build a complete event envelope with computed hashes and optional Ed25519 signature.

    This is the single source of truth for event construction.
    The SDK must not construct events by any other means.

    The envelope fields (TRD §2.3 + signing extension):
        seq, event_type, session_id, timestamp, payload, prev_hash, event_hash
        signature  (present only when private_key is supplied)

    Hash computation:
    1. Build event dict WITHOUT event_hash or signature fields
    2. JCS canonicalize (RFC 8785)
    3. SHA-256 the UTF-8 bytes → event_hash

    Signature computation (when private_key provided):
    4. Ed25519.sign(private_key, event_hash.encode('utf-8')) → signature (base64)

    The signature is over event_hash so the verifier only needs the public key
    and the stored event_hash — no re-canonicalisation required.
    """
    timestamp = _utc_timestamp()

    event = {
        "seq": seq,
        "event_type": event_type,
        "session_id": session_id,
        "timestamp": timestamp,
        "payload": payload,
        "prev_hash": prev_hash,
    }

    event["event_hash"] = _compute_event_hash(event)

    if private_key is not None:
        try:
            from agentops_sdk.signing import sign_event_hash
            event["signature"] = sign_event_hash(private_key, event["event_hash"])
        except Exception:
            pass  # signing failure must never crash the agent

    return event


def _compute_event_hash(event: dict) -> str:
    """
    SHA-256 of the JCS canonical form, excluding the event_hash field itself.
    """
    event_for_hash = {k: v for k, v in event.items() if k != "event_hash"}
    canonical_bytes = jcs_canonicalize(event_for_hash)
    return hashlib.sha256(canonical_bytes).hexdigest()


def _utc_timestamp() -> str:
    """
    UTC time as ISO 8601 with microsecond precision.
    Format: 2026-05-05T10:30:00.123456Z
    """
    now = datetime.datetime.utcnow()
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
