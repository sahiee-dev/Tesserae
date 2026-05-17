#!/usr/bin/env python3
"""
verifier_core.py - Shared hash computation and verification primitives.

CONSTITUTIONAL REQUIREMENT: Single source of truth for hash computation.
Used by BOTH ingestion service AND standalone verifier to ensure deterministic hashing.

Any modification to hash computation MUST update golden vector tests.
"""
from __future__ import annotations

import hashlib
from typing import Any

import jcs as jcs  # Re-export for downstream consumers  # noqa: PLC0414

# --- Constants (from EVENT_LOG_SPEC.md v0.6) ---
SPEC_VERSION = "v0.6"
SIGNED_FIELDS = [
    "event_id",
    "session_id",
    "sequence_number",
    "timestamp_wall",
    "event_type",
    "payload_hash",
    "payload_hash",
    "prev_event_hash"
]

GENESIS_HASH = "0" * 64


def sha256(data: bytes) -> str:
    """Compute SHA-256 hash and return hex digest."""
    return hashlib.sha256(data).hexdigest()


def compute_payload_hash(payload: dict[str, Any]) -> str:
    """
    Compute canonical hash of event payload per RFC 8785.
    
    CRITICAL: This function MUST produce identical output in:
    - SDK (for local authority mode)
    - Ingestion Service (for server authority mode)
    - Verifier (for verification)
    
    Args:
        payload: Event payload dictionary
        
    Returns:
        SHA-256 hex digest of canonical JSON
        
    Raises:
        ValueError: If payload cannot be canonicalized
    """
    try:
        canonical_bytes = jcs.canonicalize(payload)
        return sha256(canonical_bytes)
    except Exception as e:
        raise ValueError(f"Failed to canonicalize payload: {e}")


def compute_event_hash(event: dict[str, Any]) -> str:
    """
    Compute event hash from signed fields per EVENT_LOG_SPEC.md.
    
    Hash is computed over canonicalized JSON of signed fields only:
    - event_id, session_id, sequence_number, timestamp_wall
    - event_type, payload_hash, prev_event_hash
    
    Args:
        event: Full event envelope
        
    Returns:
        SHA-256 hex digest of canonical signed fields
        
    Raises:
        ValueError: If required signed fields are missing
    """
    # Extract signed fields only
    signed_obj = {}
    for field in SIGNED_FIELDS:
        if field not in event:
            raise ValueError(f"Missing required signed field: {field}")
        signed_obj[field] = event[field]

    # Canonicalize and hash
    canonical_envelope = jcs.canonicalize(signed_obj)
    return sha256(canonical_envelope)


def verify_event_hash(event: dict[str, Any]) -> bool:
    """
    Verify that event_hash matches computed hash of signed fields.
    
    Args:
        event: Event envelope with event_hash field
        
    Returns:
        True if hash is valid, False otherwise
    """
    try:
        computed = compute_event_hash(event)
        claimed = event.get("event_hash")
        return computed == claimed
    except Exception:
        return False


def verify_payload_hash(event: dict[str, Any]) -> bool:
    """
    Verify that payload_hash matches computed hash of payload.
    
    Args:
        event: Event envelope with payload and payload_hash
        
    Returns:
        True if hash is valid, False otherwise
    """
    try:
        payload = event.get("payload")
        if payload is None:
            return False
        computed = compute_payload_hash(payload)
        claimed = event.get("payload_hash")
        return computed == claimed
    except Exception:
        return False


def classify_evidence(
    authority: str, sealed: bool, complete: bool, has_drops: bool = False
) -> str:
    """
    Classify session evidence per CHAIN_AUTHORITY_INVARIANTS.md.

    CRITICAL: Binary classification only - no "partial" footgun.

    AUTHORITATIVE_EVIDENCE requires ALL conditions:
    - Server authority
    - Valid CHAIN_SEAL
    - Complete session (SESSION_END present)
    - No LOG_DROP events
    - Chain cryptographically valid

    Everything else is NON_AUTHORITATIVE_EVIDENCE.

    Args:
        authority: "server" or "sdk"
        sealed: Has valid CHAIN_SEAL
        complete: Has SESSION_END and no sequence gaps
        has_drops: Has LOG_DROP events

    Returns:
        "AUTHORITATIVE_EVIDENCE" or "NON_AUTHORITATIVE_EVIDENCE"
    """
    if authority == "server" and sealed and complete and not has_drops:
        # ALL conditions met - this is the ONLY path to authoritative status
        return "AUTHORITATIVE_EVIDENCE"
    else:
        # Everything else - including:
        # - SDK authority (even if "sealed")
        # - Server authority without seal
        # - Server authority with drops
        # - Incomplete sessions
        return "NON_AUTHORITATIVE_EVIDENCE"


def validate_chain_continuity(events: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """
    Validate hash chain continuity.

    Args:
        events: Ordered list of events

    Returns:
        (is_valid, error_message) tuple
    """
    prev_hash = None

    for i, event in enumerate(events):
        # First event must have null prev_event_hash (per agentops_verify.py)
        if i == 0:
            if event.get("prev_event_hash") is not None:
                return False, "First event must have prev_event_hash=None"
        # Subsequent events must link to previous
        elif event.get("prev_event_hash") != prev_hash:
            return (
                False,
                f"Chain broken at event {i}: expected {prev_hash}, got {event.get('prev_event_hash')}",
            )

        # Verify event hash
        if not verify_event_hash(event):
            return False, f"Invalid event hash at event {i}"

        # Verify payload hash
        if not verify_payload_hash(event):
            return False, f"Invalid payload hash at event {i}"

        prev_hash = event.get("event_hash")

    return True, None


def validate_sequence_monotonicity(
    events: list[dict[str, Any]],
) -> tuple[bool, str | None]:
    """
    Validate sequence numbers are strictly monotonic from 0.

    Args:
        events: Ordered list of events

    Returns:
        (is_valid, error_message) tuple
    """
    expected_seq = 1

    for i, event in enumerate(events):
        actual_seq = event.get("sequence_number")
        if actual_seq != expected_seq:
            return (
                False,
                f"Sequence gap at event {i}: expected {expected_seq}, got {actual_seq}",
            )
        expected_seq += 1

    return True, None


def check_mixed_authority(events: list[dict[str, Any]]) -> tuple[bool, set[str] | None]:
    """
    Check for mixed authority in session (constitutional violation).

    Args:
        events: List of events

    Returns:
        (has_mixed_authority, authorities_found) tuple
    """
    authorities: set[str] = set()
    for event in events:
        auth = event.get("chain_authority")
        if auth:
            authorities.add(auth)

    has_mixed = len(authorities) > 1
    return has_mixed, authorities if has_mixed else None


def build_trust_assumptions(
    events: list[dict],
    hmac_verified: bool,
    hmac_key_provided: bool,
    evidence_class: str,
    signatures_valid: bool = False,
    merkle_valid: bool = False,
) -> dict:
    """
    Build the trust_assumptions field for JSON output.

    This documents what the verifier DID and DID NOT verify.
    It answers: "AUTHORITATIVE relative to what trust assumptions?"

    Per docs/TRUST_MODEL.md §6.
    """
    has_chain_seal = any(
        e.get("event_type") == "CHAIN_SEAL" for e in events
    )
    has_log_drop = any(
        e.get("event_type") == "LOG_DROP" for e in events
    )

    return {
        # Was an independent process (Ingestion Service) involved?
        "independent_server_verification": has_chain_seal,

        # Was the server's identity cryptographically verified?
        # True only if HMAC key was provided AND HMAC matched.
        "server_identity_verified": hmac_verified,

        # Was a key provided at all?
        "hmac_key_provided": hmac_key_provided,

        # Was instrumentation complete?
        # "unknown" always — verifier cannot know what was not captured.
        # "incomplete" if LOG_DROP events are present.
        "instrumentation_complete": (
            "incomplete" if has_log_drop else "unknown"
        ),

        # Was freshness (session recency) verified?
        # Never — verifier does not check timestamps against current time.
        "session_freshness_verified": False,

        # Is the Ingestion Service assumed honest (not Byzantine)?
        # True whenever CHAIN_SEAL is present — we trust the server.
        # False means no server was involved.
        "ingestion_service_assumed_honest": has_chain_seal,

        # Does the system defend against a Byzantine Ingestion Service?
        # No in v1.0. Requires transparency log (v2.0).
        "byzantine_server_defended": False,

        # Is clock accuracy required for ordering guarantees?
        # No — ordering is cryptographic (hash chain), not timestamp-based.
        "clock_accuracy_required": False,

        # Was each event Ed25519-signed by the session keypair?
        # True only when all events carry a valid signature from SESSION_START pubkey.
        "ed25519_signatures_verified": signatures_valid,

        # Was an RFC 6962 Merkle root sealed in SESSION_END and verified?
        # Enables O(log n) inclusion proofs and external root publication.
        "merkle_root_verified": merkle_valid,

        # Does the Verifier defend against full-chain rewrite by an attacker
        # who knows the hash algorithm?
        # True if HMAC verified (server auth) OR Ed25519 signatures verified
        # (an attacker without the private key cannot forge valid signatures).
        "full_chain_rewrite_defended": hmac_verified or signatures_valid,

        # Reference to the formal trust model
        "trust_model_ref": "docs/TRUST_MODEL.md",
    }


# Golden vector for hash determinism testing
GOLDEN_TEST_PAYLOAD = {
    "test": "data",
    "number": 42,
    "nested": {"key": "value"}
}

# Placeholder - will be computed
GOLDEN_PAYLOAD_HASH = "5357e4c31d1b855c84c3b2c70640071d84279d20e7e1786e77ab5f1522df5a4a"
SHA_256_HEX_LEN = 64


def test_golden_vector() -> bool:
    """
    Golden vector test for hash determinism.

    CRITICAL: This test MUST pass identically in:
    - SDK
    - Ingestion Service
    - Verifier

    Returns:
        True if hash matches golden vector
    """
    computed = compute_payload_hash(GOLDEN_TEST_PAYLOAD)
    # Verify length is correct AND matches deterministic golden hash
    return len(computed) == SHA_256_HEX_LEN and computed == GOLDEN_PAYLOAD_HASH
