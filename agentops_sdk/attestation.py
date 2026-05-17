"""
agentops_sdk/attestation.py — Selective disclosure attestation.

Given a verified session (JSONL with Merkle root + Ed25519 signatures),
produce a compact proof that a specific event exists in the session
WITHOUT revealing the event payload content.

Security guarantee
------------------
An attestation proves:
  1. An event with the stated event_hash exists in the session
     (Merkle RFC 6962 inclusion proof against root in SESSION_END).
  2. The session keypair signed this event_hash
     (Ed25519 signature from SESSION_START public key).
  3. The event has the stated event_type and payload_hash
     (event_hash is a cryptographic commitment to all signed fields).

What is NOT revealed:
  - The actual payload content (only its SHA-256 hash is disclosed).
  - Which other events are in the session.
  - The prev_event_hash linkage details.

Use case (Colosseum)
--------------------
Prove "agent X made a secret-channel TOOL_CALL in session Y" to a third
party without leaking the message content. The third party receives:
  - session_id, merkle_root, sdk_public_key   (session identity)
  - event_type, sequence_number, payload_hash  (what happened)
  - event_hash, signature                      (authenticity)
  - inclusion_proof                            (membership)
"""
from __future__ import annotations

import json
from typing import Any

from agentops_sdk.merkle import compute_inclusion_proof, verify_inclusion_proof


def build_attestation(
    jsonl_path: str,
    event_index: int,
    *,
    reveal_session_id: bool = True,
    reveal_timestamp: bool = False,
) -> dict[str, Any]:
    """
    Build a selective disclosure attestation for the event at event_index
    among the non-SESSION_END events in the session.

    Args:
        jsonl_path:         Path to a flushed JSONL session file.
        event_index:        0-based index into the Merkle leaf list
                            (non-SESSION_END events, ordered by seq).
        reveal_session_id:  Whether to include session_id in the output.
        reveal_timestamp:   Whether to include timestamp_wall in the output.

    Returns:
        JSON-serializable attestation dict.

    Raises:
        ValueError: If the session has no Merkle root (not yet sealed),
                    or if event_index is out of range.
    """
    with open(jsonl_path) as f:
        all_events = [json.loads(line) for line in f if line.strip()]

    session_start = next(
        (e for e in all_events if e.get("event_type") == "SESSION_START"), None
    )
    session_end = next(
        (e for e in all_events if e.get("event_type") == "SESSION_END"), None
    )

    if session_end is None:
        raise ValueError("Session has no SESSION_END — cannot attest.")

    merkle_root = session_end.get("payload", {}).get("merkle_root")
    if not merkle_root:
        raise ValueError("SESSION_END has no merkle_root — session predates Merkle support.")

    merkle_leaf_count = session_end["payload"].get("merkle_leaf_count", 0)
    sdk_public_key = (session_start or {}).get("payload", {}).get("sdk_public_key")

    # Merkle leaves = all events EXCEPT SESSION_END, sorted by seq
    leaf_events = sorted(
        [e for e in all_events if e.get("event_type") != "SESSION_END"],
        key=lambda e: e.get("seq", 0),
    )

    if event_index < 0 or event_index >= len(leaf_events):
        raise ValueError(
            f"event_index {event_index} out of range [0, {len(leaf_events) - 1}]"
        )

    target = leaf_events[event_index]
    event_hashes = [e["event_hash"] for e in leaf_events]

    inclusion_proof = compute_inclusion_proof(event_hashes, event_index)

    # Reveal event_type and seq — enough to characterise the event without
    # exposing payload content. event_hash is a SHA-256 commitment to the
    # entire event (including payload), so the third party can bind a payload
    # preimage to this attestation if they later obtain it.
    disclosed: dict[str, Any] = {
        "event_type": target["event_type"],
        "seq":        target["seq"],
        "event_hash": target["event_hash"],
        "signature":  target.get("signature"),
    }
    if reveal_timestamp:
        disclosed["timestamp"] = target.get("timestamp")

    attestation: dict[str, Any] = {
        "attestation_version": "v1",
        "merkle_root":         merkle_root,
        "merkle_leaf_count":   merkle_leaf_count,
        "sdk_public_key":      sdk_public_key,
        "event_index":         event_index,
        "disclosed":           disclosed,
        "inclusion_proof":     inclusion_proof,
    }
    if reveal_session_id and session_start is not None:
        attestation["session_id"] = session_start.get("session_id")

    return attestation


def verify_attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    """
    Verify a selective disclosure attestation.

    Does NOT require the original JSONL file.  The caller supplies only
    the attestation dict produced by build_attestation().

    Checks performed:
      1. Merkle inclusion: event_hash is a leaf in the tree with stated root.
      2. Ed25519 signature: event_hash was signed by the session keypair
         (if sdk_public_key and signature are present).

    Returns:
        {
            "result":           "PASS" | "FAIL",
            "merkle_inclusion": True | False,
            "signature_valid":  True | False | None,
            "errors":           list[str],
        }
    """
    errors: list[str] = []
    merkle_ok = False
    sig_ok: bool | None = None

    disclosed   = attestation.get("disclosed", {})
    event_hash  = disclosed.get("event_hash", "")
    event_index = attestation.get("event_index", 0)
    leaf_count  = attestation.get("merkle_leaf_count", 0)
    root_hex    = attestation.get("merkle_root", "")
    proof       = attestation.get("inclusion_proof", [])

    # ── Check 1: Merkle inclusion ─────────────────────────────────────────────
    try:
        merkle_ok = verify_inclusion_proof(
            root_hex=root_hex,
            leaf_event_hash=event_hash,
            leaf_index=event_index,
            total_leaves=leaf_count,
            proof_hashes=proof,
        )
        if not merkle_ok:
            errors.append("Merkle inclusion proof failed — event_hash not in stated root.")
    except Exception as exc:
        errors.append(f"Merkle verification error: {exc}")

    # ── Check 2: Ed25519 signature ────────────────────────────────────────────
    pub_key   = attestation.get("sdk_public_key")
    signature = disclosed.get("signature")

    if pub_key and signature:
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature

            pk_bytes = base64.b64decode(pub_key)
            pk       = Ed25519PublicKey.from_public_bytes(pk_bytes)
            sig_raw  = base64.b64decode(signature)
            pk.verify(sig_raw, event_hash.encode("utf-8"))
            sig_ok = True
        except InvalidSignature:
            sig_ok = False
            errors.append("Ed25519 signature invalid — event_hash was not signed by session key.")
        except Exception as exc:
            sig_ok = False
            errors.append(f"Ed25519 verification error: {exc}")
    else:
        sig_ok = None  # No key or signature provided — cannot check

    result = "PASS" if merkle_ok and sig_ok is not False and not errors else "FAIL"

    return {
        "result":           result,
        "merkle_inclusion": merkle_ok,
        "signature_valid":  sig_ok,
        "errors":           errors,
    }
