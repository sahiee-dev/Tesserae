#!/usr/bin/env python3
"""
agentops_verify.py — Standalone Verifier for AgentOps Replay logs.
Implements TRD v2.0 sections 3.1–3.5.

Usage:
  python3 agentops_verify.py <session.jsonl> [--format {text,json}]

Exit codes:
  0  PASS — chain is valid
  1  FAIL — chain has integrity violations
  2  ERROR — file not found, permission error, or malformed JSONL
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as hmac_module
import json
import sys
import os
from typing import Any

# Canonical JCS — single source of truth
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from jcs import canonicalize as jcs_canonicalize
from verifier_core import build_trust_assumptions

VERIFIER_VERSION = "1.0"
GENESIS_HASH = "0" * 64

ALLOWED_EVENT_TYPES = {
    "SESSION_START", "SESSION_END",
    "LLM_CALL", "LLM_RESPONSE",
    "TOOL_CALL", "TOOL_RESULT", "TOOL_ERROR",
    "LOG_DROP",
    "CHAIN_SEAL", "CHAIN_BROKEN", "REDACTION", "FORENSIC_FREEZE",
}

REQUIRED_FIELDS = {
    "seq", "event_type", "session_id", "timestamp",
    "payload", "prev_hash", "event_hash",
}


# ---------------------------------------------------------------------------
# Check 1: Structural validity
# ---------------------------------------------------------------------------

def check_structural_validity(events: list[dict]) -> dict:
    errors = []
    for event in events:
        seq = event.get("seq", "?")
        for field in REQUIRED_FIELDS:
            if field not in event:
                errors.append(f"seq={seq}: Missing required field '{field}'")
        if "seq" in event and not isinstance(event["seq"], int):
            errors.append(f"seq={seq}: 'seq' must be a positive integer")
        if "seq" in event and isinstance(event["seq"], int) and event["seq"] < 1:
            errors.append(f"seq={seq}: 'seq' must be >= 1")
        if "event_type" in event and event["event_type"] not in ALLOWED_EVENT_TYPES:
            errors.append(f"seq={seq}: Unknown event_type '{event['event_type']}'")
        if "session_id" in event and not isinstance(event["session_id"], str):
            errors.append(f"seq={seq}: 'session_id' must be a string")
        if "payload" in event and not isinstance(event["payload"], dict):
            errors.append(f"seq={seq}: 'payload' must be a JSON object")
        if "prev_hash" in event:
            ph = event["prev_hash"]
            if not (isinstance(ph, str) and len(ph) == 64 and all(c in "0123456789abcdef" for c in ph)):
                errors.append(f"seq={seq}: 'prev_hash' must be 64-char lowercase hex")
        if "event_hash" in event:
            eh = event["event_hash"]
            if not (isinstance(eh, str) and len(eh) == 64 and all(c in "0123456789abcdef" for c in eh)):
                errors.append(f"seq={seq}: 'event_hash' must be 64-char lowercase hex")

    return {
        "status": "PASS" if not errors else "FAIL",
        "events_checked": len(events),
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Check 2: Sequence integrity
# ---------------------------------------------------------------------------

def check_sequence_integrity(events: list[dict]) -> dict:
    errors = []
    gaps = []
    duplicates = []

    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    seqs = [e.get("seq") for e in sorted_events]

    # All must share the same session_id
    session_ids = set(e.get("session_id") for e in events)
    if len(session_ids) > 1:
        errors.append(f"Multiple session_ids found: {session_ids}")

    # Check for duplicates
    seen = {}
    for s in seqs:
        if s in seen:
            duplicates.append(s)
        seen[s] = True

    # First seq must be 1
    first_seq = seqs[0] if seqs else None
    if first_seq != 1:
        errors.append(f"First seq must be 1, got {first_seq}")

    # Each subsequent seq must be previous + 1
    for i in range(1, len(seqs)):
        expected = seqs[i - 1] + 1
        if seqs[i] != expected:
            gap_msg = f"Expected seq={expected}, found seq={seqs[i]}"
            gaps.append(gap_msg)
            errors.append(gap_msg)

    if duplicates:
        errors.append(f"Duplicate seq values: {duplicates}")

    return {
        "status": "PASS" if not errors else "FAIL",
        "first_seq": first_seq,
        "last_seq": seqs[-1] if seqs else None,
        "gaps": gaps,
        "duplicates": duplicates,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Check 3: Hash chain integrity
# ---------------------------------------------------------------------------

def _compute_event_hash(event: dict) -> str:
    # Exclude both event_hash (always) and signature (added after hash is computed).
    # This ensures old unsigned events and new signed events hash identically.
    event_for_hash = {k: v for k, v in event.items() if k not in ("event_hash", "signature")}
    canonical_bytes = jcs_canonicalize(event_for_hash)
    return hashlib.sha256(canonical_bytes).hexdigest()


def check_hash_chain_integrity(events: list[dict]) -> dict:
    errors = []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))

    # FIX 3: Validate prev_hash of seq=1 equals GENESIS_HASH
    first_events = [e for e in sorted_events if e.get("seq") == 1]
    if first_events:
        first_event = first_events[0]
        if first_event.get("prev_hash") != GENESIS_HASH:
            errors.append(
                f"seq=1: prev_hash must be '{'0' * 64}' (genesis), "
                f"got '{first_event.get('prev_hash')}'"
            )

    prev_event_hash: str | None = None

    for event in sorted_events:
        seq = event.get("seq", "?")

        # Recompute event_hash
        try:
            expected_hash = _compute_event_hash(event)
        except Exception as e:
            errors.append(f"seq={seq}: Failed to compute hash: {e}")
            break

        stored_hash = event.get("event_hash")
        if stored_hash != expected_hash:
            errors.append(
                f"seq={seq} ({event.get('event_type', '?')}): "
                f"event_hash mismatch — expected {expected_hash}, found {stored_hash}"
            )
            break

        # Verify chain linkage
        if prev_event_hash is not None:
            if event.get("prev_hash") != prev_event_hash:
                errors.append(
                    f"seq={seq}: prev_hash does not match previous event_hash — "
                    f"expected {prev_event_hash}, found {event.get('prev_hash')}"
                )
                break

        prev_event_hash = stored_hash

    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Check 4: Session completeness
# ---------------------------------------------------------------------------

def check_session_completeness(events: list[dict]) -> dict:
    errors = []
    sorted_events = sorted(events, key=lambda e: e.get("seq", 0))
    event_types = [e.get("event_type") for e in sorted_events]

    has_session_start = "SESSION_START" in event_types
    has_session_end = "SESSION_END" in event_types
    has_chain_seal = "CHAIN_SEAL" in event_types
    log_drop_count = event_types.count("LOG_DROP")
    chain_broken_count = event_types.count("CHAIN_BROKEN")

    # Exactly one SESSION_START
    if event_types.count("SESSION_START") != 1:
        errors.append(f"Expected exactly 1 SESSION_START, found {event_types.count('SESSION_START')}")

    # SESSION_START must have the lowest seq
    if has_session_start:
        start_seq = next(e["seq"] for e in sorted_events if e.get("event_type") == "SESSION_START")
        if start_seq != sorted_events[0].get("seq"):
            errors.append(f"SESSION_START must be at seq=1, found at seq={start_seq}")

    # At least one SESSION_END or CHAIN_SEAL
    if not has_session_end and not has_chain_seal:
        errors.append("Session has no SESSION_END or CHAIN_SEAL")

    # CHAIN_SEAL must be the absolute last event
    if has_chain_seal:
        last_seq = sorted_events[-1].get("seq")
        seal_seq = next(e["seq"] for e in sorted_events if e.get("event_type") == "CHAIN_SEAL")
        if seal_seq != last_seq:
            errors.append(f"CHAIN_SEAL must be the last event (seq={last_seq}), found at seq={seal_seq}")

    return {
        "status": "PASS" if not errors else "FAIL",
        "has_session_start": has_session_start,
        "has_session_end": has_session_end,
        "has_chain_seal": has_chain_seal,
        "log_drop_count": log_drop_count,
        "chain_broken_count": chain_broken_count,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Merkle tree helpers — RFC 6962, inlined for standalone verifier
# ---------------------------------------------------------------------------

def _merkle_leaf_hash(event_hash_hex: str) -> bytes:
    """SHA-256(0x00 || raw_event_hash_bytes) — RFC 6962 leaf domain separation."""
    return hashlib.sha256(b'\x00' + bytes.fromhex(event_hash_hex)).digest()


def _merkle_internal_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right) — RFC 6962 internal node domain separation."""
    return hashlib.sha256(b'\x01' + left + right).digest()


def _merkle_mth(leaves: list[bytes]) -> bytes:
    """RFC 6962 MTH: recursive Merkle tree hash over leaf digests."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = 1 << ((n - 1).bit_length() - 1)  # largest power of 2 < n
    return _merkle_internal_hash(_merkle_mth(leaves[:k]), _merkle_mth(leaves[k:]))


def _compute_merkle_root(event_hashes: list[str]) -> str:
    """Compute Merkle root over a list of 64-char event_hash hex strings."""
    if not event_hashes:
        return hashlib.sha256(b"").hexdigest()
    leaves = [_merkle_leaf_hash(h) for h in event_hashes]
    return _merkle_mth(leaves).hex()


# ---------------------------------------------------------------------------
# Ed25519 helper — inlined so verifier stays standalone (no SDK import needed)
# ---------------------------------------------------------------------------

def _verify_ed25519_signature(public_key_b64: str, event_hash_hex: str, signature_b64: str) -> bool:
    """
    Verify an Ed25519 signature over an event_hash.
    Standalone — requires only the `cryptography` package, not the SDK.
    """
    try:
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        public_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, event_hash_hex.encode("utf-8"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Check 5: Ed25519 signature verification
# ---------------------------------------------------------------------------

def check_signatures(events: list[dict]) -> dict:
    """
    Verify Ed25519 signatures on all events.

    Three outcomes:
      - "UNSIGNED":  SESSION_START has no sdk_public_key → old format, backwards compat
      - "PASS":      all events carry valid signatures against SESSION_START public key
      - "FAIL":      one or more signatures are missing or cryptographically invalid

    The public key is read from SESSION_START payload["sdk_public_key"].
    """
    start_events = [e for e in events if e.get("event_type") == "SESSION_START"]
    if not start_events:
        return {"status": "UNSIGNED", "reason": "No SESSION_START found", "errors": []}

    public_key_b64 = start_events[0].get("payload", {}).get("sdk_public_key")
    if not public_key_b64:
        return {"status": "UNSIGNED", "reason": "No sdk_public_key in SESSION_START", "errors": []}

    errors = []
    checked = 0
    for event in sorted(events, key=lambda e: e.get("seq", 0)):
        sig = event.get("signature")
        event_hash = event.get("event_hash", "")
        seq = event.get("seq", "?")

        if sig is None:
            errors.append(f"seq={seq} ({event.get('event_type')}): missing signature field")
            continue

        checked += 1
        if not _verify_ed25519_signature(public_key_b64, event_hash, sig):
            errors.append(f"seq={seq} ({event.get('event_type')}): invalid Ed25519 signature")

    if errors:
        return {"status": "FAIL", "checked": checked, "errors": errors}

    return {"status": "PASS", "checked": checked, "errors": []}


# ---------------------------------------------------------------------------
# Check 6: Merkle root verification
# ---------------------------------------------------------------------------

def check_merkle_root(events: list[dict]) -> dict:
    """
    Verify the Merkle root sealed in SESSION_END.

    SESSION_END payload contains:
      merkle_root:       hex root of RFC 6962 tree over events seq=1..N-1
      merkle_leaf_count: number of leaves (events before SESSION_END)

    Three outcomes:
      "ABSENT":  SESSION_END has no merkle_root → old format, backwards compat
      "PASS":    recomputed root matches stored root
      "FAIL":    root mismatch (events were added, removed, or reordered)
    """
    end_events = [e for e in events if e.get("event_type") == "SESSION_END"]
    if not end_events:
        return {"status": "ABSENT", "reason": "No SESSION_END found", "errors": []}

    session_end = end_events[0]
    stored_root = session_end.get("payload", {}).get("merkle_root")
    stored_count = session_end.get("payload", {}).get("merkle_leaf_count")

    if stored_root is None:
        return {"status": "ABSENT", "reason": "No merkle_root in SESSION_END payload", "errors": []}

    # Recompute: all events except SESSION_END, sorted by seq
    non_end = sorted(
        [e for e in events if e.get("event_type") != "SESSION_END"],
        key=lambda e: e.get("seq", 0),
    )
    leaf_hashes = [e["event_hash"] for e in non_end if "event_hash" in e]
    recomputed = _compute_merkle_root(leaf_hashes)

    errors = []
    if stored_count is not None and stored_count != len(leaf_hashes):
        errors.append(
            f"merkle_leaf_count mismatch: stored={stored_count}, recomputed={len(leaf_hashes)}"
        )
    if recomputed != stored_root:
        errors.append(
            f"merkle_root mismatch: stored={stored_root[:16]}..., recomputed={recomputed[:16]}..."
        )

    if errors:
        return {"status": "FAIL", "leaf_count": len(leaf_hashes), "errors": errors}

    return {
        "status": "PASS",
        "root": stored_root,
        "leaf_count": len(leaf_hashes),
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Evidence class determination (TRD §3.5)
# ---------------------------------------------------------------------------

def determine_evidence_class(events: list[dict], signatures_valid: bool = False) -> str:
    has_chain_seal = any(e.get("event_type") == "CHAIN_SEAL" for e in events)
    has_log_drop = any(e.get("event_type") == "LOG_DROP" for e in events)

    if has_chain_seal and not has_log_drop:
        return "AUTHORITATIVE_EVIDENCE"
    elif has_chain_seal and has_log_drop:
        return "PARTIAL_AUTHORITATIVE_EVIDENCE"
    elif signatures_valid:
        return "SIGNED_NON_AUTHORITATIVE_EVIDENCE"
    else:
        return "NON_AUTHORITATIVE_EVIDENCE"


# ---------------------------------------------------------------------------
# HMAC verification (server identity check)
# ---------------------------------------------------------------------------

def verify_chain_seal_hmac(events: list[dict], hmac_key: str) -> bool:
    """
    Verify the CHAIN_SEAL event's hmac field using the provided key.

    The seal HMAC is HMAC-SHA256(key, final_event_hash) where
    final_event_hash is the event_hash of the event immediately
    preceding the CHAIN_SEAL.

    Returns True only if a CHAIN_SEAL with a valid hmac field is found
    and the computed digest matches.
    """
    seal_events = [e for e in events if e.get("event_type") == "CHAIN_SEAL"]
    if not seal_events:
        return False

    seal = seal_events[0]
    stored_hmac = seal.get("hmac") or seal.get("seal_hmac")
    if not stored_hmac:
        return False

    # The HMAC covers the prev_hash of the CHAIN_SEAL (= final session hash)
    final_hash = seal.get("prev_hash", "")
    key_bytes = hmac_key.encode()
    computed = hmac_module.new(
        key_bytes, final_hash.encode(), digestmod=hashlib.sha256
    ).hexdigest()

    return hmac_module.compare_digest(computed, stored_hmac)


# ---------------------------------------------------------------------------
# Output formatting (TRD §3.2)
# ---------------------------------------------------------------------------

def _fmt_check(label: str, result: dict, skipped: bool = False) -> str:
    if skipped:
        status = "(skipped — earlier check failed)"
    elif result["status"] == "PASS":
        status = "PASS"
    else:
        status = "FAIL"
    return f"{label} {status}"


def print_text_output(
    file_path: str,
    session_id: str,
    event_count: int,
    evidence_class: str | None,
    checks: dict,
    overall: str,
    check_results: dict,
    trust_assumptions: dict | None = None,
    verbose: bool = False,
) -> None:
    print("AgentOps Replay Verifier v1.0")
    print("==============================")
    print(f"File        : {os.path.basename(file_path)}")
    print(f"Session ID  : {session_id}")
    print(f"Events      : {event_count}")
    if evidence_class:
        print(f"Evidence    : {evidence_class}")
    else:
        print("Evidence    : (cannot determine — chain invalid)")
    print()

    c1 = check_results.get("structural")
    c2 = check_results.get("sequence")
    c3 = check_results.get("hash_chain")
    c4 = check_results.get("completeness")

    c1_status = c1["status"] if c1 else "FAIL"
    c2_status = c2["status"] if c2 else "FAIL"
    c3_status = c3["status"] if c3 else "FAIL"

    c5 = check_results.get("signatures")
    c5_status = c5["status"] if c5 else "UNSIGNED"

    print(f"[1/6] Structural validity ........... {c1_status}")
    if c1 and c1["status"] == "FAIL":
        for e in c1["errors"]:
            print(f"      {e}")

    print(f"[2/6] Sequence integrity ............. {c2_status}")
    if c2 and c2["status"] == "FAIL":
        for e in c2["errors"]:
            print(f"      {e}")

    print(f"[3/6] Hash chain integrity ........... {c3_status}")
    if c3 and c3["status"] == "FAIL":
        for e in c3["errors"]:
            print(f"      {e}")

    # Check 4 is skipped if earlier checks failed
    earlier_failed = c1_status == "FAIL" or c2_status == "FAIL" or c3_status == "FAIL"
    if earlier_failed:
        print("[4/6] Session completeness .......... (skipped — earlier check failed)")
    else:
        c4_status = c4["status"] if c4 else "FAIL"
        print(f"[4/6] Session completeness ........... {c4_status}")
        if c4 and c4["status"] == "FAIL":
            for e in c4["errors"]:
                print(f"      {e}")

    # Check 5: Ed25519 signatures (always runs, UNSIGNED is not a failure)
    if c5_status == "PASS":
        checked = c5.get("checked", "?")
        print(f"[5/6] Ed25519 signatures ............. PASS ({checked} events signed)")
    elif c5_status == "FAIL":
        print(f"[5/6] Ed25519 signatures ............. FAIL")
        if c5:
            for e in c5["errors"]:
                print(f"      {e}")
    else:
        print(f"[5/6] Ed25519 signatures ............. UNSIGNED (hash chain only)")

    # Check 6: Merkle root (always runs, ABSENT is not a failure)
    c6 = check_results.get("merkle")
    c6_status = c6["status"] if c6 else "ABSENT"
    if c6_status == "PASS":
        root_short = c6.get("root", "")[:16]
        n = c6.get("leaf_count", "?")
        print(f"[6/6] Merkle root (RFC 6962) ......... PASS (root={root_short}... leaves={n})")
    elif c6_status == "FAIL":
        print(f"[6/6] Merkle root (RFC 6962) ......... FAIL")
        if c6:
            for e in c6["errors"]:
                print(f"      {e}")
    else:
        print(f"[6/6] Merkle root (RFC 6962) ......... ABSENT (no root in SESSION_END)")

    # Show trust assumptions when verbose or evidence is authoritative
    show_trust = verbose or evidence_class in (
        "AUTHORITATIVE_EVIDENCE", "SIGNED_AUTHORITATIVE_EVIDENCE"
    )
    if show_trust and trust_assumptions:
        print()
        print("Trust assumptions:")
        yn = lambda v: "YES" if v else "NO"
        ic = trust_assumptions.get("instrumentation_complete", "unknown").upper()
        print(f"  Independent server verification: {yn(trust_assumptions['independent_server_verification'])}")
        print(f"  Server identity verified (HMAC): {yn(trust_assumptions['server_identity_verified'])}")
        print(f"  Instrumentation complete:        {ic}")
        print(f"  Full chain rewrite defended:     {yn(trust_assumptions['full_chain_rewrite_defended'])}")
        print(f"  Byzantine server defended:       NO (v1.0)")
        print(f"  Session freshness verified:      NO")

    print()
    if overall == "PASS":
        print("Result: PASS ✅")
    else:
        print("Result: FAIL ❌")


def build_json_output(
    file_path: str,
    session_id: str,
    event_count: int,
    evidence_class: str | None,
    overall: str,
    check_results: dict,
    errors: list[str],
    hmac_verified: bool = False,
    trust_assumptions: dict | None = None,
) -> dict:
    return {
        "verifier_version": VERIFIER_VERSION,
        "file": os.path.basename(file_path),
        "session_id": session_id,
        "event_count": event_count,
        "evidence_class": evidence_class,
        "result": overall,
        "hmac_verified": hmac_verified,
        "signatures_valid": check_results.get("signatures", {}).get("status") == "PASS",
        "merkle_valid": check_results.get("merkle", {}).get("status") == "PASS",
        "merkle_root": (
            check_results.get("merkle", {}).get("root")
            if check_results.get("merkle", {}).get("status") == "PASS" else None
        ),
        "checks": {
            "structural_validity": check_results.get("structural"),
            "sequence_integrity": check_results.get("sequence"),
            "hash_chain_integrity": check_results.get("hash_chain"),
            "session_completeness": check_results.get("completeness"),
            "ed25519_signatures": check_results.get("signatures"),
            "merkle_root": check_results.get("merkle"),
        },
        "trust_assumptions": trust_assumptions,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentOps Replay Verifier v1.0"
    )
    parser.add_argument("session_file", help="Path to JSONL session file to verify")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--hmac-key", default=None,
        help="HMAC-SHA256 key for verifying CHAIN_SEAL server identity"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show full trust assumptions in text output"
    )
    args = parser.parse_args()

    # FIX 1: file/parse errors → exit code 2
    try:
        with open(args.session_file) as f:
            raw = f.read()
    except FileNotFoundError:
        print(f"ERROR: File not found: {args.session_file}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"ERROR: Permission denied: {args.session_file}", file=sys.stderr)
        sys.exit(2)
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    events: list[dict] = []
    try:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                events.append(json.loads(line))
    except json.JSONDecodeError as e:
        print(f"ERROR: Malformed JSONL: {e}", file=sys.stderr)
        sys.exit(2)

    file_path = args.session_file
    event_count = len(events)
    session_id = events[0].get("session_id", "unknown") if events else "unknown"
    check_results: dict[str, dict] = {}
    all_errors: list[str] = []

    # Run checks in order; stop early if a check fails
    c1 = check_structural_validity(events)
    check_results["structural"] = c1

    if c1["status"] == "PASS":
        c2 = check_sequence_integrity(events)
        check_results["sequence"] = c2
    else:
        all_errors.extend(c1["errors"])
        c2 = {"status": "FAIL", "errors": ["skipped"]}
        check_results["sequence"] = c2

    if c1["status"] == "PASS" and c2["status"] == "PASS":
        c3 = check_hash_chain_integrity(events)
        check_results["hash_chain"] = c3
    else:
        all_errors.extend(c2.get("errors", []))
        c3 = {"status": "FAIL", "errors": ["skipped"]}
        check_results["hash_chain"] = c3

    if c1["status"] == "PASS" and c2["status"] == "PASS" and c3["status"] == "PASS":
        c4 = check_session_completeness(events)
        check_results["completeness"] = c4
        if c4["status"] == "FAIL":
            all_errors.extend(c4["errors"])
    else:
        all_errors.extend(c3.get("errors", []))
        c4 = {"status": "FAIL", "errors": ["skipped"]}
        check_results["completeness"] = None  # type: ignore[assignment]

    # Determine overall result from checks 1-4
    all_passed = all(
        check_results.get(k, {}).get("status") == "PASS"
        for k in ["structural", "sequence", "hash_chain", "completeness"]
        if check_results.get(k) is not None
    )
    overall = "PASS" if all_passed else "FAIL"

    # Check 5: Ed25519 signatures (independent of chain checks — runs regardless)
    c5 = check_signatures(events)
    check_results["signatures"] = c5
    signatures_valid = (c5["status"] == "PASS")
    if c5["status"] == "FAIL":
        all_errors.extend(c5["errors"])
        overall = "FAIL"

    # Check 6: Merkle root (independent — runs regardless)
    c6 = check_merkle_root(events)
    check_results["merkle"] = c6
    merkle_valid = (c6["status"] == "PASS")
    if c6["status"] == "FAIL":
        all_errors.extend(c6["errors"])
        overall = "FAIL"

    # Evidence class only determinable on PASS
    evidence_class: str | None = (
        determine_evidence_class(events, signatures_valid=signatures_valid)
        if overall == "PASS" else None
    )

    # HMAC verification
    hmac_key_provided = bool(args.hmac_key)
    hmac_verified = (
        verify_chain_seal_hmac(events, args.hmac_key)
        if hmac_key_provided else False
    )

    # Build trust assumptions (always present)
    ta = build_trust_assumptions(
        events, hmac_verified, hmac_key_provided,
        evidence_class or "",
        signatures_valid=signatures_valid,
        merkle_valid=merkle_valid,
    )

    if args.format == "json":
        output = build_json_output(
            file_path, session_id, event_count,
            evidence_class, overall, check_results, all_errors,
            hmac_verified=hmac_verified,
            trust_assumptions=ta,
        )
        print(json.dumps(output, indent=2))
    else:
        print_text_output(
            file_path, session_id, event_count,
            evidence_class, check_results, overall, check_results,
            trust_assumptions=ta,
            verbose=args.verbose,
        )

    sys.exit(0 if overall == "PASS" else 1)


if __name__ == "__main__":
    main()
