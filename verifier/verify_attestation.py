#!/usr/bin/env python3
"""
verifier/verify_attestation.py — Standalone attestation verifier.

Verifies a selective disclosure attestation produced by
agentops_sdk/attestation.py WITHOUT requiring the original JSONL file
or any SDK dependency (only the `cryptography` package).

Usage:
    python3 verifier/verify_attestation.py attestation.json
    python3 verifier/verify_attestation.py attestation.json --format json

Exit codes:
    0  PASS — attestation is cryptographically valid
    1  FAIL — attestation is invalid or forged
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from typing import Any


# ── RFC 6962 Merkle primitives (inlined — no SDK dependency) ─────────────────

_LEAF_PREFIX     = b'\x00'
_INTERNAL_PREFIX = b'\x01'


def _leaf_hash(event_hash_hex: str) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + bytes.fromhex(event_hash_hex)).digest()


def _internal_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


def _k_split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def _verify_inclusion(
    root_hex: str,
    leaf_event_hash: str,
    leaf_index: int,
    total_leaves: int,
    proof_hashes: list[str],
) -> bool:
    try:
        # Collect left/right decisions outer-to-inner, then reverse to match
        # the inner-to-outer path order from compute_inclusion_proof.
        decisions: list[bool] = []
        m, n = leaf_index, total_leaves
        for _ in range(len(proof_hashes)):
            k = _k_split(n)
            if m < k:
                decisions.append(True)
                n = k
            else:
                decisions.append(False)
                m -= k
                n -= k
        decisions.reverse()

        current = _leaf_hash(leaf_event_hash)
        for sibling_hex, is_left in zip(proof_hashes, decisions):
            sibling = bytes.fromhex(sibling_hex)
            if is_left:
                current = _internal_hash(current, sibling)
            else:
                current = _internal_hash(sibling, current)

        return current.hex() == root_hex
    except Exception:
        return False


# ── Ed25519 verification (inlined) ───────────────────────────────────────────

def _verify_ed25519(public_key_b64: str, event_hash_hex: str, signature_b64: str) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pk  = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        sig = base64.b64decode(signature_b64)
        pk.verify(sig, event_hash_hex.encode("utf-8"))
        return True
    except Exception:
        return False


# ── Core verification logic ───────────────────────────────────────────────────

def verify(attestation: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []

    disclosed   = attestation.get("disclosed", {})
    event_hash  = disclosed.get("event_hash", "")
    event_index = attestation.get("event_index", 0)
    leaf_count  = attestation.get("merkle_leaf_count", 0)
    root_hex    = attestation.get("merkle_root", "")
    proof       = attestation.get("inclusion_proof", [])
    pub_key     = attestation.get("sdk_public_key")
    signature   = disclosed.get("signature")

    # Check 1: Merkle inclusion
    merkle_ok = _verify_inclusion(root_hex, event_hash, event_index, leaf_count, proof)
    if not merkle_ok:
        errors.append("Merkle inclusion proof FAILED — event_hash not in stated root")

    # Check 2: Ed25519 signature
    if pub_key and signature:
        sig_ok: bool | None = _verify_ed25519(pub_key, event_hash, signature)
        if not sig_ok:
            errors.append("Ed25519 signature INVALID — event_hash not signed by session key")
    else:
        sig_ok = None

    result = "PASS" if merkle_ok and sig_ok is not False else "FAIL"
    return {
        "result":           result,
        "merkle_inclusion": merkle_ok,
        "signature_valid":  sig_ok,
        "event_type":       disclosed.get("event_type"),
        "seq":              disclosed.get("seq"),
        "event_hash":       disclosed.get("event_hash"),
        "merkle_root":      root_hex,
        "errors":           errors,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def _print_text(r: dict, attestation: dict) -> None:
    disclosed = attestation.get("disclosed", {})
    width = 52

    print(f"\nAttestation Verifier  (agentops-replay-pro)")
    print("=" * width)
    if "session_id" in attestation:
        print(f"  Session:    {attestation['session_id']}")
    print(f"  Merkle root: {attestation.get('merkle_root', '')[:16]}...")
    print(f"  Event idx:  {attestation.get('event_index')} / {attestation.get('merkle_leaf_count')} leaves")
    print()
    print(f"  Disclosed facts (no payload content):")
    print(f"    event_type:  {disclosed.get('event_type')}")
    print(f"    seq:         {disclosed.get('seq')}")
    print(f"    event_hash:  {(disclosed.get('event_hash') or '')[:16]}...  (commits to payload)")
    print()

    mk = r["merkle_inclusion"]
    sg = r["signature_valid"]
    print(f"  [1/2] Merkle inclusion ........... {'PASS ✅' if mk else 'FAIL ❌'}")
    if sg is None:
        print(f"  [2/2] Ed25519 signature .......... UNSIGNED (no key)")
    else:
        print(f"  [2/2] Ed25519 signature .......... {'PASS ✅' if sg else 'FAIL ❌'}")

    print()
    verdict = "PASS ✅" if r["result"] == "PASS" else "FAIL ❌"
    print(f"  Result: {verdict}")
    if r["errors"]:
        for err in r["errors"]:
            print(f"  ! {err}")
    print("=" * width)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a selective disclosure attestation.")
    parser.add_argument("attestation_file", help="Path to attestation JSON file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    try:
        with open(args.attestation_file) as f:
            attestation = json.load(f)
    except Exception as exc:
        print(json.dumps({"result": "FAIL", "error": str(exc)}))
        sys.exit(1)

    result = verify(attestation)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        _print_text(result, attestation)


    sys.exit(0 if result["result"] == "PASS" else 1)


if __name__ == "__main__":
    main()
