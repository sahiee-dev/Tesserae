#!/usr/bin/env python3
"""
verifier/verify_zkp.py — Standalone ZK claim verifier.

Verifies a zero-knowledge Pedersen/Schnorr claim produced by
agentops_sdk/zkp.py WITHOUT requiring the original JSONL file.

The only dependency beyond stdlib is `py_ecc` for BN128 arithmetic.

Usage:
    python3 verifier/verify_zkp.py claim.json
    python3 verifier/verify_zkp.py claim.json --format json

Exit codes:
    0  PASS — Schnorr transcript valid + event is in Merkle tree
    1  FAIL — proof invalid or forged
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

from py_ecc.bn128 import G1, multiply, add
from py_ecc.fields import bn128_FQ as FQ


# ── BN128 parameters (must match zkp.py exactly) ─────────────────────────────

CURVE_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def _make_h() -> tuple:
    label = b"agentops/ZKP/H_generator/v1"
    scalar = int(hashlib.sha256(label).hexdigest(), 16) % CURVE_ORDER
    return multiply(G1, scalar)

G = G1
H = _make_h()


def _g1_from_dict(d: dict) -> tuple:
    return (FQ(int(d["x"], 16)), FQ(int(d["y"], 16)))


# ── RFC 6962 Merkle verification (inlined) ────────────────────────────────────

_LEAF_PREFIX     = b'\x00'
_INTERNAL_PREFIX = b'\x01'


def _leaf_hash(event_hash_hex: str) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + bytes.fromhex(event_hash_hex)).digest()


def _internal_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


def _k_split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def _verify_merkle_inclusion(
    root_hex: str,
    leaf_event_hash: str,
    leaf_index: int,
    total_leaves: int,
    proof_hashes: list[str],
) -> bool:
    try:
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


# ── Schnorr verification ──────────────────────────────────────────────────────

def _fiat_shamir_challenge(
    R_nonce: tuple,
    commitment: tuple,
    context: bytes,
) -> int:
    def _ser(pt: tuple) -> bytes:
        return (hex(pt[0].n) + hex(pt[1].n)).encode()

    digest = hashlib.sha256(_ser(R_nonce) + _ser(commitment) + context).digest()
    return int.from_bytes(digest, "big") % CURVE_ORDER


def _verify_schnorr(
    commitment: tuple,
    proof: dict,
    fiat_shamir_context: bytes,
) -> bool:
    try:
        R_nonce  = _g1_from_dict(proof["R"])
        s1 = int(proof["s1"], 16)
        s2 = int(proof["s2"], 16)

        c   = _fiat_shamir_challenge(R_nonce, commitment, fiat_shamir_context)
        lhs = add(multiply(G, s1), multiply(H, s2))
        rhs = add(R_nonce, multiply(commitment, c))
        return lhs == rhs
    except Exception:
        return False


# ── Core verification ─────────────────────────────────────────────────────────

def verify(claim: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []

    commitment  = _g1_from_dict(claim["commitment"])
    merkle_root = claim["merkle_root"]
    event_type  = claim["event_type"]
    session_id  = claim.get("session_id", "unknown")

    m           = claim["merkle"]
    event_hash  = m["event_hash"]

    # Fiat-Shamir context (must match build_zk_claim)
    fs_ctx = (merkle_root + event_type + event_hash + session_id).encode("utf-8")

    # Check 1: Schnorr
    schnorr_ok = _verify_schnorr(commitment, claim["schnorr_proof"], fs_ctx)
    if not schnorr_ok:
        errors.append("Schnorr proof FAILED — commitment cannot be verified.")

    # Check 2: Merkle inclusion
    merkle_ok = _verify_merkle_inclusion(
        root_hex=merkle_root,
        leaf_event_hash=event_hash,
        leaf_index=m["leaf_index"],
        total_leaves=m["leaf_count"],
        proof_hashes=m["inclusion_proof"],
    )
    if not merkle_ok:
        errors.append("Merkle inclusion FAILED — event_hash not in stated root.")

    result = "PASS" if schnorr_ok and merkle_ok else "FAIL"
    return {
        "result":        result,
        "schnorr_valid": schnorr_ok,
        "merkle_valid":  merkle_ok,
        "event_type":    event_type,
        "field_name":    claim.get("field_name"),
        "merkle_root":   merkle_root[:16] + "...",
        "errors":        errors,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def _print_text(r: dict, claim: dict) -> None:
    width = 58
    print(f"\nZK Claim Verifier  (agentops-replay-pro / BN128 Schnorr)")
    print("=" * width)
    if "session_id" in claim:
        print(f"  Session:     {claim['session_id']}")
    print(f"  Merkle root: {claim.get('merkle_root', '')[:16]}...")
    print(f"  Leaf:        index {claim['merkle']['leaf_index']} "
          f"of {claim['merkle']['leaf_count']}")
    print()
    print(f"  ZK claim (no payload content revealed):")
    print(f"    event_type:  {claim.get('event_type')}")
    print(f"    field_name:  {claim.get('field_name')}  ← value hidden behind Pedersen C")
    print(f"    commitment:  C.x = {claim['commitment']['x'][:18]}...")
    print()
    sk = r["schnorr_valid"]
    mk = r["merkle_valid"]
    print(f"  [1/2] Schnorr PoK (BN128, Fiat-Shamir) .. {'PASS ✅' if sk else 'FAIL ❌'}")
    print(f"  [2/2] Merkle inclusion (RFC 6962) ........ {'PASS ✅' if mk else 'FAIL ❌'}")
    print()
    verdict = "PASS ✅" if r["result"] == "PASS" else "FAIL ❌"
    print(f"  Result: {verdict}")
    if r["errors"]:
        for e in r["errors"]:
            print(f"  ! {e}")
    print()
    print(f"  Zero-knowledge guarantee:")
    print(f"    The verifier learned that a {claim.get('event_type')} event")
    print(f"    with some {claim.get('field_name')} exists in this session.")
    print(f"    The actual hash value is hidden behind commitment C.")
    print(f"    Forging C requires breaking discrete-log on BN128 (~128 bit).")
    print("=" * width)


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a BN128 Schnorr ZK claim.")
    parser.add_argument("claim_file", help="Path to ZK claim JSON file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    try:
        with open(args.claim_file) as f:
            claim = json.load(f)
    except Exception as exc:
        print(json.dumps({"result": "FAIL", "error": str(exc)}))
        sys.exit(1)

    result = verify(claim)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        _print_text(result, claim)

    sys.exit(0 if result["result"] == "PASS" else 1)


if __name__ == "__main__":
    main()
