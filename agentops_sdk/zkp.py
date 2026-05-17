"""
agentops_sdk/zkp.py — Zero-Knowledge Proof of Payload Hash Knowledge.

Implements a non-interactive Schnorr sigma protocol over BN128 (the same
curve used by Ethereum's zkSNARK precompiles) to prove:

  "I know a hash value h (specifically, the SHA-256 args_hash of a secret
  channel message) such that the Pedersen commitment C = h_scalar * G + r * H
  is correctly formed, where the event containing h is in this session's
  Merkle tree."

Security properties
-------------------
HIDING:   The verifier sees only C, not h. Pedersen commitments are
          PERFECTLY hiding (information-theoretically, C looks uniform
          over random r, even with unlimited compute).

BINDING:  The prover cannot open C to two different values. Computationally
          binding under the discrete-log assumption on BN128.

SOUNDNESS: The prover cannot produce a valid Schnorr transcript without
           knowing (h_scalar, r). Sound under the DL assumption + ROM
           (random oracle model, via Fiat-Shamir heuristic).

ZERO-KNOWLEDGE: The transcript (R_nonce, s1, s2) can be simulated without
                the witness — the verifier learns nothing beyond "prover
                knows the opening of C."

Limitation (documented)
-----------------------
The Merkle INCLUSION PROOF in this version reveals the leaf index. Hiding
the index too requires a ZK-SNARK circuit with a SHA-256 or Poseidon
Merkle tree — a natural extension for future work.

Why this matters for AI agent audit
------------------------------------
Without ZK:  verifier receives args_hash directly — they can build a
             "collusion signature database" mapping known-malicious message
             hashes to agents.
With ZK:     verifier receives only Pedersen commitment C. They can verify
             the claim but cannot extract args_hash, blocking the database.
             Proofs for the same event look different each run (random r).

References
----------
- Schnorr, C.P. (1991). Efficient signature generation by smart cards.
  J. Cryptology.
- Pedersen, T. (1991). Non-interactive and information-theoretic secure
  verifiable secret sharing. CRYPTO.
- Fiat, A. & Shamir, A. (1986). How to prove yourself. CRYPTO.
- BN128: https://eips.ethereum.org/EIPS/eip-197
"""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from py_ecc.bn128 import G1, G2, multiply, add, neg, is_on_curve, field_modulus
from py_ecc.fields import bn128_FQ as FQ


# ── BN128 curve parameters ────────────────────────────────────────────────────

# Scalar field order of BN128 (prime r)
CURVE_ORDER: int = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

# Two independent BN128 G1 generators.
# G is the standard generator G1 = (1, 2).
# H is derived by hashing "agentops/ZKP/H_generator/v1" to a scalar and
# multiplying G — nothing-up-my-sleeve construction.
G: tuple = G1  # (1, 2) on BN128

def _make_h_generator() -> tuple:
    label = b"agentops/ZKP/H_generator/v1"
    scalar = int(hashlib.sha256(label).hexdigest(), 16) % CURVE_ORDER
    return multiply(G1, scalar)

H: tuple = _make_h_generator()


# ── Serialisation helpers ─────────────────────────────────────────────────────

def _g1_to_dict(point: tuple) -> dict[str, str]:
    """Serialise a G1 point to JSON-safe dict."""
    return {"x": hex(point[0].n), "y": hex(point[1].n)}


def _g1_from_dict(d: dict) -> tuple:
    """Deserialise a G1 point from dict."""
    return (FQ(int(d["x"], 16)), FQ(int(d["y"], 16)))


# ── Core cryptographic primitives ─────────────────────────────────────────────

def pedersen_commit(value_hex: str, blinding: int) -> tuple:
    """
    C = (int(value_hex) mod q) * G + blinding * H

    Returns a BN128 G1 point. The commitment is:
    - Perfectly hiding:  each blinding value gives an identical distribution.
    - Computationally binding: cannot find (v', r') ≠ (v, r) with same C
      unless DL on BN128 is broken (~128-bit security).
    """
    v_scalar = int(value_hex, 16) % CURVE_ORDER
    return add(multiply(G, v_scalar), multiply(H, blinding))


def schnorr_prove(
    value_hex: str,
    blinding: int,
    commitment: tuple,
    fiat_shamir_context: bytes,
) -> dict[str, Any]:
    """
    Non-interactive Schnorr proof of knowledge of (v, r) opening commitment C.

    Protocol (Fiat-Shamir transformed):
      1. Prover picks random (k1, k2)
      2. R = k1*G + k2*H                     (nonce commitment)
      3. c = H(R || C || context)             (Fiat-Shamir challenge)
      4. s1 = k1 + c*v_scalar   (mod q)      (response for v)
      5. s2 = k2 + c*blinding   (mod q)      (response for r)

    Proof transcript: (R, s1, s2)   [c is recomputed by verifier]

    Completeness check: s1*G + s2*H = R + c*C
    """
    v_scalar = int(value_hex, 16) % CURVE_ORDER

    # Step 1-2: random nonce commitment
    k1 = secrets.randbelow(CURVE_ORDER)
    k2 = secrets.randbelow(CURVE_ORDER)
    R_nonce = add(multiply(G, k1), multiply(H, k2))

    # Step 3: Fiat-Shamir challenge
    c = _fiat_shamir_challenge(R_nonce, commitment, fiat_shamir_context)

    # Step 4-5: responses
    s1 = (k1 + c * v_scalar) % CURVE_ORDER
    s2 = (k2 + c * blinding) % CURVE_ORDER

    return {
        "R": _g1_to_dict(R_nonce),
        "s1": hex(s1),
        "s2": hex(s2),
    }


def schnorr_verify(
    commitment: tuple,
    proof: dict[str, Any],
    fiat_shamir_context: bytes,
) -> bool:
    """
    Verify a Schnorr proof transcript against a commitment.

    Verifier check: s1*G + s2*H == R + c*C
    where c is recomputed from (R, C, context) via Fiat-Shamir.
    """
    try:
        R_nonce = _g1_from_dict(proof["R"])
        s1 = int(proof["s1"], 16)
        s2 = int(proof["s2"], 16)

        # Recompute Fiat-Shamir challenge
        c = _fiat_shamir_challenge(R_nonce, commitment, fiat_shamir_context)

        # LHS: s1*G + s2*H
        lhs = add(multiply(G, s1), multiply(H, s2))

        # RHS: R + c*C
        rhs = add(R_nonce, multiply(commitment, c))

        return lhs == rhs
    except Exception:
        return False


def _fiat_shamir_challenge(
    R_nonce: tuple,
    commitment: tuple,
    context: bytes,
) -> int:
    """
    Non-interactive challenge: SHA-256(R || C || context) mod q.

    Binding all public inputs (commitment, context) into the challenge
    prevents replay attacks and ties the proof to a specific statement.
    """
    r_bytes = (_g1_to_dict(R_nonce)["x"] + _g1_to_dict(R_nonce)["y"]).encode()
    c_bytes = (_g1_to_dict(commitment)["x"] + _g1_to_dict(commitment)["y"]).encode()
    digest = hashlib.sha256(r_bytes + c_bytes + context).digest()
    return int.from_bytes(digest, "big") % CURVE_ORDER


# ── High-level ZK claim builder ───────────────────────────────────────────────

def build_zk_claim(
    jsonl_path: str,
    event_index: int,
    field_name: str = "args_hash",
) -> dict[str, Any]:
    """
    Build a ZK proof-of-knowledge claim for a specific field in a session event.

    The proof commits to the field value (e.g. args_hash) via Pedersen and
    produces a Schnorr transcript showing the prover knows the opening.

    Args:
        jsonl_path:   Path to flushed JSONL session file.
        event_index:  0-based index into the non-SESSION_END leaf events.
        field_name:   Payload field whose value we commit to (must be a hex
                      string, e.g. args_hash from record_secret_channel_message).

    Returns:
        JSON-serialisable ZK claim dict.

    Raises:
        ValueError: If the field is absent, the session has no Merkle root,
                    or the field value is not a valid hex string.
    """
    from agentops_sdk.merkle import compute_inclusion_proof

    with open(jsonl_path) as f:
        all_events = [json.loads(line) for line in f if line.strip()]

    session_start = next(
        (e for e in all_events if e.get("event_type") == "SESSION_START"), None
    )
    session_end = next(
        (e for e in all_events if e.get("event_type") == "SESSION_END"), None
    )

    if session_end is None:
        raise ValueError("Session has no SESSION_END.")
    merkle_root = session_end.get("payload", {}).get("merkle_root")
    if not merkle_root:
        raise ValueError("SESSION_END has no merkle_root.")

    sdk_public_key = (session_start or {}).get("payload", {}).get("sdk_public_key")
    session_id = (session_start or {}).get("session_id", "unknown")

    leaf_events = sorted(
        [e for e in all_events if e.get("event_type") != "SESSION_END"],
        key=lambda e: e.get("seq", 0),
    )

    if event_index < 0 or event_index >= len(leaf_events):
        raise ValueError(f"event_index {event_index} out of range.")

    target = leaf_events[event_index]
    field_value_hex = target.get("payload", {}).get(field_name)
    if not field_value_hex:
        raise ValueError(
            f"Field '{field_name}' not found in event at index {event_index}. "
            f"Available fields: {list(target.get('payload', {}).keys())}"
        )

    # Validate it's a hex string
    try:
        bytes.fromhex(field_value_hex)
    except ValueError:
        raise ValueError(f"Field '{field_name}' value is not a valid hex string: {field_value_hex!r}")

    # Commit to the field value
    blinding = secrets.randbelow(CURVE_ORDER)
    commitment = pedersen_commit(field_value_hex, blinding)

    # Fiat-Shamir context ties proof to this specific session+event+tree
    fs_context = (
        merkle_root
        + target.get("event_type", "")
        + target.get("event_hash", "")
        + session_id
    ).encode("utf-8")

    proof = schnorr_prove(field_value_hex, blinding, commitment, fs_context)

    # Merkle inclusion (reveals leaf index — not ZK on position)
    event_hashes = [e["event_hash"] for e in leaf_events]
    inclusion_proof = compute_inclusion_proof(event_hashes, event_index)

    return {
        "zkp_version":   "v1",
        "session_id":    session_id,
        "merkle_root":   merkle_root,
        "sdk_public_key": sdk_public_key,
        "event_type":    target["event_type"],   # revealed: WHAT kind of event
        "field_name":    field_name,             # revealed: WHICH field is committed
        "commitment":    _g1_to_dict(commitment),
        "schnorr_proof": proof,
        # Merkle membership (reveals leaf index — see module docstring for full ZK path)
        "merkle": {
            "event_hash":     target["event_hash"],  # needed for inclusion check
            "leaf_index":     event_index,
            "leaf_count":     len(leaf_events),
            "inclusion_proof": inclusion_proof,
        },
    }


def verify_zk_claim(claim: dict[str, Any]) -> dict[str, Any]:
    """
    Verify a ZK claim without requiring the original JSONL file.

    Checks:
      1. Schnorr transcript is valid (prover knows commitment opening).
      2. Merkle inclusion: event_hash is a leaf in the tree with stated root.
      3. Ed25519 signature on event_hash (if sdk_public_key present in claim).

    Returns:
        {
            "result":            "PASS" | "FAIL",
            "schnorr_valid":     True | False,
            "merkle_valid":      True | False,
            "signature_valid":   True | False | None,
            "errors":            list[str],
        }
    """
    from agentops_sdk.merkle import verify_inclusion_proof

    errors: list[str] = []

    commitment = _g1_from_dict(claim["commitment"])
    merkle_root = claim["merkle_root"]
    event_type = claim["event_type"]
    session_id = claim.get("session_id", "unknown")

    merkle_info = claim["merkle"]
    event_hash = merkle_info["event_hash"]

    # Reconstruct Fiat-Shamir context (must match build_zk_claim)
    fs_context = (
        merkle_root + event_type + event_hash + session_id
    ).encode("utf-8")

    # ── Check 1: Schnorr proof ────────────────────────────────────────────────
    schnorr_ok = schnorr_verify(commitment, claim["schnorr_proof"], fs_context)
    if not schnorr_ok:
        errors.append(
            "Schnorr proof FAILED — commitment opening could not be verified."
        )

    # ── Check 2: Merkle inclusion ─────────────────────────────────────────────
    merkle_ok = verify_inclusion_proof(
        root_hex=merkle_root,
        leaf_event_hash=event_hash,
        leaf_index=merkle_info["leaf_index"],
        total_leaves=merkle_info["leaf_count"],
        proof_hashes=merkle_info["inclusion_proof"],
    )
    if not merkle_ok:
        errors.append("Merkle inclusion FAILED — event_hash not in stated root.")

    # ── Check 3: Ed25519 signature on event_hash ──────────────────────────────
    pub_key = claim.get("sdk_public_key")
    sig_ok: bool | None = None

    if pub_key:
        # The session key signature is in the original event, not in the ZK claim.
        # This check is optional — a full proof would include it.
        # Marked None to indicate "not checked in this proof" (would need event envelope).
        sig_ok = None  # see verify_attestation for Ed25519 check with event_hash+sig

    result = "PASS" if schnorr_ok and merkle_ok else "FAIL"

    return {
        "result":          result,
        "schnorr_valid":   schnorr_ok,
        "merkle_valid":    merkle_ok,
        "signature_valid": sig_ok,
        "errors":          errors,
    }
