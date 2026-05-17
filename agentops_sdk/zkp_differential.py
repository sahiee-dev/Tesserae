"""
agentops_sdk/zkp_differential.py — ZK Differential Collusion Audit.

Proves that two sealed sessions differ by exactly D events of a given
type, without revealing the event type, the counts, or the payloads.

Construction:
  T_A = count_A * G + r_A * H   (commitment to count in session A)
  T_B = count_B * G + r_B * H   (commitment to count in session B)
  D_commit = T_B - T_A          (commitment to count_B - count_A)
  check    = D_commit - D * G   (equals delta_r * H when D is correct)
  Proof    = Schnorr proof of discrete log of check in base H

Security properties:
  HIDING:   Verifier sees only T_A, T_B — not count_A, count_B, or event type.
  BINDING:  Prover cannot open T to two different counts (DL assumption).
  SOUNDNESS: Prover cannot produce valid proof for wrong D (DL assumption + ROM).
  ZK:       Proof transcript is simulatable without the witness.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any

from py_ecc.bn128 import multiply, add, neg
from agentops_sdk.zkp import (
    G, H, CURVE_ORDER,
    schnorr_prove, schnorr_verify,
    _g1_to_dict, _g1_from_dict,
)


def commit_session_count(
    jsonl_path: str,
    event_type_filter: str,
) -> dict[str, Any]:
    """
    Read a sealed JSONL, count events matching event_type_filter,
    and return a tally dict with a Pedersen commitment to that count.

    The event_type_filter is NEVER written to the output — the verifier
    learns only T (the commitment), not what was counted.

    Returns:
        {
            "commitment":  {"x": hex, "y": hex},   # PUBLIC — share with verifier
            "session_id":  str,
            "merkle_root": str | None,
            "event_count": int,                    # total events in session (not filtered count)
            "_opening": {                           # PRIVATE — prover only, never send to verifier
                "count":    int,
                "blinding": int,
            },
        }
    """
    with open(jsonl_path) as f:
        events = [json.loads(line) for line in f if line.strip()]

    count = sum(
        1 for e in events
        if e.get("event_type") == event_type_filter
    )

    session_id = next(
        (e.get("session_id") for e in events if e.get("session_id")),
        "unknown",
    )
    merkle_root = next(
        (
            e.get("payload", {}).get("merkle_root")
            for e in events
            if e.get("event_type") == "SESSION_END"
        ),
        None,
    )

    blinding = secrets.randbelow(CURVE_ORDER)
    T = add(multiply(G, count), multiply(H, blinding))

    return {
        "commitment":  _g1_to_dict(T),
        "session_id":  session_id,
        "merkle_root": merkle_root,
        "event_count": len(events),
        "_opening": {
            "count":    count,
            "blinding": blinding,
        },
    }


def prove_differential(
    tally_A: dict[str, Any],
    tally_B: dict[str, Any],
    claimed_D: int,
) -> dict[str, Any]:
    """
    Produce a ZK proof that count_B - count_A == claimed_D.

    Requires _opening fields in both tallies (prover possesses them).
    The verifier receives only the returned proof dict — no openings,
    no event types, no raw counts.

    Math:
      D_commit = T_B + neg(T_A) = (count_B - count_A)*G + (r_B - r_A)*H
      check    = D_commit - claimed_D*G

      If claimed_D correct: check = 0*G + delta_r*H = delta_r*H
      Schnorr: prove knowledge of delta_r s.t. check = 0*G + delta_r*H
    """
    opening_A = tally_A["_opening"]
    opening_B = tally_B["_opening"]

    r_A     = opening_A["blinding"]
    r_B     = opening_B["blinding"]
    delta_r = (r_B - r_A) % CURVE_ORDER

    T_A = _g1_from_dict(tally_A["commitment"])
    T_B = _g1_from_dict(tally_B["commitment"])

    D_commit = add(T_B, neg(T_A))
    check    = add(D_commit, neg(multiply(G, claimed_D % CURVE_ORDER)))

    fs_context = _differential_fs_context(tally_A, tally_B, claimed_D)

    # Prove knowledge of delta_r s.t. check = 0*G + delta_r*H
    # value_hex = "00"*32 → int 0 → zero G component
    proof = schnorr_prove(
        value_hex="00" * 32,
        blinding=delta_r,
        commitment=check,
        fiat_shamir_context=fs_context,
    )

    return {
        "zkdiff_version": "v1",
        "claimed_D":      claimed_D,
        "session_id_A":   tally_A.get("session_id"),
        "session_id_B":   tally_B.get("session_id"),
        "schnorr_proof":  proof,
    }


def verify_differential(
    tally_A: dict[str, Any],
    tally_B: dict[str, Any],
    claimed_D: int,
    proof: dict[str, Any],
) -> dict[str, Any]:
    """
    Verify a ZK proof that count_B - count_A == claimed_D.

    Does NOT require _opening fields.
    Does NOT require the event type filter.
    Takes only the public commitments, the claimed D, and the proof transcript.

    Returns:
        {"result": "PASS" | "FAIL", "claimed_D": int, "valid": bool}
    """
    T_A = _g1_from_dict(tally_A["commitment"])
    T_B = _g1_from_dict(tally_B["commitment"])

    D_commit = add(T_B, neg(T_A))
    check    = add(D_commit, neg(multiply(G, claimed_D % CURVE_ORDER)))

    fs_context = _differential_fs_context(tally_A, tally_B, claimed_D)

    valid = schnorr_verify(check, proof["schnorr_proof"], fs_context)

    return {
        "result":    "PASS" if valid else "FAIL",
        "claimed_D": claimed_D,
        "valid":     valid,
    }


def _differential_fs_context(
    tally_A: dict[str, Any],
    tally_B: dict[str, Any],
    claimed_D: int,
) -> bytes:
    """
    Fiat-Shamir context binding the proof to these specific sessions and claim.
    Both prover and verifier must compute this identically.
    """
    return hashlib.sha256(
        json.dumps(
            {
                "T_A":       tally_A["commitment"],
                "T_B":       tally_B["commitment"],
                "claimed_D": claimed_D,
                "sid_A":     tally_A.get("session_id"),
                "sid_B":     tally_B.get("session_id"),
            },
            sort_keys=True,
        ).encode()
    ).digest()


# ── Self-tests ────────────────────────────────────────────────────────────────

def _make_tally_synthetic(count: int, session_id: str = "test") -> dict[str, Any]:
    """Build a tally directly from (count, random blinding) without a JSONL file."""
    blinding = secrets.randbelow(CURVE_ORDER)
    T = add(multiply(G, count), multiply(H, blinding))
    return {
        "commitment": _g1_to_dict(T),
        "session_id": session_id,
        "merkle_root": None,
        "event_count": count,
        "_opening": {"count": count, "blinding": blinding},
    }


if __name__ == "__main__":
    # ── Phase 1: homomorphic property ────────────────────────────────────────
    r1 = secrets.randbelow(CURVE_ORDER)
    r2 = secrets.randbelow(CURVE_ORDER)
    T3 = add(multiply(G, 3), multiply(H, r1))
    T5 = add(multiply(G, 5), multiply(H, r2))
    T8 = add(multiply(G, 8), multiply(H, (r1 + r2) % CURVE_ORDER))
    assert add(T3, T5) == T8, "Homomorphic property broken"
    print("PHASE 1 PASS — commit(3) + commit(5) == commit(8)")

    # ── Phase 2: differential proof ───────────────────────────────────────────
    t_a = _make_tally_synthetic(0, "baseline")
    t_b = _make_tally_synthetic(3, "colluding")

    # Correct claim D=3: must PASS
    pf_correct = prove_differential(t_a, t_b, 3)
    res = verify_differential(t_a, t_b, 3, pf_correct)
    assert res["result"] == "PASS", f"Correct D=3 should PASS: {res}"

    # Wrong claim D=2 (proof is for D=3, checked as D=2): must FAIL
    res_wrong = verify_differential(t_a, t_b, 2, pf_correct)
    assert res_wrong["result"] == "FAIL", f"Wrong D=2 should FAIL: {res_wrong}"

    # Wrong claim D=0: must FAIL
    res_zero = verify_differential(t_a, t_b, 0, pf_correct)
    assert res_zero["result"] == "FAIL", f"Wrong D=0 should FAIL: {res_zero}"

    # Prover tries to prove a false D=0 honestly: must FAIL verification
    pf_false = prove_differential(t_a, t_b, 0)   # prover "claims" D=0 (lie)
    res_false = verify_differential(t_a, t_b, 0, pf_false)
    assert res_false["result"] == "FAIL", f"Dishonest D=0 proof should FAIL: {res_false}"

    print("PHASE 2 PASS — correct D=3 PASS, wrong D=2 FAIL, wrong D=0 FAIL, dishonest proof FAIL")
