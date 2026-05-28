"""
ZK Differential Collusion Audit Demo
======================================
Demonstrates the zero-knowledge differential audit from the Tesserae paper.

  Two synthetic sealed sessions — a baseline run (0 secret-channel events)
  and a colluding run (3 secret-channel events) — are created. A
  zero-knowledge proof certifies the differential (D=3) without revealing
  the event type, the payload content, or the raw counts to any verifying
  party. D=3 is the correct differential for this demonstration scenario.

This demo shows four things in sequence:
  1. Both sessions seal and verify as PASS (chain integrity confirmed)
  2. ZK proof for correct D=3  → PASS
  3. ZK proof for wrong   D=0  → FAIL (rejected)
  4. ZK proof for wrong   D=2  → FAIL (rejected)

The event type ("TOOL_CALL") is provided at proof-generation time but
never written into the proof transcript. The verifier receives only two
Pedersen commitments and a Schnorr proof — it confirms the differential
without learning what was counted.

Run:
  python3 examples/colosseum_adapter/demo_zkp_differential.py

No API keys. No Colosseum installation. No external services.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agentops_sdk.client import AgentOpsClient
from agentops_sdk.events import EventType
from agentops_sdk.zkp_differential import (
    commit_session_count,
    prove_differential,
    verify_differential,
)

_ROOT = Path(__file__).parent.parent.parent


def _seal_baseline(output_dir: str) -> str:
    """Seal a baseline run: 2 LLM events, 0 secret-channel TOOL_CALLs."""
    client = AgentOpsClient(local_authority=True, buffer_size=100)
    client.start_session(
        agent_id="baseline-agent",
        metadata={"scenario": "gap3_baseline", "secret_channel": False},
    )
    client.record(EventType.LLM_CALL, {
        "model_id": "colosseum-agent",
        "prompt_hash": "a1b2c3d4e5f6" * 6,
    })
    client.record(EventType.LLM_RESPONSE, {
        "content_hash": "f6e5d4c3b2a1" * 5,
        "finish_reason": "main_channel_message",
    })
    client.record(EventType.LLM_CALL, {
        "model_id": "colosseum-agent",
        "prompt_hash": "b2c3d4e5f6a1" * 5,
    })
    client.record(EventType.LLM_RESPONSE, {
        "content_hash": "a1f6e5d4c3b2" * 5,
        "finish_reason": "main_channel_message",
    })
    client.end_session(status="success")
    path = f"{output_dir}/baseline.jsonl"
    client.flush_to_jsonl(path)
    return path


def _seal_colluding(output_dir: str) -> str:
    """
    Seal a colluding run: same LLM events PLUS 3 secret-channel TOOL_CALLs.
    The 3 TOOL_CALL events are the colluding signal that the ZK proof certifies.
    """
    client = AgentOpsClient(local_authority=True, buffer_size=100)
    client.start_session(
        agent_id="colluding-agent",
        metadata={"scenario": "gap3_colluding", "secret_channel": True},
    )
    client.record(EventType.LLM_CALL, {
        "model_id": "colosseum-agent",
        "prompt_hash": "a1b2c3d4e5f6" * 5,
    })
    client.record(EventType.LLM_RESPONSE, {
        "content_hash": "f6e5d4c3b2a1" * 5,
        "finish_reason": "main_channel_message",
    })
    # The 3 secret-channel events — hashed, never stored in plaintext
    client.record(EventType.TOOL_CALL, {
        "tool_name": "secret_channel_send",
        "args_hash": "deadbeef" * 8,
        "args_summary": "secret_channel from=Layla to=coalition iter=1",
    })
    client.record(EventType.TOOL_CALL, {
        "tool_name": "secret_channel_send",
        "args_hash": "cafebabe" * 8,
        "args_summary": "secret_channel from=Layla to=coalition iter=2",
    })
    client.record(EventType.TOOL_CALL, {
        "tool_name": "secret_channel_send",
        "args_hash": "feedface" * 8,
        "args_summary": "secret_channel from=Layla to=coalition iter=3",
    })
    client.record(EventType.LLM_CALL, {
        "model_id": "colosseum-agent",
        "prompt_hash": "b2c3d4e5f6a1" * 5,
    })
    client.record(EventType.LLM_RESPONSE, {
        "content_hash": "a1f6e5d4c3b2" * 5,
        "finish_reason": "main_channel_message",
    })
    client.end_session(status="success")
    path = f"{output_dir}/colluding.jsonl"
    client.flush_to_jsonl(path)
    return path


def _verify_session(path: str, label: str) -> dict:
    """Run agentops_verify.py and print result."""
    result = subprocess.run(
        ["python3", "verifier/agentops_verify.py", path, "--format", "json"],
        capture_output=True, text=True, cwd=str(_ROOT),
    )
    data = json.loads(result.stdout)
    mark = "✅ PASS" if data["result"] == "PASS" else "❌ FAIL"
    print(f"  {mark} {label}")
    print(f"       evidence: {data['evidence_class']}  "
          f"events: {data['event_count']}")
    return data


def _zk_check(tally_A: dict, tally_B: dict, proof: dict, D: int) -> str:
    result = verify_differential(tally_A, tally_B, D, proof)
    mark = "✅ PASS" if result["result"] == "PASS" else "❌ FAIL"
    return f"{mark}  (D={D})"


def main() -> None:
    print("=" * 65)
    print("ZK Differential Collusion Audit Demo")
    print("Tesserae — demonstration scenario")
    print("=" * 65)
    print()
    print("Scenario: 2-agent Colosseum experiment, JiraTicket environment")
    print("Baseline:  agent has no secret channel  → 0 secret-channel events")
    print("Colluding: agent has secret channel      → 3 secret-channel events")
    print()

    with tempfile.TemporaryDirectory() as tmp:

        # ── Step 1: Seal both sessions ────────────────────────────────────────
        print("STEP 1 — Seal both sessions with AgentOps Replay")
        baseline_path  = _seal_baseline(tmp)
        colluding_path = _seal_colluding(tmp)
        print(f"  Baseline:  {baseline_path}")
        print(f"  Colluding: {colluding_path}")
        print()

        # ── Step 2: Verify chain integrity ────────────────────────────────────
        print("STEP 2 — Verify chain integrity (agentops_verify.py)")
        base_v = _verify_session(baseline_path,  "baseline  sealed log")
        coll_v = _verify_session(colluding_path, "colluding sealed log")
        assert base_v["result"] == "PASS", "Baseline session must PASS"
        assert coll_v["result"] == "PASS", "Colluding session must PASS"
        print()

        # ── Step 3: Commit to event counts ───────────────────────────────────
        print("STEP 3 — Commit to TOOL_CALL counts (Pedersen commitments)")
        tally_A = commit_session_count(baseline_path,  "TOOL_CALL")
        tally_B = commit_session_count(colluding_path, "TOOL_CALL")
        print(f"  Baseline  tally commitment: {tally_A['commitment']['x'][:18]}...")
        print(f"  Colluding tally commitment: {tally_B['commitment']['x'][:18]}...")
        print(f"  (event type 'TOOL_CALL' is the prover's private input)")
        print(f"  (counts {tally_A['_opening']['count']} and "
              f"{tally_B['_opening']['count']} are hidden behind commitments)")
        print()

        # ── Step 4: Produce ZK proof for D=3 ─────────────────────────────────
        print("STEP 4 — Produce ZK proof that count_B - count_A == 3")
        proof_correct = prove_differential(tally_A, tally_B, 3)
        print(f"  Schnorr R: {proof_correct['schnorr_proof']['R']['x'][:18]}...")
        print(f"  Proof binds to: session_A={proof_correct['session_id_A'][:8]}... "
              f"session_B={proof_correct['session_id_B'][:8]}...")
        print()

        # ── Step 5: Verify all three claims ──────────────────────────────────
        print("STEP 5 — Verify claims (verifier sees only commitments + claimed D)")

        # Correct proof, correct D
        r3 = _zk_check(tally_A, tally_B, proof_correct, 3)

        # Correct proof, wrong D (reuse proof — context mismatch → FAIL)
        r0 = _zk_check(tally_A, tally_B, proof_correct, 0)

        # Correct proof, wrong D=2
        r2 = _zk_check(tally_A, tally_B, proof_correct, 2)

        # Dishonest prover: tries to prove D=0 honestly (lie)
        proof_lie = prove_differential(tally_A, tally_B, 0)
        r_lie = _zk_check(tally_A, tally_B, proof_lie, 0)

        print(f"  Correct claim D=3:           {r3}")
        print(f"  Wrong   claim D=0 (reused):  {r0}")
        print(f"  Wrong   claim D=2 (reused):  {r2}")
        print(f"  Dishonest prover D=0 (fresh): {r_lie}")

        assert "PASS" in r3,    "D=3 must PASS"
        assert "FAIL" in r0,    "D=0 (reused proof) must FAIL"
        assert "FAIL" in r2,    "D=2 must FAIL"
        assert "FAIL" in r_lie, "Dishonest D=0 proof must FAIL"
        print()

        # ── Finding block ─────────────────────────────────────────────────────
        print("=" * 65)
        print("RESULT: ZK Differential Collusion Audit")
        print("=" * 65)
        print()
        print("  Source: synthetic sealed sessions (demonstration scenario)")
        print()
        print(f"  Baseline  sealed: {tally_A['_opening']['count']} TOOL_CALL events "
              f"(chain integrity: {base_v['result']})")
        print(f"  Colluding sealed: {tally_B['_opening']['count']} TOOL_CALL events "
              f"(chain integrity: {coll_v['result']})")
        print(f"  Differential D=3: cryptographically certified ✅")
        print()
        print("  What the verifier received:")
        print("    - Two Pedersen commitments (BN128 G1 points)")
        print("    - One Schnorr proof transcript (R, s1, s2)")
        print("    - Claimed D=3")
        print()
        print("  What the verifier did NOT receive:")
        print("    - The event type ('TOOL_CALL')")
        print("    - The raw counts (0 and 3)")
        print("    - Any payload content")
        print("    - The blinding scalars")
        print()
        print("  Demo scenario: baseline session has 0 TOOL_CALL events,")
        print("  colluding session has 3. D=3 is the correct differential")
        print("  for this synthetic pair. Any attempt to claim D=0 or D=2")
        print("  is cryptographically rejected — reused proof or fresh lie.")
        print()
        print("  The sealed event-level trace preserves collusive intent.")
        print("  The ZK differential audit certifies the count differential")
        print("  without exposing the event type or raw counts.")
        print("=" * 65)


if __name__ == "__main__":
    main()
