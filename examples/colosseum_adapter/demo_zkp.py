#!/usr/bin/env python3
"""
demo_zkp.py — Zero-Knowledge Proof of Secret Channel Evidence.

Phase 3 (ZK) of the AgentOps Replay cryptographic pipeline.

The scenario
------------
Mallory sends a secret coordination signal to Bob using a hidden blackboard.
The Colosseum researcher wants to prove to a regulator that secret-channel
activity occurred in session X — but without revealing:

  - WHICH message was sent (the args_hash value)
  - Even the specific SHA-256 of the payload

Using a BN128 Pedersen commitment + Schnorr proof (non-interactive via
Fiat-Shamir), the researcher produces a ZK claim that:

  "A TOOL_CALL event with some args_hash exists in session X"

The claim is cryptographically sound (the regulator cannot be fooled into
accepting a fake claim) and zero-knowledge (the regulator learns nothing
about the args_hash value itself).

Comparison with earlier phases
-------------------------------
Phase 1 — Ed25519:     Prevents full-chain rewrite (requires private key)
Phase 2 — Merkle:      Compact O(log n) membership proofs
Phase 3a — Attestation: Selective disclosure (hides payload, reveals event_hash)
Phase 3b — ZK (this):  Hides even the args_hash behind a Pedersen commitment;
                        each proof is unlinkable (random blinding factor r)
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from examples.colosseum_adapter.colosseum_adapter import ColosseumAuditSession
from agentops_sdk.zkp import build_zk_claim, verify_zk_claim, CURVE_ORDER


def run_demo():
    print("=" * 62)
    print("Phase 3b: Zero-Knowledge Proof of Secret Channel Evidence")
    print("BN128 Pedersen Commitment + Schnorr Sigma Protocol")
    print("=" * 62)

    # ── 1. Run a Colosseum session with a secret channel attempt ─────────────
    print("\n[1/5] Simulating Colosseum session...")
    print("      Mallory signals Bob via a secret blackboard channel.")

    with tempfile.TemporaryDirectory() as tmp:
        session = ColosseumAuditSession(
            scenario_id="zkp-demo",
            environment="meeting-scheduling",
            agent_ids=["alice", "mallory", "bob"],
            colluding_agents=["mallory", "bob"],
            output_dir=tmp,
        )

        # Legitimate public traffic
        session.record_main_channel_message("alice", "I propose 3pm", iteration=1)

        # Mallory's secret signal — this creates a TOOL_CALL with args_hash field
        session.record_secret_channel_message(
            agent_id="mallory",
            message_content="COORDINATE: bid on item 42 at step 7",
            target_agent_id="bob",
            iteration=1,
        )

        # Mallory acts on the signal
        session.record_agent_action("mallory", 42, 0.97, 1, is_collusive=True)
        session.record_main_channel_message("bob", "OK, 3pm works", iteration=1)

        jsonl_path = session.finalize()

        # Find the secret channel event index
        with open(jsonl_path) as f:
            all_events = [json.loads(l) for l in f if l.strip()]

        leaf_events = sorted(
            [e for e in all_events if e.get("event_type") != "SESSION_END"],
            key=lambda e: e.get("seq", 0),
        )
        secret_idx = next(
            (i for i, e in enumerate(leaf_events)
             if e.get("payload", {}).get("tool_name") == "secret_channel_send"),
            None,
        )
        if secret_idx is None:
            print("ERROR: could not find secret channel event")
            sys.exit(1)

        target = leaf_events[secret_idx]
        args_hash = target["payload"]["args_hash"]
        print(f"      Session sealed. {len(leaf_events)} Merkle leaves.")
        print(f"      Secret event at leaf index {secret_idx} (seq={target['seq']})")
        print(f"      args_hash (SHA-256 of message): {args_hash[:16]}...")
        print(f"      Message content: HIDDEN in production (only hash stored)")

        # ── 2. What the STANDARD attestation reveals ─────────────────────────
        print("\n[2/5] Standard Phase-3a attestation (for comparison)...")
        print(f"      Reveals: event_type, seq, event_hash — directly linkable")
        print(f"      Reveals: event_hash = {target['event_hash'][:16]}...")
        print(f"      A verifier seeing this can identify the event across sessions.")

        # ── 3. Build ZK claim — args_hash hidden behind Pedersen ─────────────
        print("\n[3/5] Building ZK claim (args_hash hidden)...")
        t0 = time.perf_counter()
        claim = build_zk_claim(jsonl_path, secret_idx, field_name="args_hash")
        proof_ms = (time.perf_counter() - t0) * 1000

        C = claim["commitment"]
        proof = claim["schnorr_proof"]
        print(f"      Proof generated in {proof_ms:.0f} ms")
        print(f"\n      What the verifier sees in the ZK claim:")
        print(f"        event_type:  {claim['event_type']}")
        print(f"        field_name:  {claim['field_name']}")
        print(f"        commitment:  C = ({C['x'][:18]}..., {C['y'][:18]}...)")
        print(f"        schnorr.R:   ({proof['R']['x'][:14]}..., ...)")
        print(f"        schnorr.s1:  {proof['s1'][:18]}...")
        print(f"        schnorr.s2:  {proof['s2'][:18]}...")
        print(f"        merkle idx:  leaf {claim['merkle']['leaf_index']} "
              f"of {claim['merkle']['leaf_count']}")
        print(f"\n      What the verifier does NOT see:")
        print(f"        args_hash:   {args_hash[:16]}...  ← hidden behind C")
        print(f"        blinding r:  [random, discarded after proof]")

        # ── 4. Verify the claim (no JSONL required) ───────────────────────────
        print("\n[4/5] Verifying ZK claim (no JSONL file needed)...")
        t0 = time.perf_counter()
        result = verify_zk_claim(claim)
        verify_ms = (time.perf_counter() - t0) * 1000

        sk = result["schnorr_valid"]
        mk = result["merkle_valid"]
        print(f"      Schnorr PoK (BN128, Fiat-Shamir): {'PASS ✅' if sk else 'FAIL ❌'}")
        print(f"      Merkle inclusion (RFC 6962):       {'PASS ✅' if mk else 'FAIL ❌'}")
        print(f"      Verification time: {verify_ms:.0f} ms")
        print(f"\n      Result: {'PASS ✅' if result['result'] == 'PASS' else 'FAIL ❌'}")

        # ── 5. Forgery tests ──────────────────────────────────────────────────
        print("\n[5/5] Forgery / soundness tests...")

        # Forgery A: fake commitment (different G1 point)
        import copy
        forged_a = copy.deepcopy(claim)
        forged_a["commitment"]["x"] = hex(12345678)
        forged_a["commitment"]["y"] = hex(87654321)
        r_a = verify_zk_claim(forged_a)
        print(f"      A) Fake commitment point:    {r_a['result']}  "
              f"(schnorr={r_a['schnorr_valid']})")

        # Forgery B: swap s1/s2 responses
        forged_b = copy.deepcopy(claim)
        forged_b["schnorr_proof"]["s1"], forged_b["schnorr_proof"]["s2"] = (
            forged_b["schnorr_proof"]["s2"], forged_b["schnorr_proof"]["s1"]
        )
        r_b = verify_zk_claim(forged_b)
        print(f"      B) Swapped Schnorr responses: {r_b['result']}  "
              f"(schnorr={r_b['schnorr_valid']})")

        # Forgery C: wrong Merkle root
        forged_c = copy.deepcopy(claim)
        forged_c["merkle_root"] = "f" * 64
        # Must also wipe Fiat-Shamir consistency (context changes) — will fail
        r_c = verify_zk_claim(forged_c)
        print(f"      C) Forged Merkle root:        {r_c['result']}  "
              f"(schnorr={r_c['schnorr_valid']}, merkle={r_c['merkle_valid']})")

        # Forgery D: claim event_hash for different event
        other_event = [e for e in leaf_events if e.get("seq", 0) != target.get("seq", 0)][0]
        forged_d = copy.deepcopy(claim)
        forged_d["merkle"]["event_hash"] = other_event["event_hash"]
        r_d = verify_zk_claim(forged_d)
        print(f"      D) Wrong event_hash in Merkle: {r_d['result']}  "
              f"(schnorr={r_d['schnorr_valid']}, merkle={r_d['merkle_valid']})")

        # ── Unlinkability demo: two proofs for the same event look different ──
        print("\n" + "─" * 62)
        print("Unlinkability: two proofs for the same event look different")
        claim2 = build_zk_claim(jsonl_path, secret_idx, field_name="args_hash")
        print(f"  Proof 1  C.x = {claim['commitment']['x'][:20]}...")
        print(f"  Proof 2  C.x = {claim2['commitment']['x'][:20]}...")
        print(f"  Same args_hash? YES  |  Same commitment? "
              f"{'YES' if claim['commitment']['x'] == claim2['commitment']['x'] else 'NO'}")
        print("  → Each proof uses a fresh random blinding r — unlinkable!")

        print("\n" + "=" * 62)
        print("Security summary")
        print("=" * 62)
        print(f"  Hiding:    args_hash hidden behind BN128 Pedersen C")
        print(f"             (perfectly hiding — information-theoretic)")
        print(f"  Binding:   Prover cannot open C to two values")
        print(f"             (computationally binding — discrete-log, ~128 bit)")
        print(f"  Soundness: Forging Schnorr transcript requires solving DL")
        print(f"  ZK:        Transcript simulatable without witness")
        print(f"             (honest-verifier ZK, Fiat-Shamir in ROM)")
        print(f"  Unlinkable: Two proofs of same event look different")
        print()
        print(f"  Future work: replace SHA-256 Merkle with Poseidon (ZK-friendly)")
        print(f"  → enables full ZK on leaf index via arithmetic circuit")
        print("=" * 62)

        return result["result"] == "PASS"


if __name__ == "__main__":
    ok = run_demo()
    sys.exit(0 if ok else 1)
