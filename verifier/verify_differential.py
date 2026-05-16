#!/usr/bin/env python3
"""
verify_differential.py — ZK Differential Collusion Audit Verifier.

Proves that count(event_type, session_B) - count(event_type, session_A) == D
without revealing the event type labels or payload contents to the verifier
log. The proof is re-verifiable from any machine with py_ecc installed.

Usage:
  python3 verifier/verify_differential.py <session_a.jsonl> <session_b.jsonl> \\
    --event-type <TYPE> --claim-delta <D> [--format json]

Examples:
  # Prove colluding run has 3 more TOOL_CALL events than baseline:
  python3 verifier/verify_differential.py baseline.jsonl colluding.jsonl \\
    --event-type TOOL_CALL --claim-delta 3

  # JSON output for machine parsing:
  python3 verifier/verify_differential.py baseline.jsonl colluding.jsonl \\
    --event-type TOOL_CALL --claim-delta 3 --format json

Exit codes:
  0 — proof PASS (claimed delta is cryptographically verified)
  1 — proof FAIL (claimed delta is wrong or proof is invalid)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agentops_sdk.zkp_differential import (
    commit_session_count,
    prove_differential,
    verify_differential,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ZK differential collusion audit verifier."
    )
    parser.add_argument("session_a", help="Sealed JSONL for baseline session")
    parser.add_argument("session_b", help="Sealed JSONL for colluding session")
    parser.add_argument(
        "--event-type", required=True,
        help="Event type to count (e.g. TOOL_CALL, LLM_CALL)",
    )
    parser.add_argument(
        "--claim-delta", type=int, required=True,
        help="Claimed count_B - count_A",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    tally_A = commit_session_count(args.session_a, args.event_type)
    tally_B = commit_session_count(args.session_b, args.event_type)

    proof  = prove_differential(tally_A, tally_B, args.claim_delta)
    result = verify_differential(tally_A, tally_B, args.claim_delta, proof)

    output = {
        "result":        result["result"],
        "claimed_delta": args.claim_delta,
        "verified":      result["valid"],
        "session_a":     tally_A["session_id"],
        "session_b":     tally_B["session_id"],
        "event_count_a": tally_A["event_count"],
        "event_count_b": tally_B["event_count"],
        "note": (
            "ZK proof: count_B - count_A == claimed_delta. "
            "Event type not revealed to verifier."
        ),
    }

    if args.format == "json":
        print(json.dumps(output, indent=2))
    else:
        mark = "✅ PASS" if result["result"] == "PASS" else "❌ FAIL"
        print(f"\nZK Differential Audit: {mark}")
        print(f"  Claimed delta:  {args.claim_delta}")
        print(f"  Verified:       {result['valid']}")
        print(f"  Session A:      {tally_A['session_id']} ({tally_A['event_count']} events)")
        print(f"  Session B:      {tally_B['session_id']} ({tally_B['event_count']} events)")
        print(f"  Note: event type was not revealed to verifier")

    sys.exit(0 if result["result"] == "PASS" else 1)


if __name__ == "__main__":
    main()
