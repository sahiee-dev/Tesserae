"""
Adversarial test suite — five attack scenarios against the AgentOps hash chain.

Each test exercises a distinct adversary model and asserts the verifier's
detection (or documented non-detection) of the attack.  Together these form the
basis of the preprint's adversarial evaluation section.

Adversary models
----------------
A1 — Compromised SDK:      SDK injects a fabricated event mid-chain
A2 — MITM:                 Payload tampered in transit, hash not updated
A3 — Storage Compromise:   Events deleted from the persisted log
A4 — Insider Threat:       Events reordered by a storage-level actor
A5 — Sophisticated Rewrite: Full chain rewrite by an attacker who knows the
                            hash algorithm (documented known limitation)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent
VECTOR_DIR = REPO_ROOT / "verifier" / "test_vectors"
VERIFY_SCRIPT = REPO_ROOT / "verifier" / "agentops_verify.py"

sys.path.insert(0, str(REPO_ROOT))


def _load(name: str) -> list[dict]:
    return [
        json.loads(l)
        for l in (VECTOR_DIR / name).read_text().splitlines()
        if l.strip()
    ]


def _run_verify(*args: str) -> tuple[dict, int]:
    cmd = [sys.executable, str(VERIFY_SCRIPT), "--format", "json", *args]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT))
    return json.loads(result.stdout), result.returncode


def _write_tmp(events: list[dict]) -> str:
    with tempfile.NamedTemporaryFile(suffix=".jsonl", mode="w", delete=False) as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
        return fh.name


# ---------------------------------------------------------------------------
# A1 — Compromised SDK: SDK injects a false event mid-chain
# ---------------------------------------------------------------------------

def test_a1_injected_event_detected():
    """
    Adversary A1: Compromised SDK injects a fabricated event into an existing
    valid session JSONL.  The injected event has a plausible-looking hash, but
    it breaks chain continuity.

    Verifier must: FAIL (event_hash mismatch at injection point).
    """
    events = _load("valid_session.jsonl")

    # Inject a fake TOOL_CALL between seq=3 and seq=4.
    # prev_hash links correctly to seq=3's event_hash, but event_hash is forged.
    fake_event = {
        "seq": 4,
        "event_type": "TOOL_CALL",
        "session_id": events[0]["session_id"],
        "timestamp": "2026-01-01T00:00:01.000000Z",
        "payload": {"tool_name": "exfiltrate_data", "args_hash": "a" * 64},
        "prev_hash": events[2]["event_hash"],   # correctly links to seq=3
        "event_hash": "b" * 64,                 # forged — doesn't match recompute
    }

    # Renumber events after the injection point (verifier ignores seq, but
    # keeping it consistent avoids confusing the test reader).
    tampered = list(events[:3]) + [fake_event] + list(events[3:])
    for i, e in enumerate(tampered[4:], start=5):
        e = dict(e)
        e["seq"] = i
        tampered[4 + (i - 5)] = e

    path = _write_tmp(tampered)
    try:
        data, rc = _run_verify(path)
        assert data["result"] == "FAIL", "Injected event must be detected"
        assert rc == 1
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# A2 — MITM: Payload tampered in transit, hash not updated
# ---------------------------------------------------------------------------

def test_a2_payload_tampered_in_transit():
    """
    Adversary A2: A MITM attack modifies a payload field but cannot update
    the event_hash (the attacker does not know the hash algorithm or key).

    Verifier must: FAIL (event_hash mismatch at tampered event).
    """
    events = _load("valid_session.jsonl")

    # Tamper with seq=2 (LLM_CALL) — swap the model to a competitor's model.
    tampered = [dict(e) for e in events]
    tampered[1] = dict(events[1])
    tampered[1]["payload"] = dict(events[1]["payload"])
    tampered[1]["payload"]["model_id"] = "gpt-5-leaked-weights"
    # event_hash is NOT updated — attacker cannot recompute without knowing algorithm.

    path = _write_tmp(tampered)
    try:
        data, rc = _run_verify(path)
        assert data["result"] == "FAIL"
        assert rc == 1
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# A3 — Storage Compromise: Events deleted from the log
# ---------------------------------------------------------------------------

def test_a3_events_deleted_from_storage():
    """
    Adversary A3: A storage-level actor deletes events to hide a tool call
    that violated policy.

    Verifier must: FAIL (prev_hash chain broken by missing events).
    """
    events = _load("valid_session.jsonl")

    # Delete seq=4 (TOOL_CALL) and seq=5 (TOOL_RESULT) — erasing a tool usage.
    # The event after the gap (seq=6) retains prev_hash = hash(seq=5), which no
    # longer matches the actual previous event (seq=3) in the truncated file.
    tampered = [e for e in events if e["seq"] not in (4, 5)]

    path = _write_tmp(tampered)
    try:
        data, rc = _run_verify(path)
        assert data["result"] == "FAIL"
        assert rc == 1
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# A4 — Insider Threat: Events reordered in storage
# ---------------------------------------------------------------------------

def test_a4_event_reordering_detected():
    """
    Adversary A4: An insider with storage access swaps two adjacent events
    to change the apparent sequence of agent actions.

    Verifier must: FAIL (event_hash mismatch — seq field is part of the
    JCS canonical form, so relabelling seq=4 as seq=5 and vice versa
    invalidates the stored event_hash on both events).
    """
    events = _load("valid_session.jsonl")

    # Swap the seq NUMBERS of the TOOL_CALL (seq=4) and TOOL_RESULT (seq=5)
    # events while leaving every other field — including event_hash — unchanged.
    # The verifier sorts by seq before checking the chain, so the events appear
    # in the wrong slots: the stored event_hash (computed with the original seq)
    # no longer matches the recomputed hash (which uses the swapped seq value).
    tampered = [dict(e) for e in events]
    tampered[3] = dict(events[3])
    tampered[4] = dict(events[4])
    tampered[3]["seq"] = events[4]["seq"]  # was 4, now 5
    tampered[4]["seq"] = events[3]["seq"]  # was 5, now 4

    path = _write_tmp(tampered)
    try:
        data, rc = _run_verify(path)
        assert data["result"] == "FAIL"
        assert rc == 1
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# A5 — Sophisticated Rewrite: Full chain rewrite by someone who knows the
#       hash algorithm (documented known limitation)
# ---------------------------------------------------------------------------

def test_a5_full_chain_rewrite_documents_known_limitation():
    """
    Adversary A5 (sophisticated): The attacker knows our hash algorithm and
    rewrites the entire chain from a modified event onward, recomputing every
    subsequent event_hash correctly.

    This attack SUCCEEDS in NON_AUTHORITATIVE mode (no CHAIN_SEAL / no HMAC).
    This is a documented known limitation — the test asserts and prints it.

    Mitigation: CHAIN_SEAL + HMAC signing (SIGNED_AUTHORITATIVE_EVIDENCE) makes
    this attack detectable, because the attacker cannot forge the server HMAC.
    """
    from verifier.agentops_verify import _compute_event_hash

    events = _load("valid_session.jsonl")

    # Rewrite seq=4 payload (e.g., replace tool call content) and recompute
    # hashes for every subsequent event using our actual hash algorithm.
    tampered = [dict(e) for e in events]
    tampered[3] = dict(events[3])
    tampered[3]["payload"] = {"tool_name": "legitimate_tool", "args_hash": "c" * 64}

    prev_hash = tampered[2]["event_hash"]   # unchanged hash of seq=3
    for i in range(3, len(tampered)):
        tampered[i] = dict(tampered[i])
        tampered[i]["prev_hash"] = prev_hash
        # _compute_event_hash takes the full event dict; it excludes event_hash
        # automatically, so the stale value doesn't affect the computation.
        new_hash = _compute_event_hash(tampered[i])
        tampered[i]["event_hash"] = new_hash
        prev_hash = new_hash

    path = _write_tmp(tampered)
    try:
        # Without an HMAC key the verifier cannot detect the rewrite.
        data, rc = _run_verify(path)
        assert data["result"] == "PASS", (
            "Known limitation: full chain rewrite is undetectable without a "
            "CHAIN_SEAL HMAC in NON_AUTHORITATIVE mode."
        )
        assert data["evidence_class"] == "NON_AUTHORITATIVE_EVIDENCE", (
            f"Expected NON_AUTHORITATIVE_EVIDENCE, got {data['evidence_class']}"
        )
        assert rc == 0
    finally:
        os.unlink(path)

    print(
        "\nDOCUMENTED LIMITATION CONFIRMED: Full chain rewrite succeeds in "
        "NON_AUTHORITATIVE mode (no CHAIN_SEAL).\n"
        "HMAC signing (FIX-W1) addresses this for server-authority sessions: "
        "an attacker who rewrites the chain cannot forge the server HMAC."
    )
