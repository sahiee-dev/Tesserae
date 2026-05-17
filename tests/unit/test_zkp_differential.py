"""
Unit tests for agentops_sdk/zkp_differential.py

Tests cover:
  1. Correct delta passes
  2. Wrong delta fails
  3. Zero delta (both sessions equal) passes
  4. Negative delta (B has fewer events than A) passes when correctly claimed
  5. Tampered commitment fails
"""
import secrets
import pytest

from agentops_sdk.zkp_differential import (
    prove_differential,
    verify_differential,
    _make_tally_synthetic,
    CURVE_ORDER,
)
from agentops_sdk.zkp import _g1_to_dict, _g1_from_dict, G, H
from py_ecc.bn128 import multiply, add


class TestCorrectDelta:
    def test_correct_delta_passes(self):
        """Correct claimed D=3 verifies successfully."""
        t_a = _make_tally_synthetic(0, "baseline")
        t_b = _make_tally_synthetic(3, "colluding")
        proof = prove_differential(t_a, t_b, 3)
        result = verify_differential(t_a, t_b, 3, proof)
        assert result["result"] == "PASS"
        assert result["valid"] is True

    def test_wrong_delta_fails(self):
        """Wrong claimed D=2 when actual delta is 3 is rejected."""
        t_a = _make_tally_synthetic(0, "baseline")
        t_b = _make_tally_synthetic(3, "colluding")
        proof = prove_differential(t_a, t_b, 3)
        result = verify_differential(t_a, t_b, 2, proof)
        assert result["result"] == "FAIL"
        assert result["valid"] is False

    def test_zero_delta_both_equal_passes(self):
        """D=0 passes when both sessions have the same count."""
        t_a = _make_tally_synthetic(4, "run_1")
        t_b = _make_tally_synthetic(4, "run_2")
        proof = prove_differential(t_a, t_b, 0)
        result = verify_differential(t_a, t_b, 0, proof)
        assert result["result"] == "PASS"

    def test_negative_delta_passes_when_correctly_claimed(self):
        """D=-2 passes when B has 2 fewer events than A."""
        t_a = _make_tally_synthetic(5, "heavy")
        t_b = _make_tally_synthetic(3, "light")
        proof = prove_differential(t_a, t_b, -2)
        result = verify_differential(t_a, t_b, -2, proof)
        assert result["result"] == "PASS"

    def test_tampered_commitment_fails(self):
        """Replacing T_B commitment with a different point breaks the proof."""
        t_a = _make_tally_synthetic(0, "baseline")
        t_b = _make_tally_synthetic(3, "colluding")
        proof = prove_differential(t_a, t_b, 3)

        # Build a fake T_B commitment (count=7 instead of 3)
        fake_blinding = secrets.randbelow(CURVE_ORDER)
        fake_T = add(multiply(G, 7), multiply(H, fake_blinding))
        t_b_tampered = dict(t_b)
        t_b_tampered["commitment"] = _g1_to_dict(fake_T)

        result = verify_differential(t_a, t_b_tampered, 3, proof)
        assert result["result"] == "FAIL", (
            "Tampered commitment must be rejected"
        )
