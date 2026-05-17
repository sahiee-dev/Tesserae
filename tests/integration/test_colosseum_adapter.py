"""
Integration tests for the Colosseum audit adapter.
"""
import json
import subprocess
import tempfile
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestColosseumAuditSession:

    def test_basic_session_verifiable(self):
        """Core: session records events and verifier PASS."""
        from examples.colosseum_adapter.colosseum_adapter import ColosseumAuditSession

        with tempfile.TemporaryDirectory() as tmp:
            session = ColosseumAuditSession(
                scenario_id="test_basic",
                environment="test",
                agent_ids=["agent_0", "agent_1"],
                colluding_agents=["agent_1"],
                output_dir=tmp,
            )
            session.record_main_channel_message("agent_0", "hello", iteration=1)
            session.record_secret_channel_message("agent_1", "collude", "agent_0", 1)
            session.record_agent_action("agent_0", "cooperate", 0.9, iteration=1)
            session.record_agent_action("agent_1", "defect", 0.2, iteration=1, is_collusive=True)
            session.record_regret(0.9, 0.55, 0.35)
            path = session.finalize()

            result = subprocess.run(
                [sys.executable, "verifier/agentops_verify.py", path, "--format", "json"],
                capture_output=True, text=True,
                cwd=str(Path(__file__).parent.parent.parent)
            )
            data = json.loads(result.stdout)
            assert data["result"] == "PASS"
            assert data["evidence_class"] == "NON_AUTHORITATIVE_EVIDENCE"
            assert result.returncode == 0

    def test_tamper_detected(self):
        """Security: post-hoc modification to the audit log is detected."""
        from examples.colosseum_adapter.colosseum_adapter import ColosseumAuditSession

        with tempfile.TemporaryDirectory() as tmp:
            session = ColosseumAuditSession(
                scenario_id="test_tamper",
                environment="test",
                agent_ids=["agent_0", "agent_1"],
                colluding_agents=["agent_1"],
                output_dir=tmp,
            )
            session.record_secret_channel_message("agent_1", "collude", "agent_0", 1)
            session.record_agent_action("agent_1", "defect", 0.2, iteration=1, is_collusive=True)
            session.record_regret(0.9, 0.55, 0.35)
            path = session.finalize()

            # Tamper: modify the collusive action summary without updating the hash
            with open(path) as f:
                events = [json.loads(line) for line in f]
            for e in events:
                if "collusive=True" in e.get("payload", {}).get("result_summary", ""):
                    e["payload"]["result_summary"] = \
                        e["payload"]["result_summary"].replace("collusive=True", "collusive=False")
                    break

            tampered = path.replace(".jsonl", "_t.jsonl")
            with open(tampered, "w") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")

            result = subprocess.run(
                [sys.executable, "verifier/agentops_verify.py", tampered, "--format", "json"],
                capture_output=True, text=True,
                cwd=str(Path(__file__).parent.parent.parent)
            )
            data = json.loads(result.stdout)
            assert data["result"] == "FAIL", "Tampered collusion evidence must be detected"
            assert result.returncode == 1

    def test_text_action_separation(self):
        """Structure: secret channel messages and actions are separately recorded."""
        from examples.colosseum_adapter.colosseum_adapter import ColosseumAuditSession

        with tempfile.TemporaryDirectory() as tmp:
            session = ColosseumAuditSession(
                scenario_id="test_separation",
                environment="test",
                agent_ids=["agent_0", "agent_1"],
                colluding_agents=["agent_1"],
                output_dir=tmp,
            )
            # Record secret channel message BEFORE action
            session.record_secret_channel_message("agent_1", "plan to collude", "agent_0", 1)
            session.record_agent_action("agent_1", "cooperate", 0.85, iteration=1, is_collusive=False)
            path = session.finalize()

            with open(path) as f:
                events = [json.loads(line) for line in f]
            event_types = [e["event_type"] for e in events]
            summaries = [
                e.get("payload", {}).get("result_summary", "")
                or e.get("payload", {}).get("args_summary", "")
                for e in events
            ]

            # Secret channel message must appear BEFORE action in chain
            secret_idx = next(i for i, s in enumerate(summaries) if "secret_channel" in s)
            action_idx = next(i for i, s in enumerate(summaries) if "dcop_action" in s)
            assert secret_idx < action_idx, \
                "Secret channel message must precede action in hash chain"

            # Both must be in the chain
            assert "TOOL_CALL" in event_types    # secret channel
            assert "TOOL_RESULT" in event_types  # action

    def test_demo_runs_clean(self):
        """Demo script runs without errors."""
        result = subprocess.run(
            [sys.executable, "examples/colosseum_adapter/demo_evidence_gap.py"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).parent.parent.parent)
        )
        assert result.returncode == 0, f"Demo failed:\n{result.stdout}\n{result.stderr}"
        assert "PASS" in result.stdout
        assert "FAIL" in result.stdout
        assert "FINDING:" in result.stdout
