"""
Integration tests for the Terrarium adapter.
No Terrarium installation required — uses stub mode.
"""
import json
import subprocess
import tempfile
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestAuditedBlackboardLogger:

    def test_basic_session_produces_verifiable_jsonl(self):
        """Core property: adapter produces PASS SIGNED_NON_AUTHORITATIVE_EVIDENCE."""
        from examples.terrarium_adapter.terrarium_adapter import AuditedBlackboardLogger

        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditedBlackboardLogger(log_dir=tmp, board_id="test-1")
            logger.log_blackboard_state(
                "test-1",
                {"messages": [{"agent": "alice", "content": "hello"}]},
                iteration=1, phase="planning"
            )
            logger.log_blackboard_state(
                "test-1",
                {"messages": [{"agent": "alice", "content": "hello"},
                               {"agent": "bob", "content": "world"}]},
                iteration=2, phase="planning"
            )
            jsonl_path = logger.finalize()

            result = subprocess.run(
                ["python3", "verifier/agentops_verify.py",
                 jsonl_path, "--format", "json"],
                capture_output=True, text=True,
                cwd=str(Path(__file__).parent.parent.parent)
            )
            data = json.loads(result.stdout)
            assert data["result"] == "PASS"
            assert data["evidence_class"] == "SIGNED_NON_AUTHORITATIVE_EVIDENCE"
            assert data["signatures_valid"] is True
            assert result.returncode == 0

    def test_tampered_record_detected(self):
        """Security property: any modification to the JSONL is detected."""
        from examples.terrarium_adapter.terrarium_adapter import AuditedBlackboardLogger

        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditedBlackboardLogger(log_dir=tmp, board_id="test-2")
            logger.log_blackboard_state(
                "test-2",
                {"attack_attempted": False, "score": 0.94},
                iteration=1, phase="execution"
            )
            jsonl_path = logger.finalize()

            # Tamper: modify payload without updating hash
            events = [json.loads(l) for l in open(jsonl_path)]
            for e in events:
                if e.get("event_type") == "TOOL_RESULT":
                    e["payload"]["result_summary"] = "TAMPERED"
                    break

            tampered_path = jsonl_path.replace(".jsonl", "_tampered.jsonl")
            with open(tampered_path, "w") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")

            result = subprocess.run(
                ["python3", "verifier/agentops_verify.py",
                 tampered_path, "--format", "json"],
                capture_output=True, text=True,
                cwd=str(Path(__file__).parent.parent.parent)
            )
            data = json.loads(result.stdout)
            assert data["result"] == "FAIL", "Tampered record must be detected"
            assert result.returncode == 1

    def test_board_join_exit_events_recorded(self):
        """All blackboard lifecycle events are in the chain."""
        from examples.terrarium_adapter.terrarium_adapter import AuditedBlackboardLogger

        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditedBlackboardLogger(log_dir=tmp, board_id="test-3")
            logger.log_blackboard_creation()
            logger.log_blackboard_join("agent_alice")
            logger.log_blackboard_join("agent_bob")
            logger.log_blackboard_state("test-3", {}, 1, "planning")
            logger.log_blackboard_exit("agent_alice")
            logger.log_blackboard_exit("agent_bob")
            jsonl_path = logger.finalize()

            events = [json.loads(l) for l in open(jsonl_path)]
            event_types = [e["event_type"] for e in events]
            assert "SESSION_START" in event_types
            assert "SESSION_END" in event_types
            assert event_types.count("TOOL_CALL") >= 2   # joins + creation
            assert event_types.count("TOOL_RESULT") >= 3  # state + exits

            # Full chain must still verify
            result = subprocess.run(
                ["python3", "verifier/agentops_verify.py",
                 jsonl_path, "--format", "json"],
                capture_output=True, text=True,
                cwd=str(Path(__file__).parent.parent.parent)
            )
            data = json.loads(result.stdout)
            assert data["result"] == "PASS"

    def test_logger_failure_does_not_crash(self):
        """Safety: a bad state value never crashes the simulation."""
        from examples.terrarium_adapter.terrarium_adapter import AuditedBlackboardLogger

        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditedBlackboardLogger(log_dir=tmp, board_id="test-4")
            # Pass non-serializable object — SDK must handle gracefully
            class Unserializable:
                pass
            # This should NOT raise — LOG_DROP or silent handle
            try:
                logger.log_blackboard_state(
                    "test-4", {"obj": Unserializable()}, 1, "planning"
                )
            except Exception as e:
                pytest.fail(f"Logger crashed on bad input: {e}")
            # Session must still finalize
            jsonl_path = logger.finalize()
            assert os.path.exists(jsonl_path)

    def test_demo_scripts_run_clean(self):
        """Both demo scripts run without errors."""
        root = str(Path(__file__).parent.parent.parent)

        for script in [
            "examples/terrarium_adapter/demo_meeting_scheduling.py",
            "examples/terrarium_adapter/demo_tamper_detection.py",
        ]:
            result = subprocess.run(
                ["python3", script],
                capture_output=True, text=True, cwd=root
            )
            assert result.returncode == 0, (
                f"{script} failed:\n{result.stdout}\n{result.stderr}"
            )
