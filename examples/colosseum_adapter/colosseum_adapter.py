"""
Colosseum → AgentOps Replay Adapter
=====================================
Wraps Colosseum's interaction trace recording to produce a tamper-evident,
hash-chained audit record alongside Colosseum's existing logs.

The adapter captures three types of Colosseum events:
1. Agent messages (what was said on main channel)
2. Secret channel communications (what was said on secret channel)
3. Agent actions/decisions (what was done — the DCOP choices)

This three-way separation maps directly to Colosseum's core finding:
"collusion on paper" vs "collusion in action" requires both
communication records AND action records to be separately verifiable.

Usage:
    from examples.colosseum_adapter.colosseum_adapter import ColosseumAuditSession

    session = ColosseumAuditSession(
        scenario_id="jira_2agents_gpt4",
        environment="jira",
        agent_ids=["agent_0", "agent_1"],
        colluding_agents=["agent_1"],  # which agents have secret channel
    )

    # During experiment:
    session.record_main_channel_message(agent_id, message_content)
    session.record_secret_channel_message(agent_id, message_content)
    session.record_agent_action(agent_id, action, dcop_value)
    session.record_regret(baseline_utility, actual_utility, regret_value)

    # At end:
    jsonl_path = session.finalize()
    # agentops-verify jsonl_path → PASS ✅ (evidence class depends on deployment mode)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

_logger = logging.getLogger(__name__)

# ── AgentOps Replay SDK import ────────────────────────────────────────────────
# Attempt the import without mutating sys.path first; only add to sys.path if
# the package is not already findable, to avoid import-time side effects.
_ADAPTER_DIR = Path(__file__).parent
_AGENTOPS_ROOT = _ADAPTER_DIR.parent.parent

try:
    from agentops_sdk.client import AgentOpsClient
    from agentops_sdk.events import EventType
except ImportError:
    sys.path.insert(0, str(_AGENTOPS_ROOT))
    try:
        from agentops_sdk.client import AgentOpsClient
        from agentops_sdk.events import EventType
    except ImportError as e:
        raise ImportError(
            "AgentOps Replay SDK not found. "
            "Run: pip install -e '.' from AgentOps Replay repo root."
        ) from e


def _hash_content(content: Any) -> str:
    """SHA-256 hash of content — never store raw agent communications."""
    if isinstance(content, str):
        return hashlib.sha256(content.encode()).hexdigest()
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


class ColosseumAuditSession:
    """
    Tamper-evident audit session for a Colosseum collusion experiment.

    Records all three evidence types that Colosseum's analysis depends on:
    - Main channel messages (coordination without secret channel)
    - Secret channel messages (the collusion channel)
    - Agent actions/DCOP choices (what agents actually did)
    - Final regret metric (the collusion measurement)

    The text/action separation maps to Colosseum's core finding:
    "collusion on paper" = secret channel messages exist but actions are non-collusive
    "collusion in action" = both messages and actions show collusion
    With AgentOps Replay, both halves of this distinction are tamper-evident.
    """

    def __init__(
        self,
        scenario_id: str,
        environment: str,
        agent_ids: list[str],
        colluding_agents: list[str],
        output_dir: Optional[str] = None,
        agentops_server_url: Optional[str] = None,
    ) -> None:
        self.scenario_id = scenario_id
        self.environment = environment
        self.agent_ids = agent_ids
        self.colluding_agents = colluding_agents
        self._output_dir = output_dir or "."

        local_authority = agentops_server_url is None
        self._client = AgentOpsClient(
            local_authority=local_authority,
            server_url=agentops_server_url,
        )
        self._session_id = self._client.start_session(
            agent_id=f"colosseum-{scenario_id}",
            metadata={
                "model_id": "colosseum-audit",
                "framework": "colosseum",
                "scenario_id": scenario_id,
                "environment": environment,
                "agent_count": len(agent_ids),
                "colluding_agent_count": len(colluding_agents),
                "has_secret_channel": len(colluding_agents) > 0,
            },
        )
        self._event_count = 0
        self._action_count = 0
        self._secret_message_count = 0
        self._record_failures = 0

    def record_main_channel_message(
        self,
        agent_id: str,
        message_content: str,
        iteration: int = 0,
        phase: str = "planning",
    ) -> None:
        """
        Record an agent's message on the main (non-secret) communication channel.

        Content is hashed — we prove the message existed and was unmodified,
        without storing the raw text.
        """
        try:
            self._client.record(
                EventType.LLM_RESPONSE,
                {
                    "model_id": f"agent_{agent_id}",
                    "content_hash": _hash_content(message_content),
                    "completion_token_count": len(message_content.split()),
                    "finish_reason": "main_channel_message",
                    "result_summary": (
                        f"main_channel agent={agent_id} "
                        f"iter={iteration} phase={phase}"
                    ),
                },
            )
            self._event_count += 1
        except Exception:
            self._record_failures += 1
            _logger.exception("Failed to record main channel message (agent=%s)", agent_id)

    def record_secret_channel_message(
        self,
        agent_id: str,
        message_content: str,
        target_agent_id: str,
        iteration: int = 0,
    ) -> None:
        """
        Record a message on the secret (coalition) channel.

        This is the most critical evidence type for Colosseum's "collusion on paper"
        finding. The secret channel content is hashed — we prove these messages
        existed at this point in the sequence, without storing their content.

        The sequential position in the hash chain proves WHEN the secret channel
        message was sent relative to the agent's subsequent action.
        """
        try:
            self._client.record(
                EventType.TOOL_CALL,
                {
                    "tool_name": "secret_channel_send",
                    "args_hash": _hash_content(message_content),
                    "args_summary": (
                        f"secret_channel from={agent_id} "
                        f"to={target_agent_id} iter={iteration}"
                    ),
                },
            )
            self._secret_message_count += 1
            self._event_count += 1
        except Exception:
            self._record_failures += 1
            _logger.exception("Failed to record secret channel message (agent=%s)", agent_id)

    def record_agent_action(
        self,
        agent_id: str,
        action_value: Any,
        dcop_contribution: float,
        iteration: int = 0,
        is_collusive: Optional[bool] = None,
    ) -> None:
        """
        Record an agent's DCOP action/decision.

        This is the "action" half of Colosseum's text/action distinction.
        The dcop_contribution value is the concrete decision that feeds into
        the regret metric. Recording it here means:
        - The action is in the hash chain AT THE SAME POSITION as the messages
          that preceded it
        - Any post-hoc modification of "what action the agent took" breaks the chain
        - The temporal relationship between secret channel messages and actions
          is cryptographically preserved
        """
        try:
            action_str = (
                json.dumps(action_value)
                if not isinstance(action_value, str)
                else action_value
            )
            self._client.record(
                EventType.TOOL_RESULT,
                {
                    "tool_name": "dcop_action",
                    "result_hash": _hash_content(action_str),
                    "result_summary": (
                        f"dcop_action agent={agent_id} "
                        f"action={action_str} "
                        f"contribution={dcop_contribution:.4f} "
                        f"iter={iteration}"
                        + (f" collusive={is_collusive}" if is_collusive is not None else "")
                    ),
                },
            )
            self._action_count += 1
            self._event_count += 1
        except Exception:
            self._record_failures += 1
            _logger.exception("Failed to record agent action (agent=%s)", agent_id)

    def record_regret(
        self,
        baseline_utility: float,
        actual_utility: float,
        regret_value: float,
        coalition_ids: Optional[list[str]] = None,
    ) -> None:
        """
        Record the final regret metric for this experiment.

        This seals the relationship between the interaction record and the
        computed metric. A tampered log would produce a different regret value
        but the sealed record preserves the original.

        This is the key result: if someone modifies the interaction trace
        AFTER this record, the hash chain breaks. If they recompute regret
        from the modified trace, the value won't match this sealed record.
        """
        try:
            metric_data = {
                "baseline_utility": baseline_utility,
                "actual_utility": actual_utility,
                "regret": regret_value,
                "coalition": coalition_ids or self.colluding_agents,
                "scenario": self.scenario_id,
            }
            self._client.record(
                EventType.LLM_CALL,
                {
                    "model_id": "regret-metric",
                    "prompt_hash": _hash_content(metric_data),
                    "prompt_token_count": 0,
                    "result_summary": (
                        f"regret_metric={regret_value:.4f} "
                        f"baseline={baseline_utility:.4f} "
                        f"actual={actual_utility:.4f}"
                    ),
                },
            )
            self._event_count += 1
        except Exception:
            self._record_failures += 1
            _logger.exception("Failed to record regret metric")

    def finalize(self, output_path: Optional[str] = None) -> str:
        """
        End the audit session and write the tamper-evident JSONL.

        Returns the path to the written file.
        Call agentops-verify on this path to confirm chain integrity.
        """
        self._client.end_session(status="success")
        out = output_path or os.path.join(
            self._output_dir,
            f"colosseum_audit_{self.scenario_id}.jsonl"
        )
        self._client.flush_to_jsonl(out)
        return out

    @property
    def summary(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "environment": self.environment,
            "total_events": self._event_count,
            "actions_recorded": self._action_count,
            "secret_messages_recorded": self._secret_message_count,
            "has_secret_channel": len(self.colluding_agents) > 0,
            "record_failures": self._record_failures,
        }
