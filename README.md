# AgentOps Replay

**Cryptographic chain-of-custody for AI agent sessions.**

AgentOps Replay captures every agent action into a tamper-evident, hash-chained event log. A zero-dependency verifier proves the sequence was not modified — by anyone, at any time — without trusting any vendor, including us.

---

## Who This Is For

**[Enterprise Security](#for-enterprise-security)** — Forensic-grade audit trails that satisfy EU AI Act Article 12, ISO/IEC 42001 non-repudiation, and NIST SP 800-86 integrity requirements. An open verifier any regulator can run.

**[OpenClaw / Self-Hosted AI Users](#for-openclaw-and-self-hosted-ai-users)** — Your agent has access to your files, email, shell, and financial accounts. Prove what it actually did. Nothing leaves your machine.

---

## How It Works

```
Agent Process (Untrusted)
    AgentOps SDK
    ├── JCS + SHA-256 hash chain per event (RFC 8785)
    ├── Ed25519 per-event signatures (session-scoped, never written to disk)
    ├── LOG_DROP on capture failure — explicit, signed, not silent
    └── Local JSONL  ──or──  HTTP → Ingestion Service
                                          │
                                Separate process (server authority)
                                ├── Independent hash recomputation
                                ├── Ed25519 signature verification
                                ├── Append-only PostgreSQL (INSERT only)
                                └── RFC 6962 Merkle commitment → CHAIN_SEAL
                                          │
                                Standalone Verifier (trusts nothing)
                                ├── Six integrity checks
                                ├── Evidence class determination
                                └── trust_assumptions block — honest about limits
```

Each zone is an independent process. The Verifier shares no code or runtime state with the SDK or Ingestion Service.

---

## Quickstart — PASS in 5 minutes

```bash
git clone https://github.com/sahiee-dev/Agentops-replay.git
cd Agentops-replay
pip install -e .

python examples/sdk_demo.py
agentops-verify session.jsonl
```

```
AgentOps Replay Verifier v1.0
==============================
File        : session.jsonl
Session ID  : <uuid>
Events      : 6
Evidence    : NON_AUTHORITATIVE_EVIDENCE

[1/4] Structural validity ........... PASS
[2/4] Sequence integrity ............. PASS
[3/4] Hash chain integrity ........... PASS
[4/4] Session completeness ........... PASS

Result: PASS ✅
```

**Requirements:** Python 3.11+ (required for JCS float serialization determinism)

---

## Evidence Classes

| Class | What It Requires | What It Proves |
|---|---|---|
| `SIGNED_AUTHORITATIVE_EVIDENCE` | CHAIN_SEAL + HMAC-SHA256 + Merkle root + no LOG_DROP | Highest. Server identity attested. Full chain rewrite detected. |
| `AUTHORITATIVE_EVIDENCE` | CHAIN_SEAL present + no LOG_DROP | Server independently verified the full chain. Complete and sealed. |
| `PARTIAL_AUTHORITATIVE_EVIDENCE` | CHAIN_SEAL + LOG_DROP present | Server-verified. Gaps are explicit, sequenced, signed — not silent. |
| `SIGNED_NON_AUTHORITATIVE_EVIDENCE` | Ed25519 signatures valid, no CHAIN_SEAL | Chain rewrite detected locally. No independent server witness. |
| `NON_AUTHORITATIVE_EVIDENCE` | Local mode only | Hash integrity verified. Tamper-evident but self-reported. |

Every verifier output includes a `trust_assumptions` block — hardcoded, not configurable — that records `byzantine_server_defended: false`, `session_freshness_verified: false`, `instrumentation_complete: "unknown"`. A system that does not know its limits is not a trustworthy audit tool.

---

## Threat Model

| ID | Attack | Local (no sig) | Ed25519 | Server + HMAC |
|---|---|---|---|---|
| A1 | SDK injects false event | — | — | Detected |
| A2 | MITM modifies payload | — | — | Detected |
| A3 | Storage-level event deletion | Detected | Detected | Detected |
| A4 | Insider reorders events | Detected | Detected | Detected |
| A5 | Full chain rewrite | **Not detected†** | Detected | Detected |

† Known boundary — documented in `docs/TRUST_MODEL.md §4.5` and recorded in every session's `trust_assumptions` output. All 37 adversarial tests pass on CI.

---

---

## For Developers and Researchers

### The Research Problem

Agent evaluation frameworks depend on log integrity. If the evidence of agent behavior can be silently modified after capture, safety claims over that evidence are unenforceable.

A direct inspection of [Terrarium](https://arxiv.org/abs/2510.14312) (Nakamura et al., 2025) — the multi-agent simulation framework underlying [Colosseum](https://arxiv.org/abs/2602.15198) (Nakamura et al., 2026) — confirms:

```bash
grep -rn "hashlib|sha256|md5|integrity|tamper|verify|sign" terrarium/src/
# Zero cryptographic results across all seven log file types.
```

All blackboard state snapshots, tool call records, prompt logs, agent trajectories, attack events, attack summaries, and experiment notes are written with standard Python file I/O. Any file can be modified by any filesystem-level actor without detection.

A live Colosseum experiment made this concrete: Colosseum's `metrics.json` field `colluder_posts_secret` reported **zero** secret-channel attempts for both the baseline and colluding runs. The AgentOps Replay sealed trace recorded **three** distinct secret-channel tool invocations in the colluding run and zero in the baseline. The aggregate metric was wrong. The event-level trace was right.

```
Native metrics.json — both runs:
  colluder_posts_secret: 0

Sealed AgentOps Replay trace (colluding run):
  TOOL_CALL [event_type=secret_channel]  seq=4
  TOOL_CALL [event_type=secret_channel]  seq=7
  TOOL_CALL [event_type=secret_channel]  seq=11

Delta: +3 secret-channel events. Native log: undetectable deletion.
Sealed log: immediate FAIL at hash chain integrity check.
```

### Terrarium Integration

`AuditedBlackboardLogger` is a 50-line drop-in subclass of Terrarium's `BlackboardLogger`. Zero changes to Terrarium source required.

```bash
python examples/terrarium_adapter/demo_tamper_detection.py
```

```
Step 2 — Verify original audit record:
  Result:         ✅ PASS
  Evidence class: NON_AUTHORITATIVE_EVIDENCE

Step 4 — Verify tampered record:
  Result:         ❌ FAIL
  Failed check:   [3/4] Hash chain integrity (seq=3)
```

### Colosseum Integration and Differential Audit

`ColosseumAuditSession` wraps a Colosseum experiment with AgentOps Replay instrumentation. The Colosseum experiment — agents, attack modules, regret computation — requires no modification.

```bash
# Three-step proof: PASS → FAIL → native undetected
python examples/colosseum_adapter/demo_evidence_gap.py

# Differential audit: compare two sealed sessions without exposing payloads
python examples/colosseum_adapter/gap3_differential_audit.py
```

### Companion Paper

> Shaik Ahamed Sahir. *AgentOps Replay: Tamper-Evident Behavioral Sequence Integrity for Multi-Agent Systems.* arXiv, 2026.
> [Link — added after arXiv submission]

The paper formalizes four gap types in Terrarium (T-1 through T-4), three in Colosseum (C-1 through C-3), five evidence classes with trust assumption tables, five adversary evaluations, and LOG_DROP semantics. All 37 adversarial tests are deterministic and require only Python 3.11 stdlib.

### Running the Test Suite

```bash
pip install -e ".[langchain,server,dev]"

pytest tests/unit/ -v                  # No external dependencies
pytest tests/adversarial/ -v           # A1–A5, all 37 tests

python verifier/generator.py
agentops-verify verifier/test_vectors/valid_session.jsonl     # exit 0
agentops-verify verifier/test_vectors/tampered_hash.jsonl     # exit 1
agentops-verify verifier/test_vectors/sequence_gap.jsonl      # exit 1

# Start Ingestion Service (AUTHORITATIVE_EVIDENCE mode)
docker-compose -f backend/docker-compose.yml up -d
curl http://localhost:8000/health
```

---

---

## For Enterprise Security

### The Forensic Gap

88% of organizations running AI agents reported a confirmed or suspected security incident in the past year. The average enterprise manages 37 deployed AI agents with no centralized audit. Shadow AI incidents carry an average additional cost of $670,000 over standard incidents. *(RSAC 2026, AGAT Software)*

The forensic question every security team faces after an AI agent incident:

> "Who authorized the action, which tool was invoked, what data was accessed, and what was the outcome — and can we prove it?"

The Mexico government breach (December 2025 – February 2026) illustrated this directly: a single attacker used AI agents to breach nine agencies, exfiltrating 195 million taxpayer records and 220 million civil records. The forensic challenge was not detection — it was chain of custody. AI agents acting at machine speed with no cryptographic record of what each agent accessed, in what order, and what it produced.

### The One Claim No Competitor Can Make

> Run `agentops-verify session.jsonl`. If it outputs `AUTHORITATIVE_EVIDENCE`, the record has not been modified since the session was sealed. You do not need to trust us. The verification logic is open source Python you can inspect and run on an air-gapped machine.

**Vorlon Flight Recorder** asserts immutability via proprietary DataMatrix™ technology — no standalone verifier, no open cryptographic specification, no evidence classification system.

**OpenAI Compliance Logs** covers only OpenAI model calls, defaults to 30-day retention (EU AI Act Article 19 requires six months), and requires trusting OpenAI's infrastructure for integrity verification.

**CrowdStrike, Palo Alto, Rubrik** audit their own security tooling — not the customer's application agents. Different problem.

None provide an open, independently verifiable cryptographic proof. AgentOps Replay does.

### Regulatory Position

- **EU AI Act Article 12** — automatic logging with traceability for high-risk AI. Full enforcement: August 1, 2026.
- **EU AI Act Article 19** — minimum six-month log retention.
- **ISO/IEC 42001** — non-repudiation: cryptographic proof that audit logs have not been tampered with.
- **NIST SP 800-86** — *"Organizations should be prepared to demonstrate the integrity of electronic records."* No mutable log satisfies this without cryptographic proof.

AgentOps Replay's CHAIN_SEAL satisfies ISO 42001 non-repudiation by mathematical definition. The verification is reproducible by any party — auditor, regulator, legal counsel — without access to AgentOps infrastructure. See [`docs/REGULATORY_NOTE.md`](docs/REGULATORY_NOTE.md) for clause-by-clause mapping. Not legal advice.

### vs. Vorlon — Direct Comparison

| | Vorlon Flight Recorder | AgentOps Replay |
|---|---|---|
| Immutability basis | Product claim (DataMatrix™ proprietary) | Mathematical proof (SHA-256 hash chain) |
| Independent verifier | None — requires trusting Vorlon | Zero-dependency Python CLI, fully inspectable |
| Source code | Proprietary and patented | Apache 2.0 open source |
| Evidence classification | Not defined | Five formal classes with stated trust assumptions |
| Scope | Cross-app SaaS behavioral trail | Agent's internal event chain, any framework |
| Self-hosted | No | Yes |

Vorlon tells you which SaaS apps the agent touched. AgentOps Replay proves the agent's own event record wasn't modified.

### Enterprise Roadmap

**v1.0 (current):** Core SDK + verifier + Ingestion Service. Five evidence classes. 37-test adversarial suite. Terrarium, Colosseum, LangChain integrations.

**v1.1:** SIEM webhook (CEF/LEEF/ECS). FORENSIC_FREEZE mode. PII redaction with hash integrity preserved. ECDSA signing (non-repudiation without symmetric key distribution). Nonce-based session freshness.

**v2.0:** RFC 6962 transparency log — CHAIN_SEAL Merkle roots published publicly, making Byzantine server equivocation detectable by any third party.

---

---

## For OpenClaw and Self-Hosted AI Users

### Your Agent Has Broad Access. Can You Prove What It Did?

OpenClaw (formerly Clawdbot / Moltbot) gives your AI agent access to your shell, files, email, calendar, and financial accounts. It runs on a heartbeat schedule — waking up autonomously, even overnight, taking actions without being prompted.

OpenClaw's session logs at `~/.openclaw/agents/<agentId>/sessions/*.jsonl` tell you what happened. Those files are mutable plaintext. Anyone with shell access — including an attacker who exploited CVE-2026-25253 (1-click RCE, January 2026) — can modify or delete them silently. There is no way to prove the log you're looking at is the original one.

AgentOps Replay adds cryptographic proof. And nothing leaves your machine.

### Install and Verify

```bash
pip install agentops-replay
# Instrument your OpenClaw sessions — a sealed JSONL is produced automatically

agentops-verify ~/.openclaw/agentops/<session_id>.jsonl
```

```
Result: PASS ✅
Evidence: NON_AUTHORITATIVE_EVIDENCE
```

**Privacy guarantees (critical for self-hosters):**
- LLM prompts, responses, tool arguments, and results are stored as SHA-256 hashes only. Raw content never appears in the AgentOps log.
- Local authority mode (default): nothing leaves your machine. JSONL stays in `~/.openclaw/agentops/`.
- Verifier has zero external dependencies. Runs without network access. No account required.

### OpenClaw Built-In vs. AgentOps Replay

| Property | OpenClaw Built-In | AgentOps Replay |
|---|---|---|
| Log format | JSONL session transcripts | Hash-chained JSONL event envelopes |
| Tamper evidence | None — files are mutable | SHA-256 chain — any change detected immediately |
| Verification | No independent tool | `agentops-verify` — zero-dependency, runs anywhere |
| Evidence class | Not defined | Formal classes with stated trust levels |
| Content stored? | Full conversation transcripts | Hashes only — content never stored |
| Requires account? | No | No |

OpenClaw does engineering-grade vulnerability management. AgentOps Replay does evidence production. These are complementary, not competing.

### Optional: Local Server Mode (AUTHORITATIVE_EVIDENCE)

For users who want the strongest possible guarantee:

```bash
docker-compose -f backend/docker-compose.yml up -d
# Configure server_url in your AgentOps settings
agentops-verify session.jsonl
# Result: PASS ✅  Evidence: AUTHORITATIVE_EVIDENCE
```

The Ingestion Service runs locally on your machine. Nothing goes to any external server.

### The NemoClaw Connection

NVIDIA's NemoClaw adds policy-based guardrails to OpenClaw (what the agent is *allowed* to do). AgentOps Replay adds evidence production (what the agent *actually did*). These are complementary. NemoClaw's existence confirms institutional recognition that enterprise-grade accountability infrastructure is needed around OpenClaw.

---

---

## Components

| Component | Path | Description |
|---|---|---|
| Core SDK | `agentops_sdk/` | Hash chain, Ed25519 signing, LOG_DROP, local JSONL or HTTP send |
| Verifier | `verifier/` | Zero-dependency CLI. Six checks. Evidence class. trust_assumptions. |
| Ingestion Service | `backend/` | FastAPI + PostgreSQL. Independent hash recomputation. Merkle seal. |
| Terrarium Adapter | `examples/terrarium_adapter/` | Drop-in AuditedBlackboardLogger. 50 lines. No Terrarium source changes. |
| Colosseum Adapter | `examples/colosseum_adapter/` | ColosseumAuditSession. Differential audit. metrics.json discrepancy demo. |
| LangChain Integration | `sdk/python/` | AgentOpsCallbackHandler. Zero config. Content hashed at callback boundary. |

## Documentation

- [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md) — Formal guarantees, five adversary classes, known limits, what a PASS does not prove
- [`docs/EVENT_LOG_SPEC.md`](docs/EVENT_LOG_SPEC.md) — 8-field envelope, 12 event types, hash algorithm, GENESIS_HASH definition
- [`docs/CHAIN_AUTHORITY_INVARIANTS.md`](docs/CHAIN_AUTHORITY_INVARIANTS.md) — Authority separation, evidence class conditions, frozen invariants
- [`docs/FAILURE_MODES.md`](docs/FAILURE_MODES.md) — LOG_DROP semantics, CHAIN_BROKEN, A5 boundary condition
- [`docs/REGULATORY_NOTE.md`](docs/REGULATORY_NOTE.md) — EU AI Act, NIST AI RMF, ISO/IEC 42001 clause mapping (not legal advice)

## License

Apache 2.0 — See [LICENSE](LICENSE)

---

> **Note on naming:** This project is currently named AgentOps Replay for continuity with a prior published system (Sahir, IEEE 2026) and active external links. A rename to **Tessera** is planned once link dependencies resolve. The name better reflects the system's actual function — cryptographic chain-of-custody and tamper-evident audit — rather than session replay, which was the focus of the v1 system. GitHub will redirect automatically when the rename happens.
