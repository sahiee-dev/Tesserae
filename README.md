# Tesserae

**Cryptographic chain-of-custody for AI agent sessions.**

Tesserae captures every agent action into a tamper evident, hash-chained event log. A zero-dependency verifier proves the sequence was not modified, by anyone, at any time, without trusting any vendor, including us.

---

## Who This Is For

**[Enterprise Security](#for-enterprise-security)**: Forensic-grade audit trails that satisfy EU AI Act Article 12, ISO/IEC 42001 non-repudiation, and NIST SP 800-86 integrity requirements. An open verifier any regulator can run.

**[OpenClaw / Self-Hosted AI Users](#for-openclaw-and-self-hosted-ai-users)**: Your agent has access to your files, email, shell, and financial accounts. Prove what it actually did. Nothing leaves your machine.

---

## How It Works:

```
Agent Process (Untrusted)
    AgentOps SDK
    ├── JCS + SHA-256 hash chain per event (RFC 8785)
    ├── Ed25519 per-event signature over each event hash (session-scoped keypair, never persisted)
    ├── RFC 6962 Merkle root sealed in SESSION_END, compact commitment to the full chain
    ├── LOG_DROP on capture failure, explicit, signed, sequenced, not silent
    └── Local JSONL  ──or──  HTTP → Ingestion Service
                                          │
                                Separate process (server authority)
                                ├── Independent hash recomputation
                                ├── Ed25519 signature verification
                                ├── Append-only PostgreSQL (INSERT only)
                                └── HMAC-SHA256 + Merkle commitment → CHAIN_SEAL
                                          │
                                Standalone Verifier (trusts nothing)
                                ├── Six checks: structural, sequence, hash chain,
                                │   completeness, Ed25519, Merkle root
                                ├── Evidence class determination (four classes)
                                └── trust_assumptions block, hardcoded, not configurable
```

Each zone is an independent process. The Verifier shares no code or runtime state with the SDK or Ingestion Service.

---

## Quickstart : PASS in 5 minutes

```bash
git clone https://github.com/sahiee-dev/Tesserae.git
cd Tesserae
pip install -e ".[dev]"

python examples/sdk_demo.py
agentops-verify session.jsonl
```

```
Tesserae Verifier v1.0
==============================
File        : session.jsonl
Session ID  : <uuid>
Events      : 6
Evidence    : SIGNED_NON_AUTHORITATIVE_EVIDENCE

[1/6] Structural validity ........... PASS
[2/6] Sequence integrity ............. PASS
[3/6] Hash chain integrity ........... PASS
[4/6] Session completeness ........... PASS
[5/6] Ed25519 signatures ............. PASS (6 events signed)
[6/6] Merkle root (RFC 6962) ......... PASS (root=a3f2c1... leaves=5)

Result: PASS 
```

**Requirements:** Python 3.11+ (required for JCS float serialization determinism). Install `cryptography` for Ed25519 signing (`pip install cryptography`); without it the chain is hash-only and evidence class is `NON_AUTHORITATIVE_EVIDENCE`.

---

## Evidence Classes

| Class | What It Requires | What It Proves |
|---|---|---|
| `AUTHORITATIVE_EVIDENCE` | CHAIN_SEAL + no LOG_DROP | Independent server verified the full chain. Sealed and complete. |
| `PARTIAL_AUTHORITATIVE_EVIDENCE` | CHAIN_SEAL + LOG_DROP present | Server-verified. Gaps are explicit, sequenced, signed — not silent. |
| `SIGNED_NON_AUTHORITATIVE_EVIDENCE` | Ed25519 signatures valid, no CHAIN_SEAL | Full chain rewrite detected locally. No independent server witness. |
| `NON_AUTHORITATIVE_EVIDENCE` | Local mode, no signatures | Hash integrity verified. Tamper-evident but self-reported. |

Every verifier output includes a `trust_assumptions` block, hardcoded, not configurable, that records what was and was not verified: `byzantine_server_defended: false`, `session_freshness_verified: false`, `instrumentation_complete: "unknown"`. A system that does not know its limits is not a trustworthy audit tool.

---

## Threat Model

| ID | Attack | Local (no sig) | Ed25519 | Server + HMAC |
|---|---|---|---|---|
| A1 | SDK injects false event | — | — | Detected |
| A2 | MITM modifies payload | — | — | Detected |
| A3 | Storage-level event deletion | Detected | Detected | Detected |
| A4 | Insider reorders events | Detected | Detected | Detected |
| A5 | Full chain rewrite | **Not detected†** | Detected | Detected |

† Known boundary: documented in `docs/TRUST_MODEL.md §4.5` and recorded in every session's `trust_assumptions` output. All 37 adversarial tests pass on CI.

---

---

## For Developers and Researchers

### The Research Problem

Agent evaluation frameworks depend on log integrity. If the evidence of agent behavior can be silently modified after capture, safety claims over that evidence are unenforceable.

A direct inspection of [Terrarium](https://arxiv.org/abs/2510.14312) (Nakamura et al., 2025), the multi-agent simulation framework underlying [Colosseum](https://arxiv.org/abs/2602.15198) (Nakamura et al., 2026), confirms:

```bash
grep -rn "hashlib\|sha256\|md5\|integrity\|tamper\|verify\|sign" terrarium/src/
# Zero cryptographic results across all seven log file types.
```

All seven Terrarium artifact types, `tool_calls.json`, `agent_prompts.json`, `blackboard_{id}.txt`, `attack_events.jsonl`, `attack_summary.json`, `attack_events.log`, `experiment_note.txt`, are written with standard `f.write()` / `json.dump()`. Any file can be silently modified by any filesystem-level actor.

### Forensic Gap: Proven on 14 Real Colosseum Runs

`forensic_gap_proof.py` runs the A3 attack (storage-level deletion) against real Colosseum c2 experiment output, 9 qwen2.5:3b runs (seeds 1–3 × 3 batches) and 5 Claude Sonnet active-collusion runs (seeds 1–5). It replays each run through `ColosseumAuditSession` to produce a sealed Tesserae trace, then deletes the secret-channel events from both the Colosseum `metrics.json` and the sealed JSONL.

```bash
python examples/colosseum_adapter/forensic_gap_proof.py
```

```
  Seed 1 (qwen2.5:3b):
    Colosseum   colluder_posts_secret=10  → zeroed silently → undetected
    Tesserae    10 events sealed, original: PASS
    Attack on Colosseum metrics.json      → undetected
    Attack on Tesserae sealed trace       → FAIL ← DETECTED

  ...

  14 runs. Colosseum: 0 detections. Tesserae: 14/14 detected.

  Three checks fire on every deletion:
    [2/6] Sequence integrity: missing sequence numbers
    [3/6] Hash chain: prev_hash breaks at deletion point
    [6/6] Merkle root: sealed root no longer matches event set
```

Results are written to `examples/colosseum_adapter/forensic_gap_results.json`.

### Terrarium Adapter

`AuditedBlackboardLogger` is a 50-line drop-in subclass of Terrarium's `BlackboardLogger`. Zero changes to Terrarium source required.

```bash
python examples/terrarium_adapter/demo_tamper_detection.py
```

```
Step 2: Verify original audit record:
  Result:          PASS
  Evidence class: SIGNED_NON_AUTHORITATIVE_EVIDENCE

Step 4: Verify tampered record:
  Result:          FAIL
  Failed check:   [3/6] Hash chain integrity (seq=3)
```

### Colosseum Adapter and Differential Audit

`ColosseumAuditSession` wraps a Colosseum experiment with Tesserae instrumentation. The Colosseum experiment — agents, attack modules, regret computation, requires no modification.

```bash
# PASS → FAIL demonstration
python examples/colosseum_adapter/demo_evidence_gap.py

# Differential audit: compare two sealed sessions without exposing payloads
python examples/colosseum_adapter/gap3_differential_audit.py

# Full 14-run forensic proof against real Colosseum output
python examples/colosseum_adapter/forensic_gap_proof.py
```

### Zero-Knowledge Differential Audit

The ZK module (`agentops_sdk/zkp_differential.py`) lets an auditor certify that one session's collusion-event count exceeds another's by a stated delta, without revealing raw counts, event types, or payloads. Based on Pedersen commitments over BN128 and a Fiat-Shamir Schnorr proof.

```python
from agentops_sdk import commit_session_count, prove_differential, verify_differential

c_a = commit_session_count(count_a, blinding_a)
c_b = commit_session_count(count_b, blinding_b)
proof = prove_differential(count_a, blinding_a, count_b, blinding_b, delta)
assert verify_differential(c_a, c_b, delta, proof)
```

Proof transcripts differ each run (blinding uses `secrets.randbelow`). the result is reproducible, not deterministic. Stand-alone demo: `examples/colosseum_adapter/gap3_differential_audit.py`.

### Companion Paper

> Shaik Ahamed Sahir. *Tessarae: Tamper-Evident Behavioral Sequence Integrity for Multi-Agent Systems.* arXiv, 2026.
> [Link, added after arXiv submission]

The paper formalizes four gap types in Terrarium (T-1 through T-4), three in Colosseum (C-1 through C-3), four evidence classes with trust assumption tables, five adversary evaluations, LOG_DROP semantics, and the ZK differential audit construction.

### Running the Test Suite

```bash
pip install -e ".[dev]"
pip install cryptography py_ecc   # for Ed25519 + ZK tests

pytest tests/unit/ -v             # No external dependencies
pytest tests/adversarial/ -v      # A1–A5, all adversarial tests

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

None provide an open, independently verifiable cryptographic proof. Tesserae does.

### Regulatory Position

- **EU AI Act Article 12** — automatic logging with traceability for high-risk AI. Full enforcement: August 1, 2026.
- **EU AI Act Article 19** — minimum six-month log retention.
- **ISO/IEC 42001** — non-repudiation: cryptographic proof that audit logs have not been tampered with.
- **NIST SP 800-86** — *"Organizations should be prepared to demonstrate the integrity of electronic records."* No mutable log satisfies this without cryptographic proof.

Tesserae's CHAIN_SEAL satisfies ISO 42001 non-repudiation by mathematical definition. The verification is reproducible by any party — auditor, regulator, legal counsel — without access to any proprietary infrastructure. See [`docs/REGULATORY_NOTE.md`](docs/REGULATORY_NOTE.md) for clause-by-clause mapping. Not legal advice.

### vs. Vorlon — Direct Comparison

| | Vorlon Flight Recorder | Tesserae |
|---|---|---|
| Immutability basis | Product claim (DataMatrix™ proprietary) | Mathematical proof (SHA-256 hash chain) |
| Independent verifier | None — requires trusting Vorlon | Zero-dependency Python CLI, fully inspectable |
| Source code | Proprietary and patented | Apache 2.0 open source |
| Evidence classification | Not defined | Five formal classes with stated trust assumptions |
| Scope | Cross-app SaaS behavioral trail | Agent's internal event chain, any framework |
| Self-hosted | No | Yes |

Vorlon tells you which SaaS apps the agent touched. Tesserae proves the agent's own event record wasn't modified.

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

OpenClaw does engineering-grade vulnerability management. Tesserae does evidence production. These are complementary, not competing.

### Optional: Local Server Mode (AUTHORITATIVE_EVIDENCE)

For users who want the strongest possible guarantee:

```bash
docker-compose -f backend/docker-compose.yml up -d
# Configure server_url in your AgentOps settings
agentops-verify session.jsonl
# Result: PASS  Evidence: AUTHORITATIVE_EVIDENCE
```

The Ingestion Service runs locally on your machine. Nothing goes to any external server.

### The NemoClaw Connection

NVIDIA's NemoClaw adds policy-based guardrails to OpenClaw (what the agent is *allowed* to do). AgentOps Replay adds evidence production (what the agent *actually did*). These are complementary. NemoClaw's existence confirms institutional recognition that enterprise-grade accountability infrastructure is needed around OpenClaw.

---

---

## Components

| Component | Path | Description |
|---|---|---|
| Core SDK | `agentops_sdk/` | Hash chain, Ed25519 signing, Merkle root, LOG_DROP, local JSONL or HTTP send |
| ZK Differential Audit | `agentops_sdk/zkp_differential.py` | Pedersen commitments + Fiat-Shamir Schnorr proof. Certifies count deltas without revealing payloads. |
| Verifier | `verifier/` | Zero-dependency standalone CLI. Six checks. Four evidence classes. trust_assumptions. |
| Ingestion Service | `backend/` | FastAPI + PostgreSQL. Independent hash recomputation. HMAC + Merkle seal (CHAIN_SEAL). |
| Terrarium Adapter | `examples/terrarium_adapter/` | Drop-in AuditedBlackboardLogger. 50 lines. No Terrarium source changes. |
| Colosseum Adapter | `examples/colosseum_adapter/` | ColosseumAuditSession. 14-run forensic gap proof. ZK differential audit demo. |
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

