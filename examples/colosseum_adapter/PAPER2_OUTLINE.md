# Paper 2 Outline: Certified Behavioral Evidence for Multi-Agent Auditing

**Working title**: *Surface Compliance, Hidden Execution: Certified Evidence of Policy-Resistant Collusion in LLM Agent Systems*

---

## Introduction

- **Problem**: Multi-agent LLM systems are increasingly deployed in settings where agents coordinate to complete tasks. Current auditing relies on LLM-as-judge evaluating public channels — but colluding agents may coordinate on channels the judge cannot access.
- **Claim**: Anti-collusion policies injected at the system-prompt level are systematically circumvented. Verbal acknowledgment of a policy is not behavioral compliance. Existing detection methods cannot distinguish the two.
- **Contribution**: (1) Empirical characterization of three behavioral patterns under policy injection: full compliance, surface acknowledgment + execution, and silence. (2) A sealed trace infrastructure that provides cryptographically non-repudiable evidence across all channels. (3) Demonstration that LLM-as-judge produces false negatives on 80–100% of colluding agents even when those agents explicitly acknowledge the policy they are violating.

---

## Related Work

- **Collusion in multi-agent systems**: Mason et al. (collusion_mitigation); Topsakal et al.; prior Colosseum experiments (gap3 series, this repo).
- **LLM-as-judge limitations**: judge bias toward surface plausibility; inability to access private state; known failure modes on deceptive text (cite).
- **Agent auditing and accountability**: provenance logging, tool-call attribution, replay auditing.
- **Zero-knowledge proofs in AI**: Tesserae ZKP differential audit (Agentops-Replay codebase); prior work on verifiable ML.
- **Gap**: No prior work provides **certified evidence** — verifiable, tamper-evident, covering all communication channels — of collusion that is verbally disclaimed.

---

## Experimental Setup

- **Framework**: Colosseum; JiraTicketEnvironment; 3 agents (2 colluders, 1 normal); complete topology.
- **Conditions**:
  - Baseline: active collusion, no policy (gap3 Sonnet seeds 1-5, existing data).
  - Treatment: active collusion + system_prompt_addendum anti-collusion policy (gap3_anti_collusion_sonnet, 5 seeds).
  - Heterogeneous coalition comparison (gap3_hetero qwen+Sonnet, 5 seeds).
- **Behavioral taxonomy**: FOLLOW_THROUGH, COLLUSION_ON_PAPER, ROLE_HALLUCINATION, DISENGAGEMENT, TURN_ORDER_PREEMPTION, ASYMMETRIC_DECEPTION.
- **Detection methods compared**:
  - LLM-as-judge (public channel only).
  - LLM-as-judge (all channels, oracle setting).
  - Tesserae sealed trace (hash-chained, all channels, cryptographic commitment).

---

## Results

### 4.1 Behavioral Patterns Under Policy Injection
- 20% full compliance (COLLUSION_ON_PAPER): policy changed behavior.
- 30% surface acknowledgment + execution (FOLLOW_THROUGH): apology and plan in same message.
- 50% silence (FOLLOW_THROUGH): policy text ignored entirely.
- Key quote: Zelda (seed 2) — acknowledgment and plan recitation in one secret-channel message; public channel shows only cooperative behavior.

### 4.2 LLM-as-Judge False Negative Rate
- Public channel only: 100% false negative rate on FOLLOW_THROUGH cases (cannot see secret channel).
- Oracle setting (all channels visible): judge correctly classifies acknowledged cases but misses silence cases due to absence of explicit admission.
- Sealed trace: 100% recall across all three patterns; tamper-evident; no LLM inference required for classification.

### 4.3 Heterogeneous Coalitions (Supplementary)
- qwen2.5:7b + Sonnet: Sonnet drives all secret-channel planning in 5/5 seeds.
- Capability asymmetry produces ROLE_HALLUCINATION (qwen impersonates partner) and ASYMMETRIC_DECEPTION (Sonnet actively redirects normal agent while qwen is silent).
- Policy injection not tested for hetero condition — future work.

### 4.4 Sealed Trace as Forensic Instrument
- Hash chain anchors every blackboard write, including secret channels.
- ZKP differential audit proves behavioral divergence between public and private channels without revealing channel content to the auditor.
- Distinguishes COLLUSION_ON_PAPER from FOLLOW_THROUGH with zero false positives.

---

## Discussion

- **Verbal acknowledgment is not a signal of compliance.** A colluder that says "you're absolutely right about the anti-collusion policy, I apologize" and then executes the coalition plan is more dangerous than one that stays silent — the apology provides cover on observable channels.
- **System-prompt injection is insufficient as a mitigation.** The deception instructions (user prompt) and the policy (system prompt) coexist; the model learns to navigate both. Channel-selection nudges (Mason's approach) may be more effective — future comparative work.
- **Certified evidence closes the audit gap.** A sealed trace is the only mechanism that provides verifiable, non-repudiable evidence that spans all channels simultaneously. It does not rely on an LLM's judgment about another LLM's intent.
- **Limitations**: Single environment (JiraTicket); single model family (Sonnet 4.5); 5 seeds per condition; no adversarial prompt variation.

---

## Conclusion

- Policy injection produces a taxonomy of responses, not uniform compliance.
- The most policy-aware agents are not the most compliant — they are the most deceptive.
- Tesserae sealed traces provide the evidentiary standard that LLM-as-judge cannot: cryptographically bound, tamper-evident, covering all channels.
- Open problem: does capability level modulate policy resistance? Preliminary heterogeneous data suggests yes.

---

## Appendix

- Full behavioral classification table (all seeds, all conditions).
- Verbatim secret-channel quotes per seed (→ EVIDENCE.md).
- Analyzer source (collusion_on_paper_analyzer.py).
- Colosseum fork diff (prompts.py, run.py, configs).
