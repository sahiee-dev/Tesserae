# AgentOps Replay — Glossary

Terms defined as they are used in this repository. For formal specifications,
see the linked source documents.

---

## AUTHORITATIVE_EVIDENCE

An evidence class assigned when the session passes all verifier checks, contains a CHAIN_SEAL, and has no LOG_DROP or CHAIN_BROKEN events. It proves that an independent process (the Ingestion Service) received the events, independently recomputed the hash chain, found it valid, and sealed it. Requires the trust assumption that the Ingestion Service is honest. (README §Evidence Classes; TRUST_MODEL §2.2)

## CHAIN_BROKEN

A server-authority event emitted by the Ingestion Service when it detects an unresolvable sequence gap in an incoming event batch — for example, receiving `seq = 1, 2, 5, 6` with no events for `seq = 3, 4`. Unlike LOG_DROP (client-side loss), CHAIN_BROKEN signals that the gap was detected at the point of ingestion. Its presence degrades the evidence class to PARTIAL_AUTHORITATIVE_EVIDENCE. (EVENT_LOG_SPEC §2.2; FAILURE_MODES §2)

## CHAIN_SEAL

A server-authority event appended by the Ingestion Service after successfully verifying and storing a complete session. Its payload includes `final_hash`, `authority`, `event_count`, `server_timestamp`, and `server_version`, and it is signed with HMAC-SHA256. The presence of a CHAIN_SEAL is the distinguishing condition that elevates evidence from NON_AUTHORITATIVE to AUTHORITATIVE. (EVENT_LOG_SPEC §2.2; TRUST_MODEL §2.2)

## Ed25519

A public-key digital signature algorithm used by the SDK to sign each event hash with a session-scoped keypair that is never persisted. Ed25519 signatures enable the SIGNED_NON_AUTHORITATIVE_EVIDENCE class. Without the `cryptography` library installed, the chain falls back to hash-only mode and evidence class is NON_AUTHORITATIVE_EVIDENCE. (README §How It Works, §Evidence Classes)

## event_hash

A SHA-256 hex digest (64 lowercase hex characters) computed over the JCS-canonicalized representation of the event, excluding the `event_hash` field itself. It binds all six other envelope fields into a single tamper-evident unit. The Ingestion Service independently recomputes this value and rejects any event whose hash does not match. (EVENT_LOG_SPEC §1.7, §3)

## Evidence Classes

Four formal classifications of session integrity strength, determined by the verifier after all checks pass. **AUTHORITATIVE_EVIDENCE**: CHAIN_SEAL present, no LOG_DROP. **PARTIAL_AUTHORITATIVE_EVIDENCE**: CHAIN_SEAL present, LOG_DROP or CHAIN_BROKEN present. **SIGNED_NON_AUTHORITATIVE_EVIDENCE**: Ed25519 signatures valid, no CHAIN_SEAL. **NON_AUTHORITATIVE_EVIDENCE**: local mode, hash integrity only. Each class carries explicit trust assumptions documenting what was and was not verified. (README §Evidence Classes; EVENT_LOG_SPEC §5; TRUST_MODEL §2)

## GENESIS_HASH

The sentinel value used as the `prev_hash` of the first event (`seq = 1`) in any session: a string of 64 ASCII zero characters (`0000...0000`). It is not a hash of any real data. Any other value in `prev_hash` at `seq = 1` constitutes a structural violation and results in a verifier FAIL. (EVENT_LOG_SPEC §4)

## JCS (JSON Canonicalization Scheme, RFC 8785)

The deterministic JSON serialization used to produce the hash input for every event. JCS sorts object keys lexicographically at all nesting levels and removes insignificant whitespace, yielding a deterministic byte sequence regardless of key insertion order. Python 3.11+ is required for correct JCS float serialization determinism. The canonical implementation lives at `verifier/jcs.py`. (EVENT_LOG_SPEC §3; README §How It Works)

## LOG_DROP

An SDK-authority event emitted when one or more events are lost due to buffer overflow or an SDK internal error. Its payload records `count`, `reason`, `seq_range_start`, and `seq_range_end`. LOG_DROP is a first-class chain event that participates in hash linking — it is never omitted. Its presence downgrades a sealed session from AUTHORITATIVE_EVIDENCE to PARTIAL_AUTHORITATIVE_EVIDENCE. The governing invariant: visible failure is always preferable to silent failure. (EVENT_LOG_SPEC §2.1; FAILURE_MODES §1)

## Merkle root

An RFC 6962 Merkle tree root computed by the SDK as a compact cryptographic commitment to the full set of events in the session. The verifier recomputes the Merkle root from the event hashes and compares it against the committed value; a mismatch (e.g., from event deletion) causes check [6/6] to FAIL. The CHAIN_SEAL also includes a Merkle commitment on the server side. (README §How It Works, §Quickstart)

## NON_AUTHORITATIVE_EVIDENCE

The baseline evidence class assigned when a session passes all verifier checks but contains no CHAIN_SEAL. The hash chain is internally consistent, but no independent process has corroborated it. Vulnerable to adversary A5 (full chain rewrite by an attacker who knows JCS). Analogous to an uncorroborated witness statement. (README §Evidence Classes; TRUST_MODEL §2.1)

## PARTIAL_AUTHORITATIVE_EVIDENCE

An evidence class assigned when a CHAIN_SEAL is present but one or more LOG_DROP or CHAIN_BROKEN events are also present. The captured portion is server-verified, and the gaps are explicit, sequenced, and signed — not silent. By definition, completeness is not guaranteed. (README §Evidence Classes; TRUST_MODEL §2.4)

## Pedersen commitment

A homomorphic commitment scheme over the BN128 elliptic curve used in the zero-knowledge differential audit module (`agentops_sdk/zkp_differential.py`). It allows an auditor to certify that one session's collusion-event count exceeds another's by a stated delta, without revealing raw counts, event types, or payloads. Combined with a Fiat-Shamir Schnorr proof for verification. (README §Zero-Knowledge Differential Audit)

## prev_hash

The `event_hash` of the immediately preceding event in the session. This field creates the backward-linked hash chain: `prev_hash[N] = event_hash[N-1]`. For `seq = 1`, it must equal the GENESIS_HASH. Reordering or deleting any event breaks the `prev_hash` linkage, causing the verifier to report FAIL at the hash chain integrity check. (EVENT_LOG_SPEC §1.6; TRUST_MODEL §4.4)

## seq

A monotonically increasing, strictly positive integer identifying the position of an event within its session. The first event must have `seq = 1`; each subsequent event must increment by exactly one. Gaps, duplicates, or non-integer values constitute a chain integrity violation. Sequence numbers — not timestamps — define the canonical ordering of events. (EVENT_LOG_SPEC §1.1)

## SIGNED_NON_AUTHORITATIVE_EVIDENCE

An evidence class assigned when Ed25519 per-event signatures are valid but no CHAIN_SEAL is present. Defends against adversary A5 (full chain rewrite) because the attacker cannot forge signatures without the session-scoped private key. No independent server witness exists. (README §Evidence Classes; TRUST_MODEL §2)

## Tesserae vs. AgentOps Replay (naming)

The project is currently named **AgentOps Replay** for continuity with a prior published system (Sahir, IEEE 2026) and active external links. A rename to **Tesserae** is planned once link dependencies resolve. The name Tesserae better reflects the system's actual function — cryptographic chain-of-custody and tamper-evident audit — rather than session replay, which was the focus of the v1 system. GitHub will redirect automatically when the rename happens. (README, final note)

## trust_assumptions

A structured block included in every verifier output that records what was and was not verified for a given session. Fields include `byzantine_server_defended: false`, `session_freshness_verified: false`, and `instrumentation_complete: "unknown"`. The block is hardcoded and not configurable — a system that does not know its limits is not a trustworthy audit tool. (README §Evidence Classes; TRUST_MODEL §6)
