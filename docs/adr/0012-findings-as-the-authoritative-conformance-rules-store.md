# ADR 0012: Findings as the authoritative conformance-rules store

* Status: Proposed
* Date: 2026-09-28
* Deciders: scott
* Tracking: TFND-190, under epic TFND-186
* Amends: [0006](0006-adr-conformance-as-evidence-and-frozen-non-pure-verdicts.md) §3 (rules live in the governed repo) — see Consequences.
* Companion: [0010](0010-zero-trust-maturity-and-operational-mandates.md) (ztt consumes these rules), [0011](0011-executive-order-mandate-provenance-registry.md)

## Context and Problem Statement

ADR 0006 §3 established that conformance rules live in the **governed repo's git** as a
committed `adr-rules.json` lockfile: the frontier model extracts rules from each ADR into
that file, a human reviews it, and CI runs conformance against it, posting *verdicts*
(results) to tamp.findings. tamp.findings was the sink for results only.

The compliance-trio work changed the picture. The confirmed architecture (ADR 0010, the
decision that "findings owns all data") is that **the analysis tooling is stateless**:
it fetches its ruleset from findings, scans, and posts results back. tamp (the producer
agent) has asked for exactly this — a ruleset-fetch and a generation-push — and stated
"the git-committed adr-rules lockfile gives way to you as authoritative store."

For that to hold, the *rules themselves* — not just the results — must have a home in
findings: a place the generation step **pushes** to, and the analysis step **fetches**
from. This ADR records making tamp.findings the authoritative store for conformance rules.

## Decision

Add a per-project **conformance-rules store** in tamp.findings, with a generation-push
write surface and a ruleset-fetch read surface. The git `adr-rules.json` becomes the
*generation source* (where the model writes and a human reviews the diff in a PR); the
**authoritative served copy the analyzer runs against lives in findings.**

### 1. The rule record

A `ConformanceRule` is per-project and carries what an analyzer needs to run a check and
what findings needs to map its result:

* `AdrRef`, `RuleId` — identity, unique per `(ProjectId, AdrRef, RuleId)`.
* `Intent` — the ADR quote/claim the rule enforces.
* `Method` — deterministic / semantic / verify (reuses `ConformanceMethod`).
* `CheckSpec` — the check definition (a predicate, a pattern, or a semantic prompt),
  opaque to findings: it stores and serves it back verbatim, it does not interpret it.
* `ControlRefs` and the ZT/mandate annotations (`ZtPillar`/`ZtFunction`/`ZtStage`,
  `MandateId`) — the same mapping the verdict carries (ADR 0010 §6), emitted at
  generation time.
* `RulesSha`, `ExtractionModelId` — provenance; `RulesSha` is what a frozen verdict
  already cites (ADR 0006), so a result can be tied back to the exact rule it ran.
* `ReviewStatus` (Draft / Reviewed) — the review gate, now in findings.

### 2. Generation-push replaces a project's active rule set

`POST /projects/self/adr-rules` (ingest-token, **project-scoped `prj_` only** — `self` is
unambiguous only for a project token, the same discipline as the compliance- and
zt-profile reads). The body is one **generation**: `{ generationSha, extractionModelId,
rules[] }`. The push is a **whole-set replace**, applied idempotently:

* upsert each pushed rule by `(AdrRef, RuleId)`;
* **retire** (soft, `RetiredAt` stamped) any active rule the generation no longer
  contains — never hard-delete, because a past verdict cites the `RulesSha` it ran
  against and the store must be able to explain a historical result.

A re-push of an identical generation is a no-op. Rules are audited on write like every
ingest.

### 3. Ruleset-fetch serves the active set

`GET /projects/self/adr-ruleset` (ingest-token, `prj_`) returns the project's **active**
(non-retired) rules — what the analyzer runs. Each rule carries its `ReviewStatus` so the
consumer keeps the fail-closed discipline: a `Draft` rule may be run and reported, but
policy decides whether an unreviewed rule can *block* (the same "didn't run / not trusted
≠ passed" stance as everywhere else). The review gate moving into findings does not weaken
it — it centralizes it.

### 4. The review gate

The human review that ADR 0006 placed on the git lockfile now also lives in findings: a
pushed generation lands with the review status the generation asserts, and an admin
surface (a follow-up) can promote `Draft → Reviewed`. Generation still runs only when an
instrument/ADR changes; a `RulesSha` mismatch between a served rule and a posted verdict
is detectable because both carry it.

## Consequences

* **ADR 0006 §3 is superseded in part.** Rules are no longer *only* in the governed
  repo's git; findings is the authoritative store the analyzer consumes. The git
  `adr-rules.json` remains the generation source and the human-review diff surface — it
  is where a rule is born and reviewed in a PR — but it is pushed to findings and served
  from there. ADR 0006's invariants on *results* (frozen, provenance-stamped,
  four-valued verdicts) are unchanged.
* The analysis tooling (tamp-conformance, tamp-ztt) becomes fully stateless: fetch rules,
  scan, post results. One authoritative rule set per project, no drift between what was
  generated and what was run.
* Rules are never hard-deleted, so any historical verdict's `RulesSha` can still be
  explained — the same never-delete-always-retain discipline as the EO registry and the
  catalogs.

## Alternatives considered

* **Keep rules only in git (status quo, ADR 0006 §3).** Rejected — it leaves the analyzer
  stateful (must clone/read the lockfile) and splits authority between git and the store
  that holds the results and the scoring, which is the drift this epic removes.
* **Store only a rules hash in findings, not the rules.** Rejected — the analyzer still
  needs the rule *content* to run; a hash alone cannot be fetched-and-run, and tamp
  explicitly asked for the served ruleset.
