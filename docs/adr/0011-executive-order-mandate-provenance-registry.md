# ADR 0011: Executive-order mandate provenance registry

* Status: Proposed
* Date: 2026-09-28
* Deciders: scott
* Tracking: tamp-EOProvenance design brief (Executive-Order Mandate Provenance Registry)
* Companion: [0010](0010-zero-trust-maturity-and-operational-mandates.md) (ztt, consumes these mandates), [0006](0006-adr-conformance-as-evidence-and-frozen-non-pure-verdicts.md) (the Capability-1 extraction engine this reuses)

## Context and Problem Statement

`tamp-EOProvenance` is the authoritative, **versioned, effective-dated** registry of
executive-order and implementing-memo mandates and their authority chain. It answers
one question, defensibly, for any date: *what was mandated, by what authority, and
since when.* It is a **provenance registry, not a checker** — it never touches a repo.
It owns the *definitions and dates* of mandates; the scoring engines (tamp-findings,
tamp-ztt) consume those definitions and produce the pass/fail evidence against real
systems.

The consumer is executive: a secretary or CISO who must show the department is
executing the sitting administration's cyber directives, system by system, as of a
date. EOs are political instruments with a fast, discontinuous lifecycle — they flip
with administrations — so the registry's whole value is being able to say what was in
force *then*, not just now.

This ADR records **how the registry's persistence, model, ingestion, and crosswalk
live inside tamp.findings**, reusing the conformance Capability-1 extraction engine
and the shared POA&M model, per the one-store decision.

## Decision

### 1. Scope: the political layer only

Track **executive orders, their implementing OMB memos, and presidential/NSM
directives of the same character** — and nothing else. NIST catalogs (800-53,
800-218, the KSIs) stay out: they are the apolitical technical bedrock the scoring
engines already map evidence to (the `ControlCatalog` / `MaturityModelCatalog`),
revise on a slow cycle, and are referenced by the crosswalk (§5) but never tracked
here.

### 2. The provenance object model: Instruments and Directives

Two linked entities, plus an append-only status history.

- **`Instrument`** — an EO, memo, NSM, or presidential memo: identifier (EO 14028,
  M-22-09), title, issuing authority, instrument type, issue/signing date,
  publication cite, and provenance (source hash, extraction model id, review status).
- **`InstrumentRelation`** — the authority graph, explicit and first-class: a typed,
  directed edge (`amends` / `revokes` / `supersedes` / `implements`) from one
  instrument (optionally a specific section) to another. An EO rarely stands alone —
  it amends prior EOs and delegates to memos, and memos implement the EO. **The
  relationship graph is the heart of the product**, so it is modeled as edges, not
  as flat foreign keys.
- **`Directive`** — one obligation extracted from an instrument: source instrument +
  section, *who* (agency/role), *must-do*, *by-when* (§4), *applicability*
  (all systems / national-security systems / where-applicable), *type* (§3),
  crosswalk (§5), and provenance stamp. Its **status is not a column** but an
  append-only effective-dated history (§4).

### 3. Directive types — only one becomes a check

The classification keeps the registry honest; it is emitted at extraction time and
human-reviewed:

- **Self-executing dated requirement** ("encrypt at rest by DATE") → a checkable
  mandate with an effective date; crosswalks to a findings/ztt check (§5). Rare in
  EOs, common in memos.
- **Delegation** ("OMB shall issue guidance within 90 days") → a tracking milestone
  and a forward link to the memo that will carry the real deadline. **Not** a
  technical check. This is why EOs seldom hold hard dates — they hand them to memos.
- **Aspirational** ("shall promote", "encourage") → no rule; dropped by abstention.

### 4. Never delete, always date — the point-in-time engine

A compliance claim is only meaningful against the mandate set **in force on the
evaluation date**, and a rescinded directive must stop accruing findings while
staying historically true as-of-then. So:

- **Every status change is an append-only, effective-dated row**
  (`DirectiveStatusChange`: directive, new status `active | rescinded | superseded`,
  effective date, the instrument that caused it, recorded-at). Nothing is ever
  deleted or mutated. A directive's status *as of any date* is the latest change on
  or before that date. This append-only history hooks the same `GuardAuditTrail`
  immutability the audit log and attestation snapshots already use.
- **Dates are anchored.** A directive's `by-when` is absolute, or **relative**
  (offset + anchor, e.g. "within 90 days of the signing date" or "within 1 year of a
  predicate memo's issue"). When the anchor is a future event that has not occurred,
  the directive is a first-class **`date-pending`** state, resolved when the anchor
  lands. Date-anchoring is one of the two things EOs need that ADRs do not.
- **Amendment-diff is the other.** When a new instrument issues, its
  amends/revokes/supersedes relations are diffed against the corpus and written as
  effective-dated status changes onto the affected prior directives
  (`active → rescinded as of DATE`), and their crosswalked checks go **dormant** with
  that date. Rescinds are **forward-dated, not retroactive**: a system
  non-compliant with a since-rescinded directive stays historically non-compliant
  as-of-then and simply stops accruing new findings after the rescind date.

The worked example the engine must handle: EO 14306 (June 6 2025) struck roughly half
of EO 14144 — machine-readable secure-software attestation, CISA central validation,
the FAR amendments, the PQC-adoption mandate, the WebAuthn deployment requirement,
the expanded email-TLS directive. Each flips to `rescinded as of 2025-06-06`, their
crosswalked checks go dormant with that date, and nothing is deleted. **That
diff-and-effective-date behavior is the product; the current-EO list is only a
re-verifiable snapshot.**

### 5. Crosswalk down; the partition is fixed by target

Each surviving dated requirement links (`DirectiveCrosswalk`) to the check in
tamp-findings or tamp-ztt that proves it — encrypt-at-rest → the storage-encryption
check; MFA → the identity check; secure-software attestation → the findings
supply-chain check. The crosswalk is the join that turns a political directive into a
per-system, as-of-date status. **The split is fixed by the crosswalk target:**
supply-chain mandates point into tamp-findings, operational mandates point into
tamp-ztt (ADR 0010 §7). The partition is enforced so no mandate is scored twice or
dropped. Every mandate result from the scoring engines is stamped with the
mandate-pack version as of its evaluation date — the same way conformance freezes
evidence against a model-id and rules-hash.

### 6. Ingestion = conformance Capability-1 + two additions

The registry needs no new extraction engine. It is the ADR engine's Capability 1
(prose → machine-checkable rules, abstention over invention, a committed
hash-stamped human-reviewed lockfile, staleness-fails-closed) pointed at EOs/memos,
with exactly two additions: the **amendment-differ** (§4) and the **date-anchor
resolver** (§4). Everything else — extraction-confidence, human-reviewed source,
frozen provenance — carries over unchanged.

The committed, hash-stamped source is an **`eo-directives` corpus** (the analogue of
the governed repo's `adr-rules.json` lockfile). Because this registry is centralized
rather than per-governed-repo, the corpus is a committed artifact **in this repo**
(`Content/eo/`), seeded on startup by content hash like the OSCAL catalog, and
regenerated only when an instrument issues; source-hash drift without regeneration
fails closed. A model misreading a clause is caught in human review before trust —
the stakes here are legal/political, so the review gate is not optional.

## Consequences

* Point-in-time queries ("what was in force on 2025-05-01, and was system S compliant
  with it *then*") fall out of the append-only effective-dated history.
* The authority graph is queryable — "what does EO 14306 amend, and which directives
  did that kill" — because relations are first-class edges.
* One POA&M model spans the trio: a mandate is *defined and dated* here, *checked* in
  findings or ztt, and a failed check is a POA&M in the shared model, stamped with the
  in-force mandate version.
* The registry is definitions-only; it never evaluates a system, so it holds no
  build/scan data and opens no repo-facing surface.

## Open questions (carried to the design doc / build)

Instrument sourcing (Federal Register / OMB feeds) and issuance detection; the
crosswalk partition sign-off with findings + ztt; how a delegation with no
implementing memo yet is surfaced as visibly-tracked rather than lost; applicability
scoping ("where applicable" / "national-security systems") reusing ztt's N/A
semantics; the review cadence + authority for a trusted directive set; and the
snapshot re-verification process — specified in
`docs/design/tamp-ztt-eoprovenance-data-model.md`.
