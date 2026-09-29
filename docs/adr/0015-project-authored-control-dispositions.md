# ADR 0015: Project-authored control dispositions; archetype as the default (amends 0009)

* Status: Accepted
* Date: 2026-09-29
* Deciders: scott
* Tracking: TFND-209 follow-on (noUnmapped)
* Amends: [0009](0009-control-disposition-and-the-no-unmapped-meta-gate.md) (control disposition + the no-unmapped meta-gate)
* Builds on: [0007](0007-three-layer-harden-only-policy.md) (harden-only template→client→project merge), TFND-203 (the archetype policy layer)

## Context and Problem Statement

ADR 0009 established that a control's disposition — **Gated** (we own it, evidence proves it),
**Inherited** (a layer below provides it), **NotApplicable** (precondition absent), or **Unmapped**
(no assertion; what the `noUnmapped` meta-gate blocks on) — is **derived** from the merged policy
stack, never stored. But in practice the assertions were only authored in **code**: the FedRAMP
templates, plus a nascent archetype layer that shipped **no** control assertions at all
(`ArchetypeLayers.For(Library)` returned an empty layer). So on a real project (`tamp-core`, FedRAMP
High) 229 of 370 controls sat Unmapped with nowhere to be dispositioned.

The tempting fix — disposition by **archetype** (Library / Container / Service) — is necessary but
**not sufficient**, and getting it wrong would be a compliance defect. The tamp ecosystem is ~50
repositories that genuinely differ: `tamp-core` is a build library that implements no cryptography of
its own (its only `System.Security.Cryptography` use is SHA-256 content hashing for build
determinism), so it **inherits** the SC-13 crypto cluster; `tamp-http` may **own** transport crypto
and must assert SC-13 as Gated. An archetype-level answer alone would give both the same disposition,
which is wrong. Authority has to sit at the **project**, and an admin must be able to say, per control,
"no — *we* own this one" (or inherit / N/A), with a justification and the concrete **evidence** (a code
reference) that backs it.

## Decision

**The project is the authority for control dispositions; the archetype and template supply defaults.**

1. **Project-authored dispositions.** An admin authors per-control assertions on the **project policy
   layer** via `PATCH /projects/{id}/control-dispositions` — for each control: `Gated` / `Inherited` /
   `NotApplicable`, a `Justification`, and (for Inherited) `InheritedFrom`. One assertion per control
   id; re-authoring a control replaces its project claim. This is the admin's "we own this / inherit
   this / N-A here" surface, written to prod and auditable.

2. **Justification carries the evidence.** By convention the `Justification` records the concrete code
   reference that backs the call (e.g. *"Inherited — component calls only the platform crypto module;
   `src/Tamp.Core/AbsolutePath.cs:294` is SHA-256 hashing, not confidentiality crypto"*). The
   disposition is not an opinion; it points at the code.

3. **Archetype/template are defaults, not verdicts.** Across ~50 repos, no one hand-dispositions 229
   controls per project. The **archetype** layer supplies a per-archetype baseline (a Library inherits
   the runtime access/comms/auth/audit families it never implements; a Service owns them), and the
   **template** supplies the org/authorization common controls and the gate-backed ("we prove this")
   controls that hold for every system on that baseline. A project only overrides where it differs.
   Archetype/template defaults are **findings-authored** (downgrade-proof — a caller cannot pick an
   archetype to dodge a control).

4. **Merge is unchanged: harden-only, strictest-kind-wins** (`Gated < Inherited < NotApplicable`, per
   0007/0009). Consequences:
   * A project **fills** any Unmapped control (any kind wins where nothing was set).
   * A project may **upgrade** a control to owned — a project `Gated` beats an archetype/template
     `Inherited` (Gated is strictest). This is the `tamp-http` SC-13 case, and it needs no special
     precedence.
   * A project **cannot silently downgrade** — a project `NotApplicable`/`Inherited` will not override
     a stricter upper-layer `Gated`. This preserves the "unscanned control does not pass" guarantee.

5. **Downgrades are an explicit, review-gated exception.** A legitimate project downgrade (an admin
   determining a control genuinely does not apply *here*, over a stricter default) is not a silent
   loosening: it is authored as a project override that takes precedence **only through the review gate**
   (reuse [0012](0012-findings-as-the-authoritative-conformance-rules-store.md) review-gating), so it is
   justified and audited — the same rule as loosening an acceptance gate. *Status: the review-gated
   project-precedence path is not yet built; the current work only fills Unmapped controls, which needs
   no precedence. It lands when the first real non-Unmapped downgrade is needed.*

## Consequences

* **Tracking lives in prod, per project** — the project's dispositions (with evidence) are the record.
  This supersedes any out-of-band ledger; determinations are made in the product as they are decided.
* **The archetype default does the bulk; the project adds specificity.** Deploying the Library
  archetype pack collapses most of the 229 across every library project at once; per-project editing
  then carries the project-specific evidence (code refs) and the genuine differences (`tamp-http` crypto).
* **Two write surfaces, one model.** Archetype/template defaults are authored in code (content packs
  later; TFND-203 trajectory); project dispositions are authored at runtime via the endpoint. Both are
  just `ControlAssertion`s merged by the same resolver — no parallel machinery.
* **The one deferred piece** is the review-gated project-precedence path for downgrades (§5). Until
  then, the model supports fills and upgrades, which covers the entire current unmapped set.
