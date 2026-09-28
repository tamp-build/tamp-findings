# ADR 0010: Zero Trust maturity + operational mandates in tamp.findings

* Status: Proposed
* Date: 2026-09-28
* Deciders: scott
* Tracking: tamp-ztt design brief (Zero Trust Maturity Scoring from Repo Evidence)
* Companion: [0011](0011-executive-order-mandate-provenance-registry.md) (the EO/memo registry that defines the mandates), [0006](0006-adr-conformance-as-evidence-and-frozen-non-pure-verdicts.md) (the conformance engine this derives from), [0009](0009-control-disposition-and-the-no-unmapped-meta-gate.md) (the disposition pattern this mirrors)

## Context and Problem Statement

`tamp-ztt` scores a system against the CISA Zero Trust Maturity Model (ZTMM v2.0)
from repo + ADR evidence, and — in the same evaluation — checks the binary
operational mandates of EO 14028 (encrypt at rest / in transit, MFA, IPv6 where
applicable). The maturity axis is a **graded gauge** (5 pillars, cross-cutting
folded per-pillar, stages 1–4 with a floor of 1 and no zero); the mandate axis is
a **binary gate** that generates POA&Ms. The two axes behave *oppositely* on an
undetermined result and must not be conflated.

The decision this ADR records: **where and how the persistence, model, rulesets,
and ingestion for tamp-ztt live inside tamp.findings**, reusing the existing
substrate (the conformance engine, the four-valued verdict, the POA&M model, the
framework-per-client vocabulary, frozen provenance, ingest-token auth) rather than
standing up a parallel store. tamp-ztt's scoring math and UI live in that tool;
tamp.findings owns the data foundation it reads and writes.

The core property to preserve, end to end, is **conservative-by-construction**:
the engine can only under-claim. Every number is a floor evidence or a corroborated
pick can raise; nothing greens without derivation or a corroborated pick.

## Decision

### 1. The scored unit is a **System**, modeled as a first-class entity

The ZTMM scored unit is a *system* (a CSAM inventory entry) — which may be an app,
a data center, a network pipe, a kube cluster, or a database farm. That is broader
than a `Project` (which is repo/build-shaped: it carries a GitHub repository,
components, versions). Overloading `Project` would force non-repo systems into a
repo-shaped hole and read oddly in every findings screen.

So a new `ZtSystem` entity is the scored node. A `ZtSystem` belongs to a `Client`
(inheriting the ZTMM assignment, §3), carries the CSAM identity, and **optionally
references a `Project`** — that link is what feeds build/conformance evidence into
the derivation for repo-backed *consumer systems*. A `ZtSystem` with no linked
`Project` (a data center, a network) is legitimate: it simply has no derived
evidence, so every function defaults to 1 (§4), exactly as the model intends.

*Alternative considered — system = Project:* maximal reuse, but it either pollutes
the Project table with CSAM/system semantics or excludes non-repo systems from ZT
scoring entirely. Rejected; the optional `Project` FK gives the reuse without the
overload.

### 2. Two node types: consumer systems vs enterprise offerings

- **Consumer systems** are `ZtSystem` rows (§1).
- **Enterprise offerings (provider nodes)** are an admin-defined, free-form
  registry — a new `EnterpriseOffering` entity plus its per-function scores. An
  offering is named by a service-level id and defined *entirely* by the per-function
  stage scores it confers; the engine ships **no built-in catalog** and encodes
  nothing about any specific technology. Distinct tiers of one tool are distinct
  offerings with distinct scores. An offering is scored **once** and inherited by
  N systems (§5).

### 3. ZTMM is a maturity model, assigned on its **own axis**

`Client.FrameworkId` is singular and already carries the *control-baseline*
framework (800-53 / GovRAMP). A client held to a control baseline is also ZT-scored,
so ZTMM cannot ride `FrameworkId`. ZTMM is a different kind of vocabulary — pillars
× functions × stages, not a control list — so it gets its **own catalog and its own
assignment**:

- A `MaturityModelCatalog` (versioned, one `IsCurrent`, jsonb pillars→functions→
  stage-descriptors), paralleling `ControlCatalog`. Seeded from the shipped CISA
  ZTMM v2.0 structure, refreshed by content hash, prior versions retained for
  reproducibility — the same lifecycle as the OSCAL catalog.
- ZT scoring applies to a `ZtSystem` when its client opts in (a nullable
  `Client.MaturityModelId`, distinct from `FrameworkId`). No opt-in → no ZT surface,
  no noise.

### 4. Per-function disposition is **derived on read**; only picks are stored

Every pillar-function, for every system, resolves to exactly one disposition —
`owned` (verified / committed / contradicted), `inherited` (edge-attested /
edge-committed), `not-applicable`, or `undetermined`. This is the ZT analogue of the
`no-unmapped` control disposition (ADR 0009), and it follows the same discipline:
**the disposition is a pure function of evidence ∩ picks ∩ model, computed on read**,
never a stored per-function verdict that could drift.

What is *stored* is only the state a human supplies or a tool ingests:
- **Maturity evidence** — conformance verdicts carrying a pillar/function/stage
  assertion (§6), frozen like all conformance evidence.
- **Inheritance edges** and their **attestations** (§5).
- **Owner picks** — N/A role declarations and committed intents (§7).

What is *derived* — the per-function disposition, its stage, its grade, and the
roll-up — is computed by a pure `ZtDispositionResolver` + a pinned scoring contract
(§8), mirroring `ControlDispositionResolver` and `GateEvaluator`.

**The default rule and its guard (critical).** Anything not derived, not inherited,
and not dispositioned N/A defaults to **stage 1 (Traditional)** — never 0, never
blank, never a block. This makes the score self-improving and un-gameable. The guard:
`undetermined → 1` must **never** swallow `not-applicable`. N/A leaves the
denominator entirely; collapsing it into 1 re-creates the scale-poisoning bug. N/A
stays off the number line — the same guard ADR 0009's resolver already enforces for
controls.

### 5. Inheritance is **attested, not machine-verified**, capped, and expires

A repo cannot see the enterprise plumbing (the SQL-to-Splunk ingestor, the storage
platform's encryption), so a system inherits those functions from an offering by an
explicit edge. Three rules, all conservative:

- **Provider scored once; min-cap flows downhill.** A consumer inheriting a function
  from an offering capped at Advanced can never exceed Advanced on that function.
  Roll-up across inherited functions is therefore a **min, not an average** (§8).
- **The edge is attested.** tamp-ztt records *who attested, when, and what evidence
  they attached* (provider-team email, onboarding/enrollment confirmation, digital
  proof) and freezes it as audit-ready provenance. It does **not** judge whether the
  evidence proves reality — in a government audit the chain of custody is the
  deliverable, not a truth claim. An edge with attester + statement + evidence is
  `edge-attested`; a bare pick is `edge-committed` (scored but flagged: "attest and
  attach proof").
- **Attestations go stale.** Every attestation carries a date and an expiry; an
  expired attestation degrades `edge-attested` back toward `edge-committed` until
  refreshed — the same stale-evidence-is-no-evidence rule as the SBOM-age gate and
  the conformance disposition expiry.

### 6. Maturity + mandate evidence derive from the conformance engine

tamp-ztt needs no new verification engine — the ADR-conformance system (ADR 0006)
is it. Rule generation (Capability 1) must additionally emit, beside the existing
control mapping, either the **pillar / function / stage** the ADR represents
(maturity) or the **mandate id** it satisfies (binary). This is an additive
extension to the conformance ingest wire contract (`ConformancePayloadDto`) and to
the stored evidence.

The verdict → disposition mapping is near 1:1 and computed on read:

| Conformance verdict | ztt maturity disposition | ztt mandate result |
|---|---|---|
| `pass` | `owned / verified` — score the stage | mandate met |
| `fail` | `owned / contradicted` — claimed-and-broken | **POA&M** |
| `unknown` | `owned / committed` — routes to spot-check, blocks green | unproven — **blocks**, never a pass |
| `error` | data-quality hole | data-quality hole |

Stage and grade are **orthogonal** (ADR 0006's frozen-verdict spirit, applied to a
graded framework): the *stage* (1–4) is a property of what the ADR/evidence decided
and is emitted at rule-generation time; the *grade* (verified/committed/contradicted)
is whether the code lives up to it. A verified stage 2 is an honest low score;
a `contradicted` is the case only the tool catches (the owner self-reports the
intent as truth and the code proves otherwise). Both axes are stored on the evidence.

### 7. Two axes, one evaluation, opposite defaults

Maturity and mandate share the engine but are stored, defaulted, and rolled up
separately, because conflating them is a category error:

| | Maturity axis | Mandate axis |
|---|---|---|
| Output | stage 1–4 (gauge) | pass / fail (gate) |
| Undetermined default | **1 (Traditional)** | **unknown, never pass** |
| Consequence | temperature reading, no POA&M | fail / unproven → **POA&M** |

The mandate axis inherits the fail-closed posture already in tamp.findings:
"didn't run" ≠ "compliant". Its "where applicable" is the **same N/A disposition**
doing its job (no network surface → IPv6 N/A, not fail). The **mandate set is a
policy pack** (admin/policy-defined, like the policy templates and the offering
registry), each mandate = binary requirement + applicability rule + derivation rule
+ POA&M window, versioned as EOs/memos change (defined upstream by ADR 0011). The
supply-chain mandates in the same EO 14028 lineage stay with tamp-findings; tamp-ztt
owns the operational ones (encryption, MFA, IPv6). One shared POA&M model (§9).

### 8. The scoring math is a **shared contract**, pinned before roll-up

Roll-up walks the **graph, not the list** — a shared provider stuck at Initial is the
ceiling on every system inheriting it, and that fact dominates where investment buys
the most score. The aggregation math (per-function weights, per-pillar fold of the
cross-cutting capabilities, **min across inherited functions**, how N/A is excluded,
how committed-vs-verified is surfaced) is a single pinned `ZtmmScoringContract` in
the Domain — pure and deterministic like `GateEvaluator` and `PolicyLayerMerge` — not
a per-producer knob. If two producers folded cross-cutting differently, a combined
total would be summing numbers computed by different rules. The mandate axis rolls up
**separately**: a compliance count + a POA&M list, reported beside the gauge, never
averaged in.

### 9. One POA&M model across all three tools

`PoamItem` gains an additive **source discriminator** (`SourceKind` +
`SourceRef`) so a POA&M records what produced it — a finding, an operational-mandate
failure, or a ZT contradiction — without a new POA&M table. All three tools create
POA&Ms through the existing `PoamService`; the shared severity→window table
(`PolicyLayer.PoamDeadlineDays`) supplies the deadline. (Note: that table is defined
and merged today but not yet consumed when a POA&M is created — closing that gap is
in scope for this work, so mandate POA&Ms actually get their dated window.)

## Consequences

* tamp-ztt reads and writes one store; a system's ZT posture sits next to its build
  findings, its control coverage, and its POA&Ms, under one client/framework chain.
* The conservative floor, the provider cap, the attestation-not-proof stance, and the
  four-valued fail-closed mandate all fall directly out of mechanisms already built.
* Derive-on-read keeps the score from drifting from evidence, at the cost of a
  scoring pass on read — bounded because picks/edges are few and evidence is indexed
  by system.
* The `ZtSystem` node and the `EnterpriseOffering` registry are the two net-new
  hierarchies; everything else extends an existing entity or contract.

## Open questions (carried to the design doc / build)

The scoring-contract weights and fold rule; offering-definition granularity;
provider-registry ownership (who scores offerings, derived vs declared); the
enumerated acceptable attestation evidence types + expiry cadence; and the exact
`ConformancePayloadDto` additions — all specified in
`docs/design/tamp-ztt-eoprovenance-data-model.md`.
