# ADR 0007: Three-layer harden-only policy (template → client → project)

* Status: Accepted
* Date: 2026-09-28
* Deciders: scott
* Tracking: TFND-179 (three-layer harden-only policy model)

## Context and Problem Statement

A policy in tamp.findings decides **what blocks a build**: an enforcement mode, a set of
required scanners, the acceptance gates and their thresholds, the denied licences, and the
POA&M remediation deadlines. Today that policy is set flat, per project, and resolved by a
**pick-one** lookup — `Project → Client → instance default` — where the most specific setting
that exists wins *whole* (`GateDecisionService.ForLatestAsync`). There is no merging: a client
that mandates a gate cannot stop a project from simply choosing a policy that omits it.

That is the wrong shape for the customers this product is for. A platform or compliance team
owns a **baseline** (FedRAMP Moderate, a civic baseline, an internal standard). A client
account layers **its** obligations on top. A project team should be able to be *stricter* than
both — never looser. The prior override model lets a project silently undercut the baseline it
is supposed to inherit, and an assessor reading the effective policy cannot see which authority
each rule came from.

The question this ADR answers: **how do template, client and project policy compose so that the
effective policy is always the strictest across the three, every rule carries the layer that
imposed it, and no lower layer can weaken an upper one — without breaking the existing scoring,
gating and attestation machinery or requiring a data migration of every project's current
policy?**

## Decision

### 1. Three layers, harden-only

Policy is composed of three ordered layers:

```
Template (versioned library) → Client (picks a template + hardening) → Project (hardening)
```

Each lower layer may only **add** a rule or **tighten** a threshold. The **effective value at
every field is the strictest across the layers that set it**, and the merge records **which
layer supplied it** (provenance). This is `PolicyLayerMerge.Resolve`, a pure, deterministic
function in the Domain — the same discipline as `EnforcementResolution` and `GateEvaluator`, so
an effective policy recorded against a build can be reproduced from the layers later.

Per field:

| Field | Merge rule |
|---|---|
| Enforcement mode | strictest wins (`Enforcing` > `Advisory`) |
| Required scanners | union (a lower layer adds, never removes) |
| Gates — enabled | logical OR |
| Gates — threshold | minimum of the provided values (lower is stricter); an unset threshold loses to any real value |
| Denied licences | union |
| POA&M deadlines (per severity) | minimum days (a shorter deadline is stricter) |

The **write side** enforces harden-only (a project cannot save a value looser than what it
inherits — the editor disables the affordance and the service validates it). The **merge side**
only computes the strictest state; it never needs to reject anything, which is what keeps it
pure.

### 2. What a layer carries, and what it deliberately does not

A layer (`PolicyLayer`, stored as jsonb) carries the **hardenable, blocking** fields above. It
does **not** carry risk-scoring weights, category caps, or score bands. Those stay in
`RiskPolicyConfig` and its v2 editor for now, because "harden-only" is not yet well-defined for
a scoring weight (raising a weight is stricter; changing a band is not obviously either). When
weights do fold into templates, the rule will be "harden = raise a weight or cap only"; until
then a template simply *links* a `RiskPolicy` for scoring and layers the blocking policy on top.
This split keeps this ADR's guarantee — strictest-wins, no loosening — provable over exactly the
fields where it is meaningful.

### 3. Merge into the existing evaluation shapes, do not re-home data

The layers merge, **at resolution time**, into the shapes the evaluators already consume —
`ProjectGatesConfig` for `GateEvaluator`, the licence deny-list in `RiskPolicyConfig` for the
scorer, `EnforcementMode` for `EnforcementResolution`. Nothing about `RiskScorer`,
`GateEvaluator` or `RiskInputsBuilder` changes. A project with **no** overlay layers and no
template resolves to exactly its current flat config, so the change is **backward compatible**
and needs no migration of existing policy data — only the additive new columns/table for the
overlays and the template library.

### 4. Loosening needs InfoSec approval

Hardening flows straight through: a client or project tightening its own layer applies on the
next evaluation with no approval, written to the audit log. But two actions can *weaken* what
others inherit, and both route through the existing `PendingApproval` / `IApprovalEffect`
machinery requiring the InfoSec **`AcceptRisk`** capability (ADR 0002's single authorization
boundary; ADR 0004 §5 for enforcement):

* **Loosening a template** — it lowers the floor for every client and project under it. Clients
  and projects that had hardened past the loosened value keep their stricter setting.
* **Switching a client's template** — it swaps the whole inherited baseline.

Enforcement mode continues to obey ADR 0004's **locked instance floor**: the strictest-wins
result of the three layers is still clamped up to the instance floor when the instance is
locked.

## Consequences

* The effective policy is now a **merge with provenance**, not a pick-one — every gate,
  scanner, licence and deadline on the policy screen shows `🔒 inherited from <layer>`,
  `↓ hardened here`, or `+ added here`, and an assessor can trace each rule to the authority
  that imposed it.
* A project can be stricter than its client and template but **never looser** — the guarantee the
  prior override model could not make.
* Scoring weights and bands are still single-layer (RiskPolicy). That is a known, deliberate gap
  recorded here, not an oversight; folding them in is future work under "harden = raise only".
* The domain gained 16 layerable gate keys (the ones that exist today). The v3 prototype shows
  18 — it adds `missingScanners` and `adrConformance`, which are not gate keys yet
  (`adrConformance` waits on the phase-7 conformance ingest). They are out of scope here.
* Because the merge is pure and the layers are stored, an effective policy can be recomputed for
  any historical build from its layers — the same reproducibility ADR 0001 requires of verdicts.
