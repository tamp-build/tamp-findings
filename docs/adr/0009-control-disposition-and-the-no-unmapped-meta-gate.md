# ADR 0009: Control disposition and the no-unmapped meta-gate

* Status: Proposed
* Date: 2026-09-28
* Deciders: scott
* Tracking: TFND-185 (control-disposition model + no-unmapped meta-gate), under epic TFND-181

## Context and Problem Statement

The gates answer "is this build clean against the checks we run?" (ADR 0001, four-valued
verdicts). The capability intersection (TFND-184) stops a check that a component cannot
produce from reading as a false pass. But neither answers the question a compliance reviewer
actually asks:

> Of the controls this system is *held to*, which ones are we actually covering — and which
> have we simply not thought about?

A green gate rail can sit above a framework where 300 of 370 in-scope controls have **no
mapping at all** to any gate, inheritance claim, or applicability justification. The dashboard
looks clean because it only measures the gates that exist, not the controls that should. That
gap — silent, unmeasured non-coverage — is the compliance analogue of the ADR 0001 false pass:
absence of a decision rendered as if it were a passing one.

We already have the denominator. The shipped OSCAL catalog (`ControlCatalog`, 1196 NIST
800-53 Rev5 controls with real baseline membership) plus a project's assigned framework give
the exact set of **in-scope controls** (`ComplianceProfileQuery` already computes it). What is
missing is a per-control *decision* and a gate that fails when any decision is missing.

## Decision

Introduce a **control-disposition model** and a **`no-unmapped` meta-gate**.

### 1. Every in-scope control gets exactly one disposition

For each control in the project's baseline, the effective policy resolves to one of four
dispositions:

| Disposition | Meaning | Source |
|---|---|---|
| **Gated** | An automated gate produces evidence for this control. | A template `assertion` mapping the control to one or more `GateKeys`. |
| **Inherited** | The control is satisfied by inheritance (a hosting provider, an authorizing boundary). Not our evidence to produce. | A template `assertion` of kind `Inherited`, with `InheritedFrom` + justification. |
| **NotApplicable** | The control does not apply — either asserted N/A with justification, **or** every gate mapping it needs a capability this build's components cannot produce (TFND-184). | An `assertion` of kind `NotApplicable`, **or** derived from the capability intersection over a `Gated` assertion. |
| **Unmapped** | No assertion covers this control. We have not decided how it is met. | The **absence** of any assertion. This is the gap the meta-gate closes. |

Disposition is a pure function of `in-scope controls ∩ effective assertions ∩ component
capability` — the same three-way intersection the epic is built on. It lives in a pure domain
resolver (`ControlDispositionResolver`), deterministic and reproducible like `GateEvaluator`
and `PolicyLayerMerge`, so a disposition recorded against a build can be recomputed later.

### 2. The per-template `assertions[]` schema (§8)

Assertions hang off `PolicyLayer` (the harden-only overlay, ADR 0007), so they merge through
the same template → client → project stack and inherit its provenance. `PolicyLayer.SchemaVersion`
bumps to `2`; the field is additive jsonb, so stored layers without it deserialize to an empty
set.

```jsonc
// PolicyLayer.Assertions: ControlAssertion[]
{
  "kind": "Gated" | "Inherited" | "NotApplicable",
  "controlIds": ["RA-5", "SI-2"],   // OSCAL control ids
  "gates": ["kevExposure", "criticalCves"], // Gated only — the GateKeys that cover these controls
  "justification": "…",             // required for Inherited / NotApplicable
  "inheritedFrom": "AWS GovCloud (IaaS)" // Inherited only
}
```

**Merge (harden-only, strictest-wins):** assertions merge per control id. The strictest kind
wins — `Gated` (we actively test) > `Inherited` (someone else attests) > `NotApplicable` (no
one need). Gate lists union. A lower layer can strengthen a control's disposition or add a new
one; it cannot weaken what an upper layer asserted. This is the same discipline as every other
`PolicyLayer` field.

### 3. The `no-unmapped` meta-gate

A new well-known gate `noUnmapped`. Unlike every other gate it does not read a scanner count;
it reads the disposition set:

* **Pass** — every in-scope control has a disposition (`Unmapped == 0`). The mapping is complete.
* **Fail** — one or more in-scope controls are `Unmapped`. Observed: "K of N in-scope controls unmapped".
* **Unknown** — coverage could not be computed: no framework assigned, or no current catalog.
  A gate that claims to cover controls but has no controls to check is a misconfiguration, not
  a clean build — the same "absent is not clean" rule as the scanner gates.

It **gates the coverage of the mapping itself**, not any one control. It is the check that the
matrix is filled in.

**Rollout — advisory while the matrix fills, strict once clean.** A freshly-assigned framework
starts almost entirely `Unmapped`, so `noUnmapped` will `Fail` loudly on day one — which is the
correct signal ("you have not mapped anything yet"), not a defect. Whether that failure
*blocks* is the existing enforcement lever (ADR 0004): the meta-gate is seeded **enabled on the
federal templates** (FedRAMP Low/Moderate/High, GovRAMP Core) and left off Tamp Standard, and a
project runs Advisory until its matrix is clean, at which point ops flips the instance/project
to Enforcing and the meta-gate begins to block regressions. No new advisory mechanism is
introduced; the four-valued verdict and the enforcement mode already express exactly this.

### 4. A shipped starter assertion set

The federal templates ship a small, defensible starter mapping for the automated technical
controls the six scanner classes genuinely cover (e.g. `RA-5`/`SI-2` → CVE+KEV+SBOM gates,
`SA-11`/`SA-15` → SAST+coverage, `IA-5` → verified-secrets, `CM-8`/`SR-3` → SBOM, `SC`/`SI-10`
web controls → DAST — which then resolve to N/A on a code-package via the capability
intersection). The remainder ship `Unmapped` on purpose: the meta-gate then reports the real,
honest coverage gap rather than a fabricated 100%. Filling the matrix is ongoing compliance
work, not a code change.

## Consequences

* The dashboard and the compliance profile can now show coverage as four honest numbers
  (gated / inherited / N/A / unmapped) instead of a gate rail that measures only what exists.
* The disposition is derived, never stored per-control, so it cannot drift from the catalog or
  the templates — same guarantee as the in-scope control set.
* `GateEvaluator.RequiredCapability` becomes the single shared gate→capability map, consumed by
  both the intersection rule (TFND-184) and the disposition resolver.
* The starter mapping is deliberately incomplete; the meta-gate makes that incompleteness
  visible and actionable rather than hidden.

## Alternatives considered

* **Store a disposition column per control per project.** Rejected — it would drift from the
  catalog and the templates the moment either changed, the exact failure the computed in-scope
  set was designed to avoid.
* **Evaluate the meta-gate outside the gate model.** Rejected — it belongs in the same
  four-valued rail so it inherits enforcement mode, provenance, and the UI marks for free.
* **A separate per-gate "advisory" flag for the meta-gate.** Rejected — the enforcement mode
  (ADR 0004) already expresses advisory-vs-blocking; a second mechanism would be a parallel
  lever to keep in sync.
