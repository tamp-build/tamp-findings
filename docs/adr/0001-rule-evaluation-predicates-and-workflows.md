# ADR 0001: Rule evaluation — four-valued verdicts, predicates by default, Elsa for complexity

* Status: Accepted
* Date: 2026-08-22
* Deciders: scott
* Tracking: TFND (ticket to follow)

## Context and Problem Statement

Policy in tamp.findings is currently expressed through four unrelated mechanisms, none of them composable:

| Mechanism | What it can express |
|---|---|
| Risk categories | A closed set of keys, hardcoded in a `switch` in `RiskScorer`; `enabled` / `max` / `weights` only |
| `ScannerOverrides` | A severity **ceiling** per scanner — nothing else |
| Acceptance gates | A closed set of keys, hardcoded in a `switch` in `GateEvaluator`; every gate is `observed <= threshold` |
| Suppressions | Four fixed scopes matched on ruleId / path / component |

Adding a gate, a risk category, or any rule keyed on an attribute outside that list requires a code change and a deploy. Compound conditions are inexpressible: there is no way to say *"critical **and** KEV-listed **and** not covered by a VEX statement **and** older than seven days"*. Escalation is impossible — `ScannerOverrides` caps severity but cannot raise it, so *"anything CWE-89 is Critical regardless of what the scanner said"* cannot be written.

At the same time the product is moving toward approvals, alerting, and multi-party attestation signing. Those need routing, durable state, timeouts and human-in-the-loop suspension — a different problem from evaluating a predicate.

The question this ADR answers: **what is a rule, what evaluates it, and how do the simple and complex cases coexist without becoming two products?**

### The bug that motivated the shape

A gate today returns pass or fail. Nothing else. A probe against `GateEvaluator` confirmed the consequence:

> A project that has never been scanned **passes every severity gate.** `criticalSast`, `highSast`, `criticalDast`, `highDast` — all green, `Failed = 0`.

The counts are zero because no scanner ran, and `0 <= 0` is a pass. `RanSast` / `RanDast` exist on `RiskInputs`, and the *scorer* consults them via `missingScanners`, but the **gates never do**.

This is the same defect class as SSDF `PW.8.1` answering "Yes" off a passing unit-test suite (fixed under TFND-38). A gate that passes because nothing ran is not a green build — it is an unanswered question wearing a green badge, and on a release decision that is worse than a gate that fires wrongly.

Two-valued logic has no way to say *"I cannot answer that."*

## Decision Drivers

* **Explainability is a compliance requirement, not a nicety.** "Why was this finding downgraded?" and "why did this build pass?" must have stable, reviewable answers years later.
* **Determinism.** An attestation signed in March must be reproducible in September, or the signature attests to nothing.
* **Authorable by admins, not only engineers.** Rules that only a .NET developer can change put policy back on the deploy cycle — the exact problem this category of tooling exists to solve.
* **No new code-execution surface.** This is a product that scans for code-execution surfaces.
* **Volume asymmetry is real.** A large SAST ingest is ~5,000 findings; gates run ~13 times per build. Those are five orders of magnitude apart and cannot share an execution strategy naively.
* **One audit trail.** Four mechanisms today means four config shapes and four half-audit-trails.

## Considered Options

1. **Extend the existing config schema.** More knobs, still a closed set. Cheap; does not address compound conditions or extensibility.
2. **NRules** (Rete, rules authored in C#). Rejected: rules only a .NET-comfortable engineer can safely change, and changes require a deploy.
3. **OPA / Rego.** The industry standard for policy-as-code and genuinely the most powerful option. Rejected: a Go sidecar or WASM, explicitly *"difficult to safely embed"*, and Rego's learning curve needs training. Too much operational weight for a self-hosted product.
4. **Microsoft RulesEngine.** JSON rules with dynamic lambda expressions — closest general-purpose fit. Rejected: compiles expressions at runtime via Dynamic LINQ (a code-execution surface), and returns a boolean, so explainability is still ours to build.
5. **CEL** (`cel.net` on NuGet). Sandboxed, non-Turing-complete, guaranteed to terminate, config-storable. Kubernetes uses it for `ValidatingAdmissionPolicy` — the same "admin-authored policy in config" shape. Retained as a future escape hatch rather than adopted now.
6. **Elsa Workflows for everything.** Already wanted for routing and approvals. Measured below.
7. **Hand-rolled predicates for everything.** Fast, deterministic, explainable — but cannot express multi-step logic or anything involving a human.

## Decision

**A rule is a function returning a four-valued verdict, and the engine that evaluates it is an implementation detail of that rule.**

```
Evaluate(context) -> Pass | Fail | Unknown | Error   (+ structured reason)
```

| Verdict | Meaning | Release decision |
|---|---|---|
| `Pass` | Evaluated; within threshold | ship |
| `Fail` | Evaluated; exceeded | block |
| `Unknown` | **Could not be evaluated** — e.g. the scanner never ran | block, different remedy |
| `Error` | Evaluation itself broke | block, alert an operator |

`Unknown` and `Fail` both block, but they are different problems with different fixes — *"go fix the finding"* versus *"your pipeline is not running the scanner."* Collapsing them is precisely the bug above.

This is not an invention: it is [CEL's semantics](https://opensource.googleblog.com/2024/06/common-expressions-for-portable-policy.html), which renders `true`, `false`, `error` or `unknown` and defines commutative operators over all four. Adopting the same model keeps CEL viable as a later escape hatch.

Two implementations sit behind that one contract:

**Predicates — the default.** A closed declarative model over the finding vocabulary (scanner, ruleId, severity, subCategory, path/URL, tags, CWE, age, status, component). Serializable, diffable, UI-authorable, trivially deterministic, structurally explainable. This covers the large majority of real rules.

**Elsa workflows — the escalation.** For rules needing multi-step logic, external lookups, or a human. Elsa is already required for approvals, alerting and attestation routing, so it is not a new dependency.

### Why Elsa is viable for rules, and its one constraint

`IWorkflowRunner` executes workflows **in-process, synchronously, without persistence** — distinct from `IWorkflowDispatcher`, which is the background-queue path all the long-running documentation describes.

Benchmarked (Elsa 3.7.1, Release, trivial predicate workflow, warmed):

```
  100 runs     77 ms    0.779 ms/run   ~1,283/sec
1,000 runs    871 ms    0.872 ms/run   ~1,147/sec
5,000 runs  4,060 ms    0.812 ms/run   ~1,231/sec
```

Flat across all three sizes — steady state, not warm-up. **~0.8 ms per invocation.**

Against real workloads:

| Workload | Invocations | Cost | Verdict |
|---|---|---|---|
| Gates per build | ~13 | ~10 ms | free |
| DAST ingest (~40 findings × 10 rules) | 400 | ~0.3 s | fine |
| **SAST ingest, per finding × per rule** | **50,000** | **~40 s** | **not viable** |

0.8 ms is high for a workflow performing one integer comparison — that is engine overhead, roughly a thousand times a hand-rolled predicate. Hence:

> **Constraint: rule workflows evaluate a finding *set*, not a finding.**

Ten rules over 5,000 findings becomes ten invocations (~8 ms) rather than 50,000 (~40 s). This is better rule design regardless: set granularity is what makes *"more than five criticals"*, *"any critical that is also KEV-listed"* and *"high findings older than 30 days"* expressible at all.

### Rules governing the split

* **Predicate is the default in the authoring UI.** Whichever option is presented first is what people build. "Simple rule" foregrounded, "advanced" as a deliberate escalation.
* **Escalation is a conversion, not a fallback.** Promoting a predicate to a workflow is an explicit, recorded action. It changes the rule's performance profile, reproducibility and auditability; silent promotion would make those unpredictable per rule.
* **A structured reason is a required output on both paths.** A predicate yields *"critical=3 > threshold=0"* for free; a workflow will happily return `false` and nothing else. If the complex path degrades the audit trail, it becomes the path nobody may use for compliance-relevant rules — which is most of them.
* **Workflow rules feeding scoring or gating must either be restricted to pure activities, or the attestation snapshot must store the verdict rather than expect to recompute it.** A rule that calls an external API cannot be re-evaluated later to prove the attestation was sound. The snapshot-stores-the-verdict option is the more honest of the two and fits the attestation-snapshot design.

## Consequences

**Positive**

* The unscanned-gate bug becomes expressible and therefore fixable.
* `ScannerOverrides`, suppressions, gates and risk categories collapse toward one model with one audit envelope. `Suppression` already carries the right shape to generalise from — `CreatedByUserId`, `CreatedByRole`, required `Reason`, `ExpiresAt`.
* Severity escalation becomes possible, not only capping.
* Rules-as-data means the same policy is inspectable from the UI, the CLI and MCP. Rules-as-code would mean only the UI ever sees them.
* Elsa arrives once and serves rules, routing, approvals and alerting.

**Negative / accepted costs**

* **Elsa Studio is a Blazor Razor Class Library with no React build.** The rule-authoring UI is therefore a second frontend, an iframe, or something built against Elsa's API. This is the real cost of the decision and it lands during the UI redesign.
* Two execution paths mean two performance and determinism profiles to reason about.
* The benchmark is a floor: the simplest workflow that still makes a decision. Realistic rules will cost more and should be re-measured once one exists.

**Neutral**

* CEL is deliberately not adopted now, but the four-valued contract keeps it available as an escape hatch without rework.

## Notes

* The unscanned-gate defect is real and present in `GateEvaluator` today; it is not hypothetical and should be tracked separately from this ADR so it can be fixed before the rules work lands.
* Approvals and segregation of duties depend on an authorisation model that does not yet exist. `ProjectRole` (`InfoSecOfficer` / `LeadDev` / `Architect`) is defined and recorded on `Suppression`, but is never enforced — `SuppressionsEndpoints` reads the role from an `X-Author-Role` HTTP header and trusts it. Elsa consumes an authorisation model; it does not provide one. Sequencing is therefore **roles → decision record → Elsa routing → e-sign**.
* Benchmark harness was a throwaway console project and is not retained; the figures above are reproducible from the description.
