# ADR 0005: Removing Elsa — scheduled work as hosted workers

* Status: Accepted
* Date: 2026-09-26
* Deciders: scott
* Tracking: TFND
* Supersedes: the "Elsa for complexity" half of [ADR 0001](0001-rule-evaluation-predicates-and-workflows.md)

## Context and Problem Statement

[ADR 0001](0001-rule-evaluation-predicates-and-workflows.md) adopted Elsa Workflows 3.x for two jobs: the **escalation path** for rules too complex for a predicate, and the orchestration substrate for **approvals, alerting and attestation routing**. It also named the real cost up front:

> **Elsa Studio is a Blazor Razor Class Library with no React build.** The rule-authoring UI is therefore a second frontend, an iframe, or something built against Elsa's API. This is the real cost of the decision and it lands during the UI redesign.

That cost has now landed, and the bet did not pay out. Concretely, as the code stands today:

* **Nothing dispatches a workflow.** Elsa shipped behind a `Workflows:Enabled` flag that is **off by default**, and no code path calls `IWorkflowRunner` or `IWorkflowDispatcher` in anger. The engine is registered and idle.
* **The escalation path never materialised.** Every rule in the product is a predicate. The four-valued verdict and the predicate model from ADR 0001 carry the whole load; no rule was ever promoted to a workflow, and the "convert a predicate to a workflow" flow was never built.
* **Approvals never depended on Elsa.** `PendingApproval` rows are durable state the screens read directly (per the [ADR 0002](0002-blazor-hosting-and-the-authorization-boundary.md) boundary). `ApprovalService` was deliberately written to work with the engine switched off. The `WorkflowInstanceId` column meant to link a row to its orchestrating instance was never populated.
* **Exactly one workflow was intended to run live:** `PoamDueReminderWorkflow`, an Elsa Timer that swept POA&M items due within a week and recorded a reminder. That is a scheduled job, not orchestration.
* **The designer is the daily cost.** Elsa Studio is slow to load and awkward to author in — the second-frontend tax ADR 0001 predicted, paid every time anyone touches it, for a feature set the product does not use.

So the question: **do we keep a workflow engine — with its designer, its schema, its second frontend, and its idle runtime cost — for one timer sweep and a set of unrealised futures?**

## Decision Drivers

* **Pay for what runs.** A dependency that is off by default and dispatched by nothing is pure carrying cost — schema, packages, a Blazor RCL, and a mental model the next reader has to load.
* **One pattern for scheduled work.** The repo already runs recurring jobs as hosted `BackgroundService` workers (retention, suppression expiry, KEV feed sync, check publish). A timer that also wants to be a hosted worker is the pattern already in the codebase, not a new one.
* **Approvals are state, not process.** A pending decision that vanished when a worker was down would be worse than no approval flow at all. Modelling it as a durable row — which is what we already do — is the more honest design and needs no orchestrator.
* **Don't strand the escape hatch.** ADR 0001 kept CEL as a future escape hatch for complex rules. Removing Elsa must not foreclose that; it should make the eventual complex-rule story cleaner, not harder.

## Decision

**Remove Elsa entirely. Scheduled and recurring work runs as hosted `BackgroundService` workers; approvals stay durable database rows read directly by the application layer.**

Removed:

* The `Tamp.Findings.Workflows` project (workflow definitions, the `WorkflowBridge`, and the service-collection wiring).
* The Elsa package set — `Elsa`, `Elsa.Persistence.EFCore.PostgreSql`, `Elsa.Scheduling` (3.7.1).
* The `Workflows:Enabled` configuration switch and its registration block in `Program.cs`.
* The `PendingApproval.WorkflowInstanceId` column (migration `Tfnd_DropElsa_WorkflowInstanceId`). It linked a row to an Elsa instance and was never populated.

Retained, re-homed:

* The one live workflow — the POA&M due-date reminder — is now `PoamReminderService` (Application) driven by `PoamReminderWorker` (a daily hosted worker, staggered off the other startup sweeps). Same behaviour: remind on items due within the last week before their committed date, not on items already past due.

Unchanged:

* The four-valued verdict (`Pass`/`Fail`/`Unknown`/`Error`) and the predicate model from ADR 0001 stand. Those were never Elsa; predicates are the whole rule engine and always were.
* Approvals: `PendingApproval` + `ApprovalService`, already engine-independent.

### The complex-rule escalation path, if it is ever needed

ADR 0001's premise was that some rule would one day need multi-step logic, an external lookup, or a human in the loop, and that Elsa would be there for it. That day never came, and predicates covered every real rule. If it does come, the answer is **CEL** — the sandboxed, non-Turing-complete, config-storable escape hatch ADR 0001 deliberately kept available — not the reintroduction of a workflow engine. A rule is a function returning a verdict; that contract is unchanged and does not need an orchestrator behind it.

Human-in-the-loop steps (risk-acceptance sign-off, VEX publication, attestation sign-off) are already modelled as `PendingApproval` states with explicit capability checks. That is the routing layer. It needs durable state and an authorization model, both of which exist — it never needed a process engine.

## Consequences

**Positive**

* The second frontend is gone. No Elsa Studio, no iframe, no RCL to host, no slow designer. The "real cost" ADR 0001 flagged is retired rather than paid.
* One pattern for scheduled work. Every recurring job in the product is now a hosted `BackgroundService` with the same lifecycle, logging and startup-stagger discipline — one thing to understand, one place to add the next sweep.
* Smaller dependency surface and schema: three fewer packages, one fewer project, one fewer column, and no idle engine registered at startup.
* Nothing behavioural is lost, because nothing behavioural was running: the only live job kept its behaviour under a simpler host.

**Negative / accepted costs**

* We give up Elsa's durable, suspendable, timeout-aware orchestration — persistence of a half-finished multi-step process across restarts. Accepted: nothing used it, and approvals are deliberately modelled as state, not as a suspended process.
* If a genuine long-running orchestration need appears later (not a scheduled sweep, not an approval state — a real multi-step process with waits), it will have to be designed then. We are betting that need is unlikely and that a hosted worker plus durable state covers the realistic cases. ADR 0001's benchmarks and reasoning remain on the record if that bet has to be revisited.

**Neutral**

* CEL remains the documented escape hatch for complex rules. Removing Elsa does not touch that; it removes the *other* thing ADR 0001 pointed complex rules at, leaving one clear answer instead of two.

## Notes

* ADR 0001 stays "Accepted" for its core decision (four-valued verdicts, predicates by default). Only its "Elsa for complexity" arm and the "Elsa arrives once and serves rules, routing, approvals and alerting" consequence are superseded here. A pointer to this ADR is added at the top of ADR 0001.
* The approval-expiry, gate-failure-alert and POA&M-verifying workflows sketched during the Elsa period were never dispatched and are removed with the rest. If any is wanted, it returns as a hosted worker or an approval state, not as a workflow definition.
