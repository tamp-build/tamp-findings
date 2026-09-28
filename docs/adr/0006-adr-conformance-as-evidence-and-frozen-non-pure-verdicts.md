# ADR 0006: ADR-conformance as an evidence source, and freezing non-pure verdicts at the snapshot

* Status: Proposed
* Date: 2026-09-28
* Deciders: scott
* Tracking: TFND-174 (ADR-conformance as a CI/CD evidence source)

## Context and Problem Statement

We are adding **agentic ADR-conformance review** as a CI/CD evidence source. It compares a
governed repo's code and design against that repo's own Architecture Decision Records and
produces conformance verdicts — *does the code still honour what the team decided?* — which
flow into tamp.findings as findings, then get scored, gated, and attested like any other
evidence.

Three producer tools do the work, and they live **in CI / the governed repo, not in
tamp.findings**:

1. **Rule generation.** A frontier model extracts machine-checkable rules from each ADR into a
   committed `adr-rules.json` in the governed repo — versioned intent, a lockfile for
   architectural decisions. tamp.findings consumes the resulting verdicts; it never owns the
   rules.
2. **Rule examination.** Per PR, the code is checked against those rules. Deterministic rules run
   as pure predicates; semantic rules go to a mid-tier model followed by an adversarial verify
   pass.
3. **Reverse examination.** Detects decisions *in the code* that no ADR covers — change-control
   drift — and is advisory-only.

So tamp.findings' role here is narrow and, deliberately, boring: it is a **sink, gate, and
attestor for verdicts computed elsewhere.** It does not call a model. That framing is the whole
point of this ADR, because it is what keeps a non-deterministic input from contaminating a
determinism-as-compliance product.

The question this ADR answers: **how does a conformance verdict — some of them produced by a
non-deterministic LLM in CI — enter the four-valued / gating / attestation machinery without
breaking ADR 0001's determinism driver, and what, concretely, is new versus reused?**

### The collision this ADR has to resolve

ADR 0001 makes determinism a compliance requirement: *"An attestation signed in March must be
reproducible in September, or the signature attests to nothing."* An agentic conformance rule is
the opposite of that — **non-pure and non-deterministic.** The same rule against the same code
can return a differently-worded reason, or occasionally a different verdict, on a second run.

ADR 0001 already anticipated this class of rule and set the governing constraint (§ "Rules
governing the split"):

> *Workflow rules feeding scoring or gating must either be restricted to pure activities, or the
> attestation snapshot must store the verdict rather than expect to recompute it … The
> snapshot-stores-the-verdict option is the more honest of the two.*

This ADR is where that abstract constraint meets a concrete non-pure producer. It makes the
explicit choice ADR 0001 left open, and pins the reproducibility posture of LLM-backed
conformance so it is decided once, in writing, rather than improvised per rule.

## Decision Drivers

* **Determinism lives at the snapshot, not the rule.** A conformance verdict that cannot be
  re-derived byte-for-byte must still make an attestation reproducible. The only honest way is to
  store the verdict as evidence and never recompute it — the same way a SARIF ingest is trusted
  as *the record of what that scan found*, not something re-run to validate a signature.
* **Explainability is a compliance requirement (inherited from ADR 0001).** A conformance `Fail`
  that a human cannot check against the ADR text and the offending code line is not admissible.
* **Do not reinvent the machinery.** Verdict model, enforcement, delivery, and accepted-deviation
  shapes all exist. This ADR wires conformance onto them; it introduces no second gate engine, no
  second enforcement axis, no second waiver shape.
* **Ownership boundary.** The rules are the governed repo's intent, versioned in *its* git.
  tamp.findings consuming verdicts must not turn into tamp.findings owning policy it did not
  author.
* **A drift signal must not masquerade as a gate.** Reverse examination reports what no ADR
  covers; that is a prompt for change control, not grounds to block a build.
* **Waivers are only as trustworthy as the authorization model, which is unfinished.** A conformance
  deviation is an accepted architectural risk; accepting risk is an InfoSec act, and the role
  system that would bind that act is defined-but-unenforced today (ADR 0001, ADR 0002).

## Invariants

These hold for every change on this track. If a design choice breaks one, the choice is wrong.

1. **Non-pure verdicts are frozen at the snapshot.** A semantic/LLM conformance verdict is stored
   at evaluation time and **never recomputed** — not at read, not at re-attestation, not at
   audit. Determinism is preserved at the snapshot boundary.
2. **tamp.findings does not invoke a model to reach a verdict.** Conformance verdicts arrive as
   ingested findings, produced upstream in CI. The non-determinism is quarantined in the producer
   tools; the sink stays deterministic.
3. **Rules live in the governed repo.** `adr-rules.json` is versioned in that repo's git.
   tamp.findings holds verdicts and dispositions, not rules.
4. **Reverse examination never gates.** It is advisory-only, always, regardless of enforcement
   mode.
5. **A conformance `Fail` carries evidence, or it is `Unknown`.** A claimed violation that cannot
   quote both the ADR text and the code line is not a `Fail`.

## Decision

### 1. ADR-conformance is a registered evidence source, not a new subsystem

Conformance is modelled as a producer on the existing ingest path — the same shape as a scanner.
Its verdicts land as findings with their own category (a conformance `ScannerKind`-equivalent and
sub-category), carrying the ADR id and rule id they were evaluated against. Everything downstream
— scoring, gates, attestation, suppression, the explorer — treats them as findings, because they
are. No new read model, no new storage engine.

### 2. Reuse ADR 0001's four-valued verdict, with an explicit conformance mapping

The verdict is `Pass | Fail | Unknown | Error` — unchanged from ADR 0001. The producer maps its
result onto it:

| Producer result | Verdict | Rationale |
|---|---|---|
| Rule honoured | `Pass` | The decision still holds in the code. |
| Violated, **with evidence** | `Fail` | Quotes the ADR text and the code line. |
| Semantic check cannot decide, **or** a deterministic probe never ran | `Unknown` | "I cannot answer that" — the same class as ADR 0001's unscanned-gate. |
| Evaluation itself broke (model error, malformed rule, timeout) | `Error` | Alert an operator; not a policy result. |

**The adversarial verify pass is the `Fail`-versus-`Unknown` decider.** A mid-tier model claiming a
violation must survive an adversarial check that quotes *both* the ADR text and the specific code
line. A claimed violation that cannot produce that pairing degrades to `Unknown`, never `Fail`.
This is what stops an over-confident model from manufacturing a hard block out of a hallucinated
reading — a false `Fail` on a release decision is exactly the failure mode ADR 0001's four-valued
model exists to prevent, and `Unknown` is the honest home for "the model thinks so but cannot show
its work."

Both `Unknown` and `Fail` block in enforcing mode (§6); they are different problems with different
fixes — *"the code drifted from the decision"* versus *"the check could not reach a verdict"* —
and collapsing them is the same mistake ADR 0001 named.

### 3. Non-pure verdicts are frozen into the attestation snapshot; deterministic ones may recompute

This is the genuinely new decision, and it applies ADR 0001's non-pure-rule rule to a concrete
producer:

* A **semantic/LLM** conformance verdict is **stored at evaluation time and never recomputed.** The
  finding carries the verdict, the structured reason (§5), the quoted ADR text and code evidence,
  and the producer's identifiers (model, rule id, `adr-rules.json` version). The attestation
  snapshot freezes that record. Re-attesting or auditing reads the frozen verdict; it does not
  re-run a model. An LLM verdict is treated as evidence with provenance, exactly like a scan
  result — trusted because of *how it was produced and what it quotes*, not because it is
  reproducible.
* A **deterministic (predicate)** conformance verdict may be recomputed, because it is pure and
  will return the same answer. Nothing forbids storing it too; the point is only that the
  non-pure ones *must* be stored, because they cannot honestly be re-derived.

Determinism-as-compliance (ADR 0001) is therefore preserved **at the snapshot**, not at the rule.
The signature attests to the verdict that was recorded, which is a real and reproducible fact,
rather than to a computation that a later run might not reproduce.

### 4. Promoting a rule to the LLM path is an explicit, recorded conversion

Per ADR 0001 (*"escalation is a conversion, not a fallback"*): moving a conformance rule from the
deterministic predicate path to the semantic/LLM path is an explicit, recorded change in the
governed repo's `adr-rules.json`, not something that happens silently when a predicate proves
awkward to express. The conversion changes the rule's reproducibility profile — from
re-computable to frozen-at-snapshot — so it must be visible in the rules diff and reviewable, for
the same reason ADR 0001 forbids silent predicate-to-workflow promotion.

### 5. Structured reason is a required output (reuse)

Reuse ADR 0001's required-reason contract. A conformance `Fail` must carry the ADR quote plus the
code evidence; a `Pass` carries what it checked. A verdict that returns a bare boolean is
inadmissible on the compliance-relevant path, which is all of them here.

### 6. Enforcement reuses ADR 0004 — opt-in gates, locked floor, fail-closed

Conformance registers as **opt-in gate(s)** under the existing enabled-per-gate axis, and is
enforced through ADR 0004's `advisory < enforcing` machinery. No new enforcement mechanism:

* A **locked FedRAMP instance** pins conformance gates `enforcing` via the instance floor; no
  project can quietly downgrade them.
* A **commercial instance** leaves them admin-toggleable, most-specific-wins.
* In enforcing mode the fail-closed table applies unchanged: `Fail`, `Unknown`, and `Error` all
  return non-zero, and an unreachable conformance verdict is a block, never a pass.

Delivery reuses the **FindingsGate CLI** and its `--json` agent-consumable reasons (ADR 0004 § 3):
a remediation agent gets the ADR id, the rule id, the quote, and the code ref to fix-and-retry
against.

### 7. An accepted deviation is a VEX-style disposition, not a muted gate

An architectural decision to deviate — *"we knowingly break ADR 0007 here, and here is why"* —
reuses the Suppression/VEX shape: `CreatedByRole`, a required `Reason`, `ExpiresAt`, and the
**InfoSec-only `AcceptRisk` capability**. A deviation is an auditable disposition recorded
*against* a conformance `Fail`, the same way a VEX statement dispositions a vulnerability — the
`Fail` remains in the record, dated and attributed, rather than being silently turned green.
There is no "ignore this ADR" toggle; there is an accepted, expiring, attributed risk acceptance.

### 8. Reverse examination is advisory-only

Restated from the invariants as a decision because it is load-bearing: reverse examination — the
detection of decisions in code that no ADR covers — **never gates, in any enforcement mode.** It
is a change-control drift signal that surfaces as advisory findings and prompts someone to write
(or wave off) an ADR. Wiring it to a gate would let the *absence* of a written decision block a
build, which inverts the tool's purpose.

## Scope / Boundary — what this ADR does *not* decide

* **The rules themselves.** `adr-rules.json` — its schema, how the frontier model extracts it, how
  it is reviewed — lives in the **governed repo's git**, versioned as that team's intent. Out of
  scope here. tamp.findings consumes verdicts; it does not store or validate rules.
* **Shared-contract decisions.** The ingest schema, the `BuildEvent` shape, the provenance
  envelope, and `WorkerId` semantics belong to **core tamp** (the emission contract; ADR 0018 is
  owned upstream). Conformance findings ride those contracts unchanged. Referenced, not
  redecided.
* **Cross-repo conflict detection.** A governed repo's ADR can contradict a core-contract ADR. Catching
  that requires the checker to load **both** the local ADR index and the core-contract ADR index
  and reason across them. That is a **requirement on the producer tooling**, noted here so it is
  not lost, and explicitly out of scope for this ADR (which decides the sink, not the checker).
* **The producer tools' internals.** Model choice, prompt design, the adversarial-verify
  implementation, and rule-generation quality are CI-side concerns. This ADR decides only the
  contract at which their output enters tamp.findings and how it is treated once inside.

## Consequences

**Positive**

* Architectural intent becomes a first-class, gated, attestable evidence class — the same rigour
  the product already applies to CVEs, SAST, and coverage, now applied to *"did we build what we
  said we would."*
* No new machinery. Conformance is findings (ingest), verdicts (ADR 0001), gates (ADR 0004), and
  dispositions (VEX/Suppression). The blast radius is a new category and a mapping, not a new
  subsystem.
* Determinism-as-compliance survives contact with an LLM: the non-determinism is quarantined in
  CI, its output is frozen as evidence, and the sink stays reproducible. The attestation attests
  to a recorded fact.
* The adversarial-verify → `Unknown` rule makes a hallucinated violation a non-answer rather than
  a false block, which is the difference between a tool a release engineer trusts and one they
  learn to override.

**Negative / accepted costs**

* **A frozen verdict cannot be improved retroactively.** If a later, better model would have judged
  a build differently, the attested snapshot still holds the verdict of record. That is the
  correct trade — an attestation must mean what it meant when it was signed — but it means
  conformance history carries the judgement of the model that ran, warts and all.
* **A new evidence category is new noise until tuned.** Conformance `Unknown`/`Fail` volume during
  the advisory-preview period will be real, and rules will need iteration in the governed repo.
  ADR 0004's advisory→enforcing rollout is the mitigation: watch what *would* block for a sprint
  before flipping.
* **Trust in the producer is now part of the trust chain.** A verdict is only as good as the model
  and the rules that produced it. The required evidence (ADR quote + code line) and the
  adversarial pass are the guards, but this ADR is honest that it moves a model into the
  compliance path — quarantined, evidenced, and frozen, but present.

**Neutral**

* Kept as **one ADR, not two.** A clean seam exists — "conformance as a registered evidence source"
  versus "reproducibility of non-pure verdicts" — but the reproducibility decision (§3–4) is the
  load-bearing new content, and the general principle it rests on is already decided in ADR 0001
  § "Rules governing the split." Splitting would leave a hollow wiring ADR and a context-less
  reproducibility ADR that only means anything alongside it. If a *second* non-pure producer ever
  appears, the general reproducibility posture is worth lifting into its own ADR then; today it
  would be premature.

## Notes

* **Back-references.** This ADR builds directly on **[ADR 0001](0001-rule-evaluation-predicates-and-workflows.md)**
  (the four-valued verdict, the required structured reason, and the non-pure-rule rule it applies)
  and **[ADR 0004](0004-gate-enforcement-modes-and-the-cli-gate.md)** (advisory/enforcing modes,
  the locked floor, the fail-closed table, the FindingsGate CLI and `--json`). It changes neither;
  it registers a new producer onto both.
* **Authorization boundary.** Accepted deviations route through the InfoSec-only `AcceptRisk`
  capability and the audited Application services, per
  **[ADR 0002](0002-blazor-hosting-and-the-authorization-boundary.md)**'s one-authorization-boundary
  intent. That boundary is not yet fully enforced — `ProjectRole` is defined and recorded but
  `SuppressionsEndpoints` still trusts an `X-Author-Role` header (ADR 0001 Notes; ADR 0002). A
  conformance deviation waiver is exactly as trustworthy as that model, so **enforcement of
  conformance waivers is sequenced *behind* the authorization work, not ahead of it.** Shipping
  waiver enforcement first would attest to an acceptance whose author cannot be verified.
* **The rules are a git artifact.** `adr-rules.json` is the versioned lockfile for a repo's
  architectural intent, and it lives in that repo — not in this database. tamp.findings records
  what was checked and how it came out; the governed repo records what the rules were.
* **Nothing here is built yet.** This ADR decides the posture and the contract, not an
  implementation. The producer tools, the conformance category, and the gate registration are
  future work; the value of deciding now is that the reproducibility choice is made before the
  first LLM verdict is ever attested, when it is cheap, rather than after, when it is a migration.
