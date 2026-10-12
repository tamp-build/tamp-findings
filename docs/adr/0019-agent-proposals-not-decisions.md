# ADR 0019: An agent may propose; only a person decides

* Status: Proposed
* Date: 2026-10-12
* Deciders: scott
* Tracking: TFND-240 (under epic TFND-234, the MCP agent surface)
* Builds on: [0002](0002-blazor-hosting-and-the-authorization-boundary.md) (one authorization boundary), [0012](0012-findings-as-the-authoritative-conformance-rules-store.md) (review-gating), [0015](0015-project-authored-control-dispositions.md) §5 (review-gated downgrades)
* Related: [0004](0004-gate-enforcement-modes-and-the-cli-gate.md) (enforcement modes)

## Context and Problem Statement

The MCP agent surface (TFND-12, F11) is read-only, and the reason is written into
`AgentReadService` itself: *"an agent that can file a suppression can retire a finding it was
asked to fix, and the whole value of this product is that the evidence is not negotiable."* That
reasoning is correct and this ADR does not propose weakening it.

What has changed is who reads the findings. tamp.findings is being stood up for a tenant whose
findings are read and acted on by agents rather than only by people — the engagement itself asks
for findings and nothing more, so this is about what a developer's own agent can do with the
surface, not about a remediation process anyone has contracted for. Read-only has a cost that was
invisible while agents were a convenience:

* **The work product does not land on the record.** An agent investigates a finding, establishes
  that the vulnerable code path is unreachable, and writes that reasoning into a chat transcript.
  The next person to look at the finding sees an untouched open finding. The analysis is not
  evidence, because evidence is a row.
* **There is no way to ask.** An agent that has concluded a CVE does not reach this codebase cannot
  draft the VEX statement that says so for a human to approve. It can only tell its operator, who
  retypes it. The product has an approval mechanism (`IApprovalEffect`, durable approval rows,
  TFND-117) and the agent cannot reach the *request* end of it.
* **Attribution already exists and is unused.** TFND-165 persists an ingest actor precisely so a
  row can say which worker produced it. An agent token resolves to an identity with a name and a
  scope. Everything needed to record "this agent asked for this, at this time, with this argument"
  is built; nothing writes it.

The question is therefore not "should agents be able to change evidence" — they should not — but
**whether the product should distinguish asking from deciding, and let an agent do the first.**

Two framings were considered and rejected before the one below.

**"Give the agent a role with write capabilities and let the matrix handle it."** The capability
matrix is about *what a seat may do*, and it is already correct. The problem is that a credential
held by a non-person is a different kind of thing from a seat, and no row in the matrix expresses
"may draft but never commit". `LeadDev`'s conditional `AuthorVex` (draft only, InfoSec publishes)
is the closest existing shape, and notably it is a *condition on a capability*, not a role. That is
a hint about where this belongs.

**"Let the agent write, and audit it."** Audit is a detective control. The evidence record is the
product's only asset, and a detective control on the thing you are selling is a promise to notice
the damage afterwards. It also fails the specific case that matters: a suppression filed by an
agent is indistinguishable, to the gate, from one filed by a person. The gate would pass, the
release would ship, and the audit entry would be read in the post-mortem.

## A tool, not a regime

Before the decision itself, the constraint that shapes it: **this product is a tool, and a tool
does not impose a process on the person holding it.**

The first instance to get agent access has one developer. Their contract says *provide findings* —
not remediate, not staff an approval chain, not hold roles. A compliance posture is something they
may want to be ready for later, and readiness is the product's job; arriving with a mandatory
two-party workflow is not. An earlier draft of this ADR made the approver necessarily a different
person from the agent's operator, which would have deadlocked that instance on day one in the name
of a control nobody had asked for.

So this ADR separates two kinds of statement, and the distinction is load-bearing for every section
below:

| Kind | Binding | What it is for |
|---|---|---|
| **Properties** | Absolute. No setting changes them. | What makes the word "proposal" true at all |
| **Policies** | Dials, defaulting to the permissive end. | What a particular organisation wants of its own process |

The properties are §1, §3, §4, §5, §6 and §9. The policies are §2 (which of the kinds an instance
enables), §7 (staleness), §8 (volume caps) and §10 (separation of duties). This matches how the
rest of the product already behaves — gates ship advisory and are tightened deliberately
(ADR 0004), the MCP endpoint is off until an administrator opens it, posture gates default off —
and it is the same reasoning: the product states what is true, and the operator decides what to
enforce.

A dial at its permissive default is not a weakness in the design. It is the design, for an
organisation that does not yet need the strict setting and should not be made to pretend otherwise.

## Decision

**An agent may create a proposal. A proposal is inert. Only a person decides it.**

1. **Proposals are a new row kind, not a draft state on the real row.** An agent-proposed
   suppression is not a `Suppression` with `Status = Proposed`; it is an `AgentProposal` that
   *references* what it asks for. The reason is blast radius: every query that reads suppressions
   would have to learn to exclude proposed ones, and the one that forgot would be a silent
   un-suppression — or worse, a silent suppression. A separate table cannot be read by accident by
   code that predates it.

2. **Four proposal kinds, and no others without amending this ADR.** *(Which of them an instance enables is a policy; the closed set is not.)*

   | Kind | Asks for | Decided by |
   |---|---|---|
   | `SuppressionRequest` | This finding should be muted, with this reason | `AuthorSuppression` |
   | `VexProposal` | This CVE does not reach us, with this justification and impact statement | `AuthorVex` to draft, `PublishVex` to publish |
   | `TriageNote` | This finding has been analysed; here is what was found | `ViewEvidence` (annotation only — see §4) |
   | `PoamRemark` | This POA&M item's progress, as observed | `CompletePoamItem` |

   Each maps onto a capability that already exists. A proposal an agent could make that no
   capability covers is a proposal this product has no opinion about, which means it is not ready
   to accept one.

3. **Deciding goes through the existing approval path, unchanged.** A decision on a proposal
   dispatches an `IApprovalEffect` in the same transaction as the decision row (the TFND-117
   pattern), and the effect is the ordinary write — the same code path a person's own action takes.
   There is no second way to create a suppression. If accepting a proposal and filing a suppression
   can diverge, they will.

4. **A `TriageNote` is the exception that proves the rule, and it is still not a decision.** It
   writes no evidence and changes no verdict: it attaches an agent's analysis to a finding as an
   annotation, visible to a reader, carrying the agent's identity. It needs no approval because it
   asserts nothing the product will act on. It is included because it is most of the value — an
   agent's reasoning on the record, where the next person will find it — at none of the risk.

5. **Nothing an agent writes can move a gate or a score.** Stated as an invariant rather than an
   outcome, because it is testable and should be tested: a proposal of any kind, in any quantity,
   must leave `GateDecisionService.ForLatestAsync` and the computed score byte-identical. A
   proposal that could change a verdict before a person decided it would be a write path wearing a
   proposal's name.

6. **No agent carries `InfoSecOfficer`, and therefore no agent can decide anything that accepts
   risk.** Already enforced at mint (TFND-242), and this ADR is why that enforcement had to stop
   being a dropdown: once decisions exist, the role that holds `AcceptRisk` is the role that can
   make them.

7. **Proposals go stale, on a configurable clock.** *(Policy.)* An undecided proposal is marked
   stale after a per-instance interval — thirty days is a starting default and nothing more; the
   number was chosen because a number was needed. Marked, never deleted and never granted: the
   passage of time must not decide anything, and the queue of things nobody decided is itself worth
   seeing. An instance that wants no expiry at all should be able to say so.

8. **Volume is capped, and the caps are settings.** *(Policy.)* An agent in a loop can file a
   thousand proposals. Rate-limit per token and cap undecided proposals per project. A proposal
   refused because the queue is full is a better failure than a queue no human will ever read.

9. **The kill switch covers proposals.** *(Property.)* The instance-level MCP switch closes
   proposal creation along with reads, because the reason an operator reaches for it — something is
   wrong and the agents should stop — is exactly the reason they should stop *writing* first.

10. **Separation of duties is available and off by default.** *(Policy.)* An instance may require
    that a proposal is decided by someone other than the user who minted the agent's token — the
    two-party control that makes propose-only more than a speed bump when the agent's operator is
    also an approver.

    It defaults to **off**, and that default is deliberate rather than a concession. With one
    developer there is nobody else to approve anything, and a tool that refuses to work until an
    organisation hires a second person is not a compliance feature, it is a defect. The honest
    description of the default configuration is: the agent's analysis reaches the record, a person
    still performs the decision, and the second pair of eyes is not claimed.

    `McpToken.CreatedByUserId` is already stored, so turning it on costs a comparison. The reason
    to specify it now and not later is that an organisation discovering it needs separation of
    duties — because an audit asked — should find a setting rather than a design gap.

## Consequences

* **The agent surface stops being a dead end for analysis.** An agent's conclusion lands on the
  finding instead of in a transcript, which is the whole point. Expect `TriageNote` to be the most
  used kind by an order of magnitude, and to be the one that justifies the work.

* **`TriageNote` carries the risk this ADR is least able to bound, and §4's "no risk" is too
  strong.** It is the only kind with no human in the loop and it will be the highest-volume one, so
  an agent that writes *"the vulnerable path is unreachable from our entry points"* — wrongly —
  has put a bad conclusion in the place people go for authoritative answers, where the next
  reviewer will anchor on it. The risk is not to the gate; it is to the next person's judgement,
  which is harder to test for than a verdict.

  The mitigation is presentational and therefore easy to skip, which is why it is written down: an
  agent's annotation must be visibly attributed and visually distinct from a person's analysis
  *everywhere it renders*, not merely carry an actor id in a column. An instance that would rather
  gate annotations than rely on that can enable approval for the kind under §2.
* **A new queue needs an owner and a screen.** Proposals nobody decides are worse than no
  proposals: they look like progress. This needs a visible pending-decisions surface with a count,
  not a tab somebody remembers to open. That screen is the real cost of this ADR, and it is larger
  than the write path it fronts.
* **The read-only guarantee in the README and in `AgentReadService` becomes conditional and must
  be rewritten honestly.** "There is no write path" would become false. The accurate statement is
  "an agent cannot change evidence; it can ask a person to" — and the distinction has to survive
  being summarised by somebody in a hurry, including by an agent describing its own permissions.
* **`AgentReadService`'s name stops being true.** The proposal path belongs beside it, not in it:
  the class whose comment is "reads only, and there is deliberately no write path" should keep
  being that class. A sibling `AgentProposalService` with its own scope checks is the shape.
* **The surface becomes worth attacking.** A read-only endpoint leaks; an endpoint that can enqueue
  a request that a tired human might approve is a social-engineering target. The mitigation is that
  a proposal shows its author as an agent, prominently, and that an approver sees the agent's
  argument rather than a summary of it.

## Staging

Accepting the shape is not a commitment to build all of it. Nothing here gates on evidence that
agents want the write path, and the cheapest honest first step is **`TriageNote` only**: it puts
the analysis on the record — the part most clearly worth having — without building the
pending-decisions queue, which this ADR names as the larger cost and the part most likely to go
unread.

`SuppressionRequest` and `VexProposal` wait until an agent has actually been blocked by their
absence. If a month of use produces four hundred annotations and nobody wishes for a suppression
request, that is the answer. If agents are blocked repeatedly, the queue gets designed against real
examples instead of guesses.

`PoamRemark` is the weakest of the four and may not survive. It is hard to say what an agent usefully
records about a POA&M item that a `TriageNote` on the linked finding does not say better, and every
kind is a kind the decision surface has to render.

## Not decided here

* **Whether an agent may propose a control disposition** (ADR 0015 §5's review-gated downgrade).
  Deliberately out of scope: a disposition is a compliance determination about what the
  organisation owns, and the first agent-proposed one should be a separate decision taken with that
  in view rather than folded in here.
* **Whether a proposal may be auto-accepted under a policy** ("suppressions for Info-severity
  findings from this agent are pre-approved"). This is the obvious next request and it is the one
  that quietly re-creates the write path. If it is ever wanted it needs its own ADR and its own
  argument.
* **The `TriageNote` retention story.** Annotations accumulate, nothing expires them, and an agent
  can write a lot of them. Needs a decision before volume makes it one.
