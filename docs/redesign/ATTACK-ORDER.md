# Attack order — TFND-40 redesign

Derived from the dependency graph in YouTrack (235 links), not asserted. The critical path is
**9 waves** long:

```
TFND-56 → TFND-60 → TFND-63 → TFND-64 → TFND-77 → TFND-100 → TFND-102 → TFND-128 → TFND-129
ADR 0002  scaffold  router    shell     hub score attestation  PDF      retire web/  reconcile
```

Everything else has slack. The order below groups the graph into stages a team can actually work,
rather than reciting the waves.

---

## Stage 1 — Unblock everything (nothing else starts first)

**TFND-56 · ADR 0002 — Blazor hosting topology and the shared authorization boundary.**
This single ticket unblocks **64 of the 74 tasks**. Until it is Accepted, there is no correct place to
put a component and no agreed answer on whether the UI reads the domain or the API. Do it alone, do it
first, do not start the scaffold in parallel hoping the ADR ratifies it.

Two decisions run alongside it because they gate physical work rather than depending on it:

- **TFND-57 · the 1180px vs WCAG 2.1 AA reconciliation.** Now a hard dependency of the token
  stylesheet — `min-width` is written once, in `industry.css`, and changing it later means revisiting
  every screen's layout assumptions.
- **TFND-58 · the Elsa / .NET 10 spike.** Long lead time, and its answer changes Phase 13 entirely. If
  Elsa 3.x does not support .NET 10 yet, that is much better known in week one.

## Stage 2 — Two independent tracks open up

Once ADR 0002 lands, backend and frontend genuinely parallelize. They do not touch each other until
Stage 4.

**Track A — domain truthfulness (no Blazor dependency at all).**

1. **TFND-74 · four-valued gate verdicts.** The unscanned-gate bug. Must precede the project hub.
2. **TFND-76 · saturation as an explicit field.** Unblocks 18 tasks; trivially small.
3. **TFND-68 · the capability model and shared authorization evaluator** — unblocks 39 tasks, and the
   whole reason RBAC was pulled forward.
4. **TFND-69 → TFND-70 → TFND-71** — Auditor role, additive scope resolution, then killing
   `X-Author-Role` header trust. TFND-71 is a Show-stopper security fix; land it the moment TFND-70 is
   green rather than saving it for Phase 12.
5. **TFND-73 · the audit log** — unblocks 24 tasks and every mutating capability writes to it, so it
   wants to exist before those capabilities are written, not after.

**Track B — frontend foundation.**

1. **TFND-59 · CI.** Before the scaffold, not after. It protects every commit that follows.
2. **TFND-60 · scaffold the Blazor project** (unblocks 50).
3. **TFND-61 · token stylesheet and primitive kit** (unblocks 48) — gated on TFND-57.
4. **TFND-62 · lucide glyphs**, **TFND-67 · localization foundation**. Both independent and small.

**TFND-75 · the UNKNOWN gate mark** belongs here too: it is a design question with a two-day turnaround
that blocks the hub's gate rail. Raise it with the design owner in Stage 1 so the answer exists by the
time Track A finishes TFND-74.

## Stage 3 — The spine of the application

Strictly sequential, and the reason the critical path is long:

**TFND-63 (router) → TFND-64 (shell) → TFND-65 (header)**, with **TFND-66 (scoped state)** alongside.

The router unblocks 48 tasks and the shell 45. Nothing visual is worth starting before them; the
hand-off's own judgement that "introducing a router is the highest-value structural change" is correct
and the graph agrees.

**TFND-115 · Elsa runtime integration** also opens here — it depends only on the spike and the audit
log, so it can run in the background of Stage 3 rather than waiting for Phase 13.

## Stage 4 — Screens, widest parallelism

This is where the team can fan out; 20 tasks become available at once. Sequence by what unblocks most:

1. **TFND-77 · project hub header and score card** (unblocks 15) — then TFND-78 (contribution table),
   TFND-79 (gate rail), TFND-82 (scan receipts), TFND-80, TFND-81, TFND-83.
2. **TFND-86 · explorer shell** (unblocks 11) — then TFND-87 severity treatment, TFND-88 SAST spine,
   and the remaining four spines, which are independent of each other.
3. **TFND-95 · POA&M table** (unblocks 12) — then the record view and dialogs.
4. **TFND-84 · Portfolio.** Small, high visibility, and the security lead's entry point.
5. **TFND-104 → TFND-105 → TFND-106 · policy and gates editor.** Self-contained; a good candidate for
   whoever is least entangled with the shell.

Do **TFND-126 (sign-in and first-run)** early in this stage rather than in Phase 14 where the ticket
sits. Nothing can be demonstrated on a fresh instance without it, and the first-user-becomes-Admin path
is the bootstrap for everything Track A built.

## Stage 5 — Evidence and system

**TFND-100 (attestation) → TFND-103 (evidence snapshot) → TFND-102 (PDF)**, plus **TFND-101 (export
dialog)** which hands off to TFND-39 for the OSCAL emitters.

The System panels (TFND-110 through TFND-114) land here. **TFND-111 — the identity-provider registry —
is the outlier**: it is a genuine feature, not a settings panel, and generic OIDC and SAML are each
substantial. Split it per provider kind if the estimate demands it, and start it earlier than its
graph position suggests.

## Stage 6 — Workflows

**TFND-116 (pending states)** first — it is the cross-cutting UI grammar every other workflow needs.
Then the eight workflows, which are mutually independent:

Highest value first — **TFND-117 (risk acceptance approval)**, since the capability matrix already
restricts risk acceptance to InfoSec and this is what makes the approval auditable; then TFND-123
(attestation sign-off), TFND-118 (completion on a verifying build), TFND-124 (key grace period, which
retires a hazard warning the UI currently has to display), then the notification and reminder
workflows.

**TFND-125 (Elsa Studio)** is Minor and explicitly deferrable. Ship without it unless someone asks.

## Stage 7 — Cutover

**TFND-128 · retire `web/`** — gated on parity across every screen. Note it also carries removal of the
uncommitted preview auth bypass in `AuthEndpoints.cs`; that must not survive the port.

**TFND-129 · reconcile superseded tickets** — close TFND-9 as superseded with each F8 item accounted
for, unblock TFND-39, fold TFND-19 into TFND-71.

---

## Where the risk actually is

- **TFND-56 is a single point of failure.** 64 tasks wait on it. If it stalls in discussion, the whole
  track stalls; timebox it.
- **The Stage 3 spine cannot be parallelized.** Router → shell → header is four tasks of pure serial
  latency in the middle of the plan.
- **TFND-111 is under-sized relative to its ticket.** It reads as one of five System panels and is
  closer in scale to a whole phase.
- **TFND-91 (host aliasing)** is a leaf in the graph but changes historical scores. Its "retroactive or
  forward-only" decision has consequences well outside the DAST spine.
