# ADR 0002: Blazor hosting, the application layer, and one authorization boundary

* Status: Accepted
* Date: 2026-08-22
* Deciders: scott
* Tracking: TFND-56 (under TFND-40)

## Context and Problem Statement

The redesign hand-off (`docs/redesign/README.md`) retires the React SPA for Blazor on .NET 10 and states
that `Tamp.Findings.Domain`, `.Data` and `.Api` carry over unchanged. It prefers **Server** render mode
and argues the port is worth doing because *"sharing the domain types directly with the UI"* eliminates
DTO drift — citing a real bug where a hard-coded "9 gates enabled" string contradicted a computed 10.

That argument is sound, and it has a consequence the hand-off does not state: if Blazor components read
the domain directly, they bypass the minimal API — and the minimal API is not the only consumer. It is
also the ingest surface, and `Tamp.Findings.Mcp` is a second consumer (today a stub, described in its own
csproj as an *"in-process MCP server"* that will *"host read-only retrieval tools so agents can pull
aggregated findings"*).

So the question is not really "where does Blazor live." It is:

> **Three consumers — HTTP API, Blazor UI, MCP — are about to read the same data. Where is authorization
> decided, and how many times is that decision implemented?**

The timing makes this urgent rather than academic. TFND-40 Phase 2 introduces a fourteen-row capability
matrix, additive roles, scoped grants with narrowest-wins resolution, separation-of-duties flagging, and
an append-only audit log. Implementing that once is a large piece of work. Implementing it three times
is how a security product ships an authorization bypass.

### What exists today

* `Tamp.Findings.Api` is already the frontend host. It calls `UseStaticFiles()` and
  `MapFallbackToFile()` to serve the SPA bundle same-origin in production. Blazor served from this
  project is continuity, not a new arrangement.
* Authentication is already **cookie-based and server-side** (`AuthExtensions.cs`, `CookieScheme`), not a
  token the SPA carries. Blazor Server inherits it nearly unchanged.
* Business logic currently lives in three places: the domain (`RiskScorer`, `GateEvaluator`), API-project
  services (`RiskInputsBuilder`, `VexResolver`, `SbomEnrichmentService`, `LicensePolicy`), and the
  endpoint bodies themselves.
* That third location is the problem. `RiskInputsBuilder` is `Tamp.Findings.Api.Services` — a UI that
  bypasses the API cannot reach it without referencing the API project, and endpoint-body logic cannot be
  reached at all.
* Authorization is barely present, and where it exists it is wrong: `SuppressionsEndpoints` reads the
  author's role from an `X-Author-Role` HTTP header and trusts it (ADR 0001; TFND-19; TFND-71).

## Decision Drivers

* **One authorization decision, one implementation.** Three consumers must not mean three enforcement
  paths. This is a product whose commercial value is compliance evidence; an authorization gap is not a
  bug class it can absorb.
* **DTO drift is a real, observed defect**, not a theoretical one. The "9 gates enabled" string is the
  named example and the hand-off treats killing it as a primary justification for the port.
* **Single-image deployment is a product requirement** (TFND-4 / F3). Whatever is decided must ship as
  one container with one process.
* **MCP must not be a side door.** An agent pulling findings through MCP must be subject to the same
  matrix as a human clicking the UI. MCP is a stub today, which makes this cheap to get right and
  expensive to retrofit.
* **The dense screens are genuinely dense.** The policy editor recomputes effective maxima on every
  keystroke; the explorer renders trees of thousands of files and finding lists of ~5,000 rows.
* **Do not rewrite what works.** Ingest, the scorer, the gate evaluator and the data layer are not part of
  this redesign and must not be destabilised by it.

## Considered Options

### Hosting

1. **Blazor inside `Tamp.Findings.Api`.** One project, one process, one image. Matches how the SPA is
   served today.
2. **A separate `Tamp.Findings.Web` host process.** Two processes in one image, or two images. Breaks
   TFND-4 or introduces a reverse proxy inside the container.
3. **A `Tamp.Findings.Web` Razor Class Library hosted by `Tamp.Findings.Api`.** Components and static
   assets live in their own project; the API project stays the host and composition root.

### Data access

1. **UI calls the HTTP API.** One enforcement path, but reintroduces DTOs — and therefore the drift the
   port exists to eliminate — plus a serialization round trip on every keystroke of the policy editor.
2. **UI calls the domain directly.** No drift, no round trip, but authorization is implemented separately
   in the UI and the API, and MCP gets a third implementation.
3. **A shared application layer that all three consumers call.** Authorization is decided once, inside
   that layer. The HTTP API becomes a transport over it rather than the place logic lives.

### Render mode

1. **Interactive Server**, globally.
2. **WebAssembly.** Requires an HTTP API, a token the client carries, and DTOs for every screen — it
   forces data-access option 1 and discards the port's main justification.
3. **Auto.** Inherits WASM's constraints on second load; the app must then satisfy both models.
4. **Per-component**, defaulting to Interactive Server.

## Decision

**A shared application layer owns authorization; the HTTP API, the Blazor UI and MCP are three
transports over it.**

Concretely:

### 1. A new `src/Tamp.Findings.Application` project

It sits between `Domain` / `Data` and every consumer:

```
Domain  ──►  Application  ──►  Api      (HTTP transport + ingest + composition root)
Data    ──►      │        ──►  Web      (Blazor components, RCL)
                 └────────►    Mcp      (agent tools)
```

The Application layer owns:

* **The authorization evaluator** and the capability matrix (TFND-68). Every capability check happens
  here. No consumer may decide access for itself.
* **Query and command services** — the operations the product performs, expressed in domain types.
* **The audit write path** (TFND-73), so an audited action cannot be performed through a route that
  forgets to audit it.

`RiskInputsBuilder`, `VexResolver`, `SbomEnrichmentService` and `LicensePolicy` move here from
`Tamp.Findings.Api.Services` as the screens that need them are ported — **not in a big-bang move.** A
service moves when the first non-API consumer needs it. Endpoint bodies are refactored the same way,
opportunistically, when a screen touches them.

Authorization is enforced at the Application boundary, **not** at the endpoint or component. An endpoint
or a component that forgets to check is not a vulnerability, because the layer beneath it refuses.

### 2. Blazor is a Razor Class Library hosted by the API project

`src/Tamp.Findings.Web` contains components, layouts, static assets and the token stylesheet.
`Tamp.Findings.Api` references it, hosts it, and remains the composition root and the single process.

* One container, one port, one cookie — TFND-4 holds unchanged.
* UI code stays out of the API project, so the boundary is enforced by the compiler rather than by
  convention.
* `Tamp.Findings.Web` **must not reference `Tamp.Findings.Api`.** If a component needs something that
  lives in the API project, that thing is in the wrong project and moves to Application.

The project keeps the `.Api` name despite serving UI. It already does (`UseStaticFiles` +
`MapFallbackToFile`), renaming would churn every namespace and deployment reference, and the name is
accurate about what it is: the host.

### 3. Interactive Server, chosen per component

Default `InteractiveServer`. Not global, because two surfaces are better static:

* **The attestation** (TFND-100) is a print target. Static SSR renders faster, prints more predictably,
  and gives the PDF generator (TFND-102) something to render without driving a circuit.
* **Sign-in** (TFND-126) should not need a circuit to accept a password.

WebAssembly and Auto are rejected outright: both force an HTTP API for data, a token the client carries,
and DTOs for every screen — which is data-access option 1 wearing a different hat, and would discard the
port's primary justification.

**Prerendering is disabled on components that read scoped scope state.** Prerender runs before the
circuit exists, so a component reading the scope service renders twice with different answers — visible
flicker and doubled queries.

### 4. Circuit configuration is part of this decision, not an afterthought

The explorer's volumes make this concrete rather than precautionary:

* `<Virtualize>` on both explorer panes is mandatory (already required by TFND-86). Only visible rows
  reach the wire; a 5,000-row list is a few dozen rendered rows.
* Set `MaximumReceiveMessageSize` deliberately — the default 32 KB is generous for diffs but not for a
  paste into the POA&M mitigation-plan field.
* Set `DisconnectedCircuitMaxRetained` and `DisconnectedCircuitRetentionPeriod` against expected
  concurrency. This is a self-hosted tool for a team, not a public site; the defaults are sized for
  neither.
* Enable response compression for the circuit's WebSocket.
* **Server-side syntax tokenization** (TFND-88) sends spans, not a highlighter. That is a bandwidth
  decision as much as a rendering one.

### 5. MCP consumes Application, never Data

`Tamp.Findings.Mcp` references `Application`, not `Data` and not `Api`. Its tools call the same query
services with the same authorization checks. An agent's read is subject to the same matrix as a human's.

This is the cheapest moment to establish it — MCP is a `Placeholder.cs` stub today.

## Consequences

**Positive**

* One authorization implementation, tested once, covering three consumers. The Phase 2 matrix cannot be
  half-applied.
* DTO drift is structurally impossible for UI reads — the "9 gates enabled" bug class stops being
  expressible, which is the outcome the hand-off asked for.
* The policy editor recomputes on keystroke against in-process domain calls, no serialization.
* MCP inherits authorization for free rather than growing its own.
* The compiler enforces the layering: `Web` cannot reach `Api`.

**Negative / accepted costs**

* **A fourth project.** More structure than the solution has today, justified by the three-consumer
  problem rather than by taste.
* **A migration with a long tail.** Services and endpoint bodies move to Application incrementally, which
  means for most of TFND-40 the codebase has logic in both places. That is deliberate — a big-bang move
  would destabilise ingest, which is not part of this redesign — but it must be *finished*. TFND-129
  should verify `Tamp.Findings.Api.Services` is empty of business logic before the track closes.
* **Blazor Server means a stateful connection.** A dropped circuit is a visible failure where the SPA
  would have retried a fetch. Reconnection UI is a real requirement, not a nicety.
* **Self-hosted scaling is per-instance.** Circuits pin a user to a process. Acceptable for a
  single-image, single-tenant-per-deployment product; it would not be for a multi-tenant SaaS.

**Neutral**

* The HTTP API remains public and supported. It is the ingest contract and CI's interface; it is not
  deprecated by the UI ceasing to use it.
* The React app keeps building and serving until TFND-128. The two frontends coexist for the duration of
  the port.

## Notes

* The authorization evaluator this ADR places in Application is TFND-68. This ADR decides *where* it
  lives; TFND-68 decides *what it says*.
* `X-Author-Role` header trust (TFND-19 / TFND-71) is the concrete proof of the failure mode this ADR
  prevents: authorization decided at the transport, by data the transport was handed. Moving the decision
  to Application is what makes that class of mistake unavailable rather than merely discouraged.
* ADR 0001's rule engine is an Application-layer concern for the same reason — predicates and Elsa
  workflows both need the same authorization and audit envelope regardless of which consumer triggered
  evaluation.
* The 1180px / WCAG 1.4.10 question (TFND-57) is independent of this ADR and is decided separately.
