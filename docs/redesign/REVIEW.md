# Redesign review — tamp.findings UX rework + Blazor port

Reviewer: Claude · 2026-08-22
Source of truth: `docs/redesign/README.md` + `tamp-findings-redesign.dc.html` (the prototype is
authoritative where the README is silent).

This is a read of the hand-off against the codebase as it stands at `1f46dd1`. It exists to feed the
YouTrack fan-out; it is not a design critique for its own sake.

---

## 1. What this actually is

Three changes wearing one name:

1. **A frontend stack replacement.** React 19 + Vite + Tailwind + shadcn (37 files, ~8,500 lines under
   `web/`) is retired for Blazor on .NET 10. `Domain`, `.Data`, `.Api` survive.
2. **An information-architecture redesign.** New routing scheme, portfolio screen, one explorer shell
   replacing five views, a rebuilt project hub, and a new instance-level System layer.
3. **A functional expansion.** Roughly a dozen capabilities that have no implementation today — audit
   log, scanner registry, IdP management, policy library semantics, OSCAL/PDF export, workflow-backed
   approvals, and enforced RBAC.

Item 3 is the one an estimate will be wrong about. The visual rework is well specified and largely
mechanical; the new functionality is where the domain model has to grow.

## 2. New functionality — nothing behind these exists today

Verified absent from `src/` at review time.

### Domain concepts that must be created

| Concept | Status today | Notes |
|---|---|---|
| Audit log | **No entity.** `grep -ri audit src/` hits only comments and a couple of `CreatedBy` columns | Append-only: when, actor, action, scope, class chip (`risk` / `access` / other). Design puts exports, role grants, risk acceptance and key changes in it. Elsa history is one of its inputs. |
| `Auditor` role | `ProjectRole` has exactly 3 values (`InfoSecOfficer=1, LeadDev=2, Architect=3`) | Design calls for a 4th enum value. Additive — cheap, but it is a persisted enum. |
| `Viewer` | Implicit (a user with read access and no role) — documented only in a code comment | Design treats it as a real, named row in the capability matrix. Must become explicit in the authz evaluator. |
| Separation-of-duties flag | Does not exist | Recorded **on the assignment**, advisory by default, plus a single instance-level `Enforce separation of duties` switch. |
| Instance settings | Does not exist | Instance URL, DB, finding retention, build retention, session lifetime, outbound email, telemetry (off), version. |
| Identity-provider registry | GitHub OAuth only, from env vars, registered conditionally at startup (`AuthExtensions.cs`) | Design wants GitHub OAuth + generic OIDC + SAML + local password, managed in the UI, with per-provider state, user counts, rotate and disable. A large piece of work masquerading as a settings panel. |
| Scanner registry | `ScannerKinds.cs` is a static list | Design needs a **registered-but-never-seen** state, because that is what makes "no scan" distinguishable from "clean". Registration becomes a first-class user action. |
| Advisory feed status | `KevFeedSyncService` runs; nothing surfaces its state | CISA KEV, OSV, licence tiers with last-sync state. |
| Host aliasing / merge | Does not exist | The DAST `DUPLICATE HOST` callout offers "Merge hosts". That needs a domain concept, not just a UI affordance. |
| Attestation evidence snapshot | Does not exist | Sign-off freezes the evidence. ADR 0001 explicitly requires the snapshot store the verdict rather than expect recomputation. |

### Surfaces that must be built

- **Routing / deep links.** There is no router in `web/` — navigation is `useState` today. The README is
  right that this is the highest-value structural change; everything else compounds from it.
- **Policy library.** `RiskPolicy` exists, but library semantics do not: duplicate, rename, delete,
  system (read-only) policies, per-policy category sets, delete blocked while in use with a
  "move projects to" picker, and live recomputation of effective maxima against the enabled basis.
- **OSCAL export.** NIST OSCAL 1.1.2 JSON — assessment results, POA&M, and a *bundle* mode emitting both
  models with shared UUIDs so POA&M items resolve against the findings the assessment cites. No emitter
  exists. This is the most technically exacting new artefact in the redesign.
- **PDF export** (Letter/A4, signatory block). No generator exists.
- **RBAC enforcement.** See §4.1 — the single largest new behaviour.
- **Per-build deltas and build history.** `GateEvaluation` already carries `PriorScore` / `DeltaPoints`,
  so the data is partly there; the surfaces are not.
- **Density and delta toggles**, persisted per persona.

### Elsa — eight workflow definitions, none of which exist

Elsa appears nowhere in the solution (`grep -rin elsa` over `src/`, `build/`, `Directory.Packages.props`
returns nothing). ADR 0001 accepts Elsa and states plainly that its Blazor cost *"lands during the UI
redesign"* — this is that landing.

POA&M risk-acceptance approval · POA&M completion on a verifying build · AO extension request ·
VEX draft→publish · POA&M due-date reminders · gate-failure notification · attestation sign-off ·
ingest-key recycling with a grace period.

Each adds a **pending** state to a status the UI already renders, and pending states are not in the
current model.

## 3. What genuinely carries over

Real good news: the server side is in better shape for this than the client side.

- **`RiskScorer` already produces the ranked breakdown** the new score table needs.
  `RiskCategoryBreakdown(Key, Enabled, Max, EffectiveMax, SubScore, Contribution)` plus
  `RiskResult.WeightBasis` is exactly the shape of the design's contribution table, and
  `RiskBreakdownDto` already ships it (`AggregatesEndpoints.cs:512`). Saturation is the only derived
  flag the UI needs that is not already a field.
- **Auth is already cookie-based server-side** (`AuthExtensions.cs`, `CookieScheme`), not a token the SPA
  carries. Blazor Server inherits this nearly unchanged — one of the cheapest parts of the port.
- `ProjectRoleAssignment` already carries client / project / component tiers, so scoped grants need no
  schema change.
- `GateEvaluator`, `RiskInputsBuilder`, `ProjectGatesConfig`, `PoamItem`, `VexStatement`, `IngestToken`,
  `ScanRunReceipt`, `Severity` and `DastRoute` all carry over as stated.

## 4. Conflicts and decisions required

Items where the hand-off, ADR 0001 and the code disagree. Each needs a decision before the ticket it
belongs to can be written honestly.

### 4.1 Port order puts RBAC last, and everything depends on it — highest severity

The README's port order is: shell/routing → project hub → explorer + SAST → remaining spines → POA&M →
attestation → policy → **System layer last**.

But the System layer is where RBAC lives, and the capability matrix governs behaviour on *every screen
before it*: who may edit a policy, who may recycle a key, who may set a POA&M to risk-accepted, who may
export. Building those screens first means either shipping them with permissions unenforced, or
retrofitting authorization into eight screens afterwards.

ADR 0001 already states the correct sequence, for the same reason: **roles → decision record → Elsa
routing → e-sign**. Elsa consumes an authorization model; it does not provide one.

Compounding it: `SuppressionsEndpoints` reads the author's role from an **`X-Author-Role` HTTP header and
trusts it** (noted in ADR 0001, and a known unticketed defect). The capability matrix is unimplementable
on top of a client-asserted role.

**Recommendation:** split RBAC in two. Pull *enforcement* forward — the authz evaluator, trusted role
resolution, the `Auditor` value, `Viewer` made explicit — to sit immediately after shell and routing.
Leave the *admin UI* (People table, grant dialog, effective-access column) where the design puts it.

### 4.2 The gate rail is two-valued; ADR 0001 says it must be four-valued

`GateResult` is `(Key, Enabled, bool Passed, Observed, Threshold, Reason)` — still a boolean, confirmed
at review time. ADR 0001 decided a rule returns `Pass | Fail | Unknown | Error`, and the motivating bug is
exactly this: **a project that has never been scanned passes every severity gate**, because `0 <= 0`.

The redesign half-fixes this and half-inherits it:

- Portfolio has a `NO SCAN` ship chip, and the scan-receipt cards draw a never-ran class differently
  (dashed accent border) under the caption *"A missing scanner is not a clean scanner."* Good.
- But the project hub's gate rail renders **`PASS` / `FAIL` only** — an 18px square mark that is either an
  accent `✓` or a solid red `✕`. There is no third mark, no `UNKNOWN` tag, and the sub-line counts
  "3 of 10 enabled gates failing".

So the design's own scan receipts will say a scanner never ran while the gate rail above them says
`PASS`. That is the ADR's bug, rendered in high fidelity.

**Decision needed:** either the four-valued verdict lands before the project hub is built (preferred — it
is a domain change and the hub is built once), or the hub ships with a knowingly false gate rail and a
follow-up. The visual system needs a third mark either way; the design does not supply one.

### 4.3 A 1180px desktop floor in a product that ships an accessibility scanner

The shell sets `min-width: 1180px` and the README puts mobile explicitly out of scope. Separately it
states *"WCAG 2.1 AA is the bar for this product — it ships an accessibility scanner."*

Those two cannot both hold. WCAG 2.1 SC **1.4.10 Reflow** (AA) requires content to reflow to a 320px
equivalent without two-dimensional scrolling. A hard 1180px floor with horizontal scroll fails it.

Not pedantry: the product's commercial position is generating federal compliance evidence, and an
accessibility conformance claim it visibly fails is the kind of thing an assessor notices.

**Decision needed** (user's call, but it should be recorded rather than drifted into): accept the failure
and narrow the claim to "AA except 1.4.10, documented"; or scope a reflow pass; or hold the 1180px floor
only on the genuinely dense screens (explorer, policy editor) and reflow the rest.

### 4.4 Where does Blazor live, and does it call the API or the domain?

The README says the domain and API projects stay, prefers **Server** render mode, and argues the port is
worth doing because *"sharing the domain types directly with the UI"* kills DTO drift — citing the real
"9 gates enabled vs a computed 10" bug.

That implies Blazor components call domain services **directly**, bypassing the minimal API. But the API
is also the ingest surface, and `Tamp.Findings.Mcp` is a separate consumer. Two access paths to the same
data with independently implemented authorization is how authz bugs are born — and §4.1 is about to add a
great deal of authorization.

**Decision needed:** a new `Tamp.Findings.Web` project, or Blazor hosted inside `Tamp.Findings.Api`; and
whether UI reads go through the domain directly (fast, drift-free, needs a shared authz layer the API
also uses) or over HTTP (one enforcement path, reintroduces DTOs). Recommend a shared authorization
service consumed by API, Blazor and MCP alike, with the UI reading the domain directly.
**This warrants ADR 0002 before the first component is written.**

### 4.5 MudBlazor arrives with Elsa Studio

The design's aesthetic is square corners, hairline borders and registration marks; MudBlazor is rounded
Material with its own type scale and a global theme provider. The README's answer — mount Studio on its
own route and isolate rather than theme it — is the right call, and it also notes most deployments do not
need Studio at all (ship workflow definitions, expose only their state).

**Recommendation:** treat "expose Elsa Studio" as a separate, deferrable ticket from "run Elsa
workflows". The workflows are needed; the authoring UI is optional and carries all the CSS risk. Verify
Elsa 3.x and Elsa Studio support on .NET 10 before committing to either.

### 4.6 The i18n work that landed yesterday is thrown away

Commit `ccf7322` added locale detection, catalogue, pseudo-locale and Intl formatting to the React app
(`web/src/i18n/`, 45 keys in `en/common.json`). All of it retires with `web/`.

The design's localization rules are stricter than what was built: `IStringLocalizer` over `.resx`,
composed fragments with numbered placeholders instead of embedded markup, and **verification against a
pseudo-locale at ~40% expansion**. That last one collides with the design's own fixed-column CSS grids
(the score table is `150px minmax(120px,1fr) 74px 34px minmax(160px,1.15fr)`); the README acknowledges
this and says the columns are English minimums that must be verified.

Small mercy: only 45 keys are lost. The pseudo-locale generator needs a Blazor equivalent.

### 4.7 Out-of-scope items the design still renders

"Not covered" includes the client page, the create-hierarchy flow, and sign-in / first-run — but the
Portfolio header carries **"New client"** and **"New project"** buttons, and the app cannot be used
without sign-in. These are buttons with no destination.

`CreateHierarchyNodeDialog.tsx`, `ClientPageView.tsx` and `SignInView.tsx` exist in React and are being
retired, so this is not "already handled" — it is unported work with no design. It needs tickets that say
so, rather than being discovered mid-port.

### 4.8 No CI on this repo

Known and unticketed. Replacing an entire frontend, with no automated build or test gate, on a repo that
dogfoods its own scanner ingest, is the wrong moment to still be without one.

## 5. Smaller notes

- **Saturation** is the one genuinely new score computation. `RiskCategoryBreakdown` has `SubScore` and
  `EffectiveMax`, so it is derivable — but it should become an explicit field so the `SAT` chip and the
  red bar fill read from one source rather than from a UI comparison.
- **Source-viewer tokenization in C#** via Roslyn is sound for C#, but the explorer shows findings in
  whatever a scanner reports — TypeScript, YAML, Dockerfile, SQL. Roslyn covers one of those. Needs a
  decision on non-C# languages; plain text is an acceptable v1 answer, but it should be a stated one.
- **`<Virtualize>` on both explorer panes** is called out and correct: coverage runs to thousands of
  files, findings to ~5,000 rows.
- **Secrets reveal-once** already matches `IngestToken` behaviour; the project-level ingest key with
  recycle is the new part.
- **Attestation policy binding** — binding the sub-line's policy name to the same source as the score is a
  genuine bug fix, not a presentation change.
- **lucide as vendored inline SVG** (~20 glyphs, stroke-width 1.5) is the right call; no Blazor icon
  package is needed and none should be added.

## 6. Verdict

The design is unusually implementable. It is specific about tokens, states, derivations, and the
distinctions that matter — never-scanned vs clean, missing scanner vs no findings, pending vs terminal
status. It fixes real defects rather than restyling around them, and it correctly identifies routing as
the change everything else hangs off.

The risks are sequencing, not design:

1. RBAC is scheduled last but is a precondition for most of what precedes it (§4.1).
2. The gate rail renders a two-valued model that ADR 0001 has already replaced (§4.2).
3. The hosting and authorization architecture is unstated and needs an ADR before the first component
   (§4.4).

Resolve those three and the rest is a large but well-specified port.
