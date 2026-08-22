# Handoff: tamp.findings UX rework

## Overview

tamp.findings is a self-hosted security and quality dashboard that ingests scanner output across many
builds, scores each build against a configurable risk policy, and produces federal-grade compliance
evidence (CISA Secure Software Development Attestation, NIST SSDF SP 800-218).

This handoff covers a redesign of the whole application: a new information architecture, a project hub
that answers "can this ship?" and "how are we trending?" in one view, a unified evidence explorer that
replaces four near-identical two-pane screens, POA&M management, the attestation, policy and gate
editing, and a new instance-level system administration layer.

The redesign addresses, in order, the problems the product brief listed:

1. **No deep linking** — every screen has an addressable URL, shown in a URL chip in the header.
2. **The score was illegible** — the six-of-twelve concentric rings are gone, replaced by a ranked
   contribution table over every scored category.
3. **Score and gates lived apart** — they now sit side by side on the project hub.
4. **Four duplicate explorers** — one explorer shell with five spines.
5. **"Clean" vs "never scanned" was weak** — scan receipts distinguish them explicitly.
6. **DAST didn't fit the SAST model** — it is a spine of the same shell, with its own detail body.
7. **One app appearing as two hosts** — flagged in place with a "merge hosts" affordance.
8. **Severity had no hierarchy beyond colour** — a glyph ladder plus a letter code plus colour.
9. **Nothing was time-aware** — per-build deltas throughout, and a build-history table.
10. **Density was one-size-fits-all** — a density prop, and per-persona entry points.

## About the design files

The files in this bundle are **design references created in HTML**. `Tamp Findings Redesign.dc.html`
is a self-contained prototype — one file, inline styles, mock data — that demonstrates intended
layout, behaviour and states. It is **not production code to copy**.

**The target is Blazor on .NET 10**, replacing the current React 19 + Vite + Tailwind + shadcn SPA.
The existing `web/` app is being retired; treat it as prior art for behaviour and API shape, not as the
implementation to extend. The domain and API projects (`Tamp.Findings.Domain`, `.Data`, `.Api`) stay.

Conventions that apply to every screen here:

- **Localization.** Strings belong in resources (`IStringLocalizer` over `.resx`), never hard-coded in
  markup. Every literal quoted in this document is English source copy, not a string to inline.
- **Embedded markup in a localized string** goes through a composed fragment with numbered placeholders
  so translators receive `{0}`/`{1}` rather than markup — the Blazor equivalent of the React `<Trans>`
  rule. Do not concatenate localized fragments.
- **Design for ~40% text expansion.** Several layouts here are CSS grids with fixed columns — those
  columns are minimums chosen for English and must be verified against a pseudo-locale. Chips, badges,
  table headers and nav items must grow or wrap rather than truncate.

## Fidelity

**High fidelity.** Colours, typography, spacing and interaction states are final. Recreate the UI
faithfully. The visual system is Industry — a technical, blueprint-style wireframe aesthetic — inverted
onto a dark editor ground.

**Component-library recommendation: hand-roll, don't adopt.** This design needs about a dozen
primitives (card, chip, table, tabs, tree row, dialog, text input, checkbox, radio, button) and no
complex widgets — no date picker, no rich combobox, no data grid. A Blazor component library
(MudBlazor, Radzen, FluentUI) would bring rounded Material surfaces, elevation and its own type scale,
all of which fight square corners, hairline borders and registration marks. Take the token stylesheet
and write the primitives as `.razor` components.

The exception is **Elsa Studio, which is built on MudBlazor** — see the workflow section. If it is
embedded rather than run as a separate app, MudBlazor is in the build regardless, and the call becomes
whether to theme it to these tokens or isolate it. Isolating it is the cheaper answer.

---

## Design tokens

Tokens live in `industry.css` (bundled). The prototype overrides that sheet's light palette with a
dark editor palette; both tonal ramps are flipped end-for-end so every 100–900 step keeps its role
(low steps are surfaces, high steps are ink). Use these values.

### Core

| Token | Value | Use |
|---|---|---|
| `--color-bg` | `#1e1f22` | Editor ground |
| `--color-surface` | `#252629` | Raised surface |
| `--color-text` | `#d7dae0` | Primary ink |
| `--color-accent` | `#4d9dd6` | Steel accent — the single brand colour |
| `--color-divider` | `color-mix(in srgb, #d7dae0 15%, transparent)` | Hairlines |

### Neutral ramp (surfaces → ink)

`100 #202124` · `200 #2a2c30` · `300 #35383d` · `400 #4a4e55` · `500 #8c9199` · `600 #949aa3` ·
`700 #aeb3bb` · `800 #c6cbd2` · `900 #e2e6eb`

`--color-neutral-500` is the dimmest text token and is used at 9–10px. It measures ~5:1 on the
ground; do not darken it. WCAG 2.1 AA is the bar for this product — it ships an accessibility scanner.

### Accent ramp

`100 #16222e` · `200 #1d2f40` · `300 #26425c` · `400 #31577c` · `500 #3f739f` · `600 #5b9ed2` ·
`700 #7db3de` · `800 #a2c9e9` · `900 #cbe1f5`

`700` is the link and interactive-text colour. `100`/`200` are tinted fills.

### Semantic colours

These are the only colours outside the steel accent, and each one is always paired with a glyph and a
written label so that colour is never the sole signal (the attestation must survive a black-and-white
printer).

| Meaning | Hex |
|---|---|
| Critical severity · fail · blocked | `#dd5f5f` |
| High severity · warning · SoD flag | `#e2894a` |
| Medium severity · skipped · idle | `#d4bb4a` |
| Low severity | `#7db3de` |
| Info severity | `#949aa3` |
| Pass · covered · healthy | `#4fb783` |
| Text on a solid semantic fill | `#12181e` |

Risk bands: green `#4fb783`, yellow `#d4bb4a`, orange `#d68f42`, red `#dd5f5f`.

### Syntax-highlighting palette (source viewer)

keyword `#7db3de` · type `#5cc8b0` · method `#d6cf8a` · string `#d99a7a` · number `#a8ce97` ·
comment `#7f9c73` · plain `var(--color-neutral-800)` · punctuation `var(--color-neutral-600)`

### Typography

- Headings: **Barlow Condensed** 600 (`--font-heading`)
- Body: **Barlow** 400 (`--font-body`), base 13px
- Code, identifiers, counts, timestamps: `ui-monospace, monospace`
- Scale in use: 30px screen titles · 19–20px card titles · 15–16px table emphasis · 12–13px body ·
  11px secondary · 10px uppercase kickers (0.12em tracking) · 9px column headers (0.12–0.14em tracking)

Minimum sizes: nothing below 9px, and 9–10px is reserved for uppercase labels with wide tracking.

### Spacing, shape, elevation

- Spacing scale from `--space-1` (3.4px) to `--space-8` (27.2px); layout gaps of 8/10/12/16/18/22px.
- **Square corners everywhere.** Radius is 0 on cards, buttons, inputs, chips and dialogs.
- Cards are transparent line drawings: 1px `--color-divider` border, no fill, plus four `+`
  registration marks at the corners (`.blueprint` + four `<i class="corner tl|tr|bl|br">` children).
- The primary button is the one solid object: accent fill, square, with registration marks.
- Shadows only on overlays: `--shadow-lg` = `0 12px 32px rgba(0,0,0,0.6)`.
- Icons: lucide, stroke-width 1.5.

---

## Application shell

**Layout:** a flex row. Fixed 238px sidebar on `--color-neutral-100` with a right hairline; main
column fills the rest. The content wrapper has `min-width: 1180px` — this is a dense desktop tool and
should scroll horizontally rather than collapse. 22px padding.

### Sidebar (top to bottom)

1. **Brand** — "tamp" in ink, ".findings" in `--color-accent-700`, 20px Barlow Condensed, over a 10px
   uppercase kicker "attestation evidence".
2. **Scope card** — a blueprint card listing the four tiers of the domain model, each a label over a
   monospace value with a chevron: Client `BrewingCoder` · Project `tamp` · Component `tamp-findings` ·
   Build `179fe8b · net10`. This hierarchy is load-bearing and appears on nearly every screen.
3. **Nav groups**, each a 9px uppercase label over its items:
   - **Scope** — Portfolio (5), Project hub
   - **Explore** — Findings (1117), Dynamic scan (53), SBOM (84), Coverage (61%), Tests (1284)
   - **Evidence** — POA&M (3 open), VEX statements (4), Attestation (22)
   - **Project admin** — Policy & gates, Ingest keys (4)
   - **System · instance** — Users & RBAC (5), Authentication, Scanners & ingest (12), Instance
     settings, Audit log
   The System group is visually separated: a top hairline, 14px of padding above, and its group label
   in `--color-accent-700` rather than neutral, signalling that it sits outside the project scope.
   Active item: accent background, `#1e1f22` text, 3px `--color-accent-900` left border. Counts sit
   right-aligned in 10px monospace.
4. **Footer** — signed-in user and role, above a hairline.

### Header (two rows)

1. **Tab strip** on `--color-neutral-100`: Portfolio · Project hub · *(active explorer spine title)* ·
   POA&M · VEX · Attestation · Policy & gates · Ingest keys · System · *(active panel)*. The active
   tab takes the page background, a 1px accent top border and `margin-bottom: -1px` so it merges with
   the content below. The System tab uses `--color-accent-800` for its top border to mark it as
   instance-level.
2. **URL row**: a bordered monospace chip showing the current deep link with a "copy link" action,
   e.g. `/c/brewingcoder/p/tamp/build/179fe8b/sast/IngestEndpoints.cs`, plus — right-aligned — the
   build stamp `179fe8b · main · net10 · 2 h ago`, a "canonical" chip, and the account control.

**Account control:** 24px square accent avatar with the user's initials in `#12181e`, the login in
monospace, and a caret. Clicking opens a 246px blueprint menu on `--color-neutral-100` with
`--shadow-lg`: a header block (32px avatar, name, role), then Profile, API keys & ingest tokens,
Policy & gates, and Sign out (in `#dd5f5f`), each a label over an 10px sub-line, separated by
hairlines, with a 7% ink hover tint.

### URL scheme

| Screen | Path |
|---|---|
| Portfolio | `/` |
| Project hub | `/c/{client}/p/{project}/build/{sha}` |
| Explorer | `/c/{client}/p/{project}/build/{sha}/{spine}/{selection}` |
| POA&M item | `/c/{client}/p/{project}/poam/{id}` |
| VEX | `/c/{client}/p/{project}/vex` |
| Attestation | `/c/{client}/p/{project}/build/{sha}/attestation` |
| Policy & gates | `/c/{client}/p/{project}/settings/policy` |
| Ingest keys | `/c/{client}/p/{project}/settings/keys` |
| System | `/system/{panel}` |

Findings deep links carry a line anchor (`#L142`). Introducing a router is the highest-value
structural change in this redesign — nearly everything else compounds from it.

---

## Screens

### 1. Portfolio

**Purpose:** the security lead's weekly question — which project is worst right now.

Header: "Portfolio" (30px) over a 12px neutral-600 sub-line, with "New client" (secondary) and
"New project" (primary) buttons right-aligned.

One blueprint card holding a table: Project · Client · Score (right) · Band · Ship · Attestation ·
Blocking · Last build · Actions. Rows are clickable and open the project hub. Project name is 15px
Barlow Condensed 600. Score is monospace, right-aligned. Band is a chip in the band's own colour
(14% tint fill, 1px border, uppercase monospace) — the band name is always written out. Ship is a
chip: `BLOCKED` solid `#dd5f5f` with `#12181e` text, `CLEAR` outlined `#4fb783`, `NO SCAN` outlined
neutral. Attestation is a compact monospace tally (`13 Y · 4 P · 0 N · 5 M`). Blocking names the
actual reasons in prose. Actions are "edit" (accent) and "delete" (`#dd5f5f`) text buttons that stop
propagation.

Ordering is worst-posture-first, and "no canonical build in 41 days" is a first-class blocking reason —
a project with a green score and no recent scan is not healthy.

### 2. Project hub

**Purpose:** the release manager's "can this ship?" and the security lead's "how are we trending?" in
one view. This is the most-used screen.

**Header:** a 4px vertical rule in the current band's colour, then the project name (30px) over
`BrewingCoder · 3 components · policy {policy name}`. Right: "Export evidence" (secondary) and
"Open attestation" (primary).

**Row 1 — two columns, `minmax(620px, 1.55fr)` and `minmax(320px, 1fr)`.**

*Left: the risk score.* A 10px kicker "How are we trending", then the score at 46px Barlow Condensed
beside a band chip in the band colour and, when deltas are on, `+2.1 vs prior build` in monospace
accent (never wrapping). A right-aligned caption states the live band boundaries and the sentence that
matters most: *categories saturate — the score is posture, not volume.*

Then the ranked contribution table, one row per scored category, grid
`150px minmax(120px,1fr) 74px 34px minmax(160px,1.15fr)`:

- Category label (12px) over its policy key (9px monospace, neutral-500)
- A 9px contribution bar: `--color-neutral-200` track, fill width = points ÷ effective max. Fill is
  the accent for a contributing category, `--color-neutral-400` for a zero, `#dd5f5f` when saturated.
- Points / effective max, monospace, right-aligned
- A `SAT` flag in `#dd5f5f` when the category is saturated
- Evidence text, plus the delta, plus a right-aligned drill label naming the spine it opens
  (`components →`, `files →`, `routes →`, `suites →`)

Any category contributing points reads hotter: a 2px `#dd5f5f` left tick and brighter evidence text.
Rows hover with a 5% ink tint and are clickable, routing into the explorer on the right spine.
A disabled category drops to 55% opacity and reads "disabled in policy".

Below: *"SAT = category saturated: more findings of that class cannot raise the score. Twelve of twelve
scored categories shown."* — the old rings drew six of twelve; showing all of them is the point.

*Right: the gates.* Kicker "Can this ship", then the verdict: `✕ BLOCKED` as a solid `#dd5f5f` chip
with `#12181e` text, or `✓ CLEAR TO SHIP` outlined in `#4fb783`. Sub-line: "3 of 10 enabled gates
failing on this build" — **derived, never hard-coded.** Then one row per enabled gate: an 18px square
mark (accent-bordered `✓` for pass, solid `#dd5f5f` `✕` for fail), the gate's human label, a
`PASS`/`FAIL` tag, the observed value in prose, and — for failures only — an accent action link to the
thing that failed. A closing line names any gate that is configured but disabled.

**Row 2 — components and the project key**, two columns `minmax(0,1.55fr)` / `minmax(320px,1fr)`.

*Components table:* Component · Flavors · Scanner classes · Builds · Last · Actions, with a
"New component" primary button. Rows open the explorer. A component is one deployable unit; the same
commit can produce several builds distinguished by flavor (`net10`, `web`, `deployed`).

*Project ingest key:* a masked key in a monospace field beside a "Recycle" button outlined in
`#e2894a`, over the line *"Recycling invalidates the old key immediately. Any pipeline still using it
fails its next ingest, and a missing scan is not a clean scan — the affected builds will read as
unscanned."* After recycling, a copy-once panel appears (accent-600 border, accent-100 fill) with the
full key, a Copy button and a Done button, headed `NEW KEY — COPY IT NOW, IT IS NOT STORED`.

**Row 3 — scan receipts.** A four-column grid of eight cards, one per scanner class, headed
*"Scan receipts · what actually ran on 179fe8b"* with the caption *"A missing scanner is not a clean
scanner."* Each card: class name (15px), a mark (`✓` ran clean, `!` ran with findings, `—` never ran),
an uppercase state line, and a detail line naming the tools and counts. **A never-ran class is drawn
differently** — dashed accent border, `--color-accent-100` fill — because conflating "no findings"
with "no scan" is exactly how a compliance attestation becomes false. Cards route to their spine.

**Row 4 — build history.** Last six canonical builds: Build · Branch · flavor · Score · Δ · Coverage ·
Gates · Ingested. The gate column is derived (`7 ✓  3 ✕`).

### 3. Explorer (five spines)

**Purpose:** replaces Findings, Dynamic scan, Coverage and Tests — four near-identical two-pane screens
with no shared shell — plus the SBOM table.

One shell: title and sub-line, a severity legend (SAST and DAST only), a spine strip, then a
`320px / 1fr` two-pane grid. Spine tabs are monospace chips; the active one takes an accent border and
an 18% accent tint. The caption reads *"One shell, five spines — same navigation, same detail grammar,
different evidence."*

**Left pane — tree.** Group rows (module, host, ecosystem, assembly) are 600-weight and non-clickable;
leaf rows indent 12px per level and are selectable. Each row shows a truncating monospace name and, on
the right, the severity ladder in the severity colour plus a per-spine badge (severity letter, CVE
count, coverage percentage, or passed/failed). Selection: `--color-accent-200` background and a 2px
accent left border. Hover: 6% ink tint.

**Right pane — detail header (identical across spines).** A status chip, the title (19px Barlow
Condensed), a monospace sub-line, action buttons ("Open POA&M", "Suppress"), and a four-column meta
strip below a hairline.

**Per-spine bodies:**

- **SAST** — a source viewer. Header shows the file path and "source at build {sha}". Lines are 22px
  tall in 12px monospace: a 46px right-aligned, non-selectable line-number gutter (neutral-500), a
  16px severity mark, then syntax-highlighted code. The flagged line takes a 13% tint of its severity
  colour and a 3px left border in the same colour. **Set the row height on the row, not on the code
  span** — an empty line in a baseline-aligned flex row otherwise grows.
- **DAST** — request and response panels side by side, monospace, wrapping on `break-all`, the
  response carrying the reflected payload as evidence. Where the same application was reached by two
  addresses, a `DUPLICATE HOST` callout in `#e2894a` explains that findings are attributed to *how the
  scanner connected* rather than to the application, and offers "Merge hosts".
- **SBOM** — a "Known vulnerabilities" table: Advisory · Severity (ladder + letter, in colour) · CVSS ·
  KEV (solid `#dd5f5f` chip when listed, otherwise a neutral dash) · Fixed in · VEX. The VEX cell is
  the workflow: `not_affected →` in accent, or `no VEX — write one →` in `#e2894a`, linking to VEX.
- **Coverage** — the same source viewer with a covered/uncovered gutter: `+` in `#4fb783`, `−` in
  `#dd5f5f`, uncovered lines tinted. A legend strip sits under the code.
- **Tests** — a Cases table: Case · Outcome (outlined chip: green passed, yellow skipped, red failed) ·
  Duration · Note. Skip reasons are shown; a skipped test is not a passing test.

**Severity treatment (used everywhere).** Five levels, three redundant signals: a five-step ladder
glyph (`▰▰▰▰▰` Critical → `▰▱▱▱▱` Info), a letter code (C/H/M/L/I), and colour. The ladder and letter
survive a monochrome print and a colour-blind reader; the colour makes it scannable.

### 4. POA&M

**Purpose:** the federal record (NIST SP 800-53 CA-5) that a weakness exists, who owns it, and when it
closes. Reviewed monthly by the Authorizing Official.

Header with a "New POA&M item" primary button. Then a gate banner: a solid accent `GATE FAILING` chip,
the explanation that `poamPastDue` has two overdue items and what the team can do about it (close,
get an AO extension, or move to risk-accepted), and a link back to the gates.

A stats strip (Open · In progress · Completed · Risk accepted · Past due) as 26px numerals over 10px
uppercase labels.

The table: Item · Weakness · Sev (coloured ladder + letter) · Status · Owner · Scheduled · Age/due ·
Links · Actions. Rows select; actions are edit and delete.

Below, the full record for the selected item: the federal template fields in a two-column grid —
Weakness description, Mitigation plan, Resources required, Severity · status, Scheduled completion,
Reference — with actions Edit, Mark completed, Request AO extension. Then linked findings, each a
coloured ladder, a monospace reference, a description and an "open →" link into the explorer.

**Create/edit dialog** (780px, blueprint frame on `--color-neutral-100`): scroll on an *inner* wrapper,
never on the framed element — the registration marks sit outside the box and a scroll container counts
them as overflow. Fields: Title, Weakness description, Mitigation plan, Resources required, Reference
URL, each with a helper line beneath (not a placeholder — helper text survives typing). Then severity
chips (in severity colours), status chips (accent), scheduled completion (blank = unscheduled, and the
past-due gate skips unscheduled items), and owner. Footer: Save item, Cancel, and the note that saving
writes an audit entry.

**Delete confirmation** steers away from deletion: *"Federal practice is to close an item rather than
delete it — a deleted item leaves no audit trail for the AO. Delete only entries opened in error."*
The three actions are Delete permanently, Cancel, and Cancel & mark cancelled.

### 5. VEX statements

Table: Advisory · Component · Status (outlined chip) · Justification (the OpenVEX enum value in
monospace) · Rationale (prose) · Author · Dated. A "New statement" primary button. Reachable from any
CVE row in the SBOM spine.

### 6. Attestation

**Purpose:** the deliverable. The CISA SSDF form, auto-populated from real evidence, printed to PDF and
attached to contract packages.

Max width 1080px. Header: a 10px uppercase kicker naming the standard, the project at 30px, and a
sub-line carrying client, generation time, build and **the policy that produced the score** — bound to
the same source as the score itself. Buttons: "Print" and "Export…".

Summary card: the headline, four count tiles (Yes / Partial / No / Manual), each with a glyph
(`✓ ◐ ✕ ○`) so the tally survives monochrome, and the note *"Manual practices are not failures — they
require the signatory's own attestation from artefacts outside this tool."* A right rail carries the
build stamp: commit, version, built, risk score and band, gates (derived), policy.

Then the 22 practices in four family cards (PO, PS, PW, RV), each row a practice id (monospace bold),
a status chip, and a stack of label, intent and the evidence string. Status chips: Yes solid accent,
No solid `--color-accent-900` with bold text, Partial outlined, Manual outlined neutral.

Footer: the signatory attestation paragraph and three signature rules — Name and title, Signature, Date.

**Export dialog** (660px): three format cards with radio marks — **OSCAL** (NIST OSCAL 1.1.2 JSON, with
a model picker: Assessment results / POA&M / Both — bundle, where a bundle emits both models with
shared UUIDs so POA&M items resolve against the findings the assessment cites), **Generated PDF**
(Letter or A4, signatory block included), and **Raw JSON** (the tamp.findings schema, including the
gate evaluation and category breakdown). The selected format's description and exact output filename
are shown, and the footer notes that exports are recorded in the audit log.

### 7. Policy & gates

**Policy library** across the top: one card per policy showing name, schema version, kind, how many
projects use it, and a note. Actions: Duplicate…, Rename, Delete, New policy. Selecting a policy loads
**its own category set** — Tamp Standard v1 (schema 1) has no DAST categories at all; a kiosk policy
ships with DAST and coverage disabled. Selecting also resets pending edits.

**Left — the category editor.** Header states the enabled basis and that weights are relative. Rows:
enable checkbox, category label over key, an editable weight input, the computed effective max, and the
sub-weights. Effective maxima recompute live as weights change and as categories are switched on and
off — *that is why a category's ceiling is not a fixed number*, and demonstrating it is the point of
the screen.

**Right — gates and bands.** Every gate from the domain's gate key list with an enable checkbox, its
key in monospace, a plain-language description, and an editable threshold where one applies. Below,
the four bands, each with a colour swatch and an editable upper boundary (red is fixed at 100). Then
Save policy / Discard changes / Preview rescore, with an `unsaved · 1 project rescores` warning.

**Read-only enforcement:** on a system policy, every input is genuinely disabled, the toggles do not
respond, Save and Discard are disabled, and a line explains why. **Delete is blocked** while a policy
is in use: Confirm is disabled with the reason, and the dialog offers a "move projects to" picker.

### 8. Project settings

Three tabs: **Ingest tokens** (name, masked token, scopes, created, last used, expires, state, with
rotate and revoke; a "Generate token" button revealing the value once in an accent panel headed
`COPY IT NOW — THIS VALUE IS NOT STORED AND WILL NOT BE SHOWN AGAIN`, plus a curl example showing the
required headers), **Disclosure policy** (policy URL, security contact, reporting form — with the note
that a published policy URL flips SSDF RV.3.1 from Manual to Yes while a contact email alone caps it at
Partial), and **Account** (identity, session, default scope, sign out).

### 9. System administration (instance level)

Five panels behind a tab strip, under the heading *"Instance-wide settings — outside any client or
project scope. Changes here affect every tenant on this deployment."*

- **Users & RBAC** — see the RBAC section below.
- **Authentication** — identity providers (GitHub OAuth, generic OIDC, SAML, local password) with kind,
  state, user counts and configuration, plus rotate/disable actions and an "Add provider" button.
  Sign-in policy: allowed email domains, session lifetime, what new users default to (Viewer — read
  access, no role), and MFA requirements per role.
- **Scanners & ingest** — the registry of accepted scanners with class, ingest format, state and last
  received. A registered-but-never-seen scanner is what makes "no scan" distinguishable from "clean",
  so registration is a first-class action. Below: advisory feed status (CISA KEV, OSV, licence tiers).
- **Instance settings** — instance URL, database, finding retention, build retention, session lifetime,
  outbound email, telemetry (off — self-hosted means self-hosted), version.
- **Audit log** — append-only: when, actor, action, scope, and a class chip (`risk` in `#e2894a`,
  `access` in accent, others neutral). Risk acceptance, role grants and key changes are what an
  assessor reads first.

---

## RBAC model

The three named roles are the codebase's existing `ProjectRole` enum
(`InfoSecOfficer = 1`, `LeadDev = 2`, `Architect = 3`). Admin is the instance-level `User.IsAdmin`
flag. **Viewer** is the implicit default for a user with read access and no role. **Auditor** is
proposed and does not exist in the model yet — implement it as a fourth `ProjectRole` value.

**Roles are additive.** A user holds any number of them, and effective access is the union. This is
deliberate: a three-person team should not be forced into an org chart it doesn't have.

Assignments are scoped to client, project or component (`ProjectRoleAssignment` already carries all
three), and the narrower grant wins where they overlap.

### Proposed capability matrix

`✓` full · `◐` conditional · `—` denied

| Capability | Admin | InfoSec | Lead Dev | Architect | Auditor | Viewer | Condition |
|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| View findings, evidence and attestation | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| Export attestation JSON / PDF | ✓ | ✓ | ✓ | ✓ | ✓ | — | the auditor's whole job |
| Author rule suppressions | ✓ | ✓ | ✓ | ✓ | — | — | reason required |
| Author VEX statements | ✓ | ✓ | ◐ | ✓ | — | — | Lead Dev drafts; InfoSec publishes |
| Create / edit POA&M items | ✓ | ✓ | ✓ | ✓ | — | — | |
| Close a POA&M as Completed | ✓ | ✓ | ✓ | ✓ | — | — | needs a verifying build |
| Set a POA&M to Risk accepted | — | ✓ | — | — | — | — | AO decision — InfoSec only |
| Edit risk policy weights | ✓ | ✓ | — | ◐ | — | — | Architect may duplicate, not edit in place |
| Edit acceptance gates | ✓ | ✓ | — | — | — | — | gates are the release contract |
| Create / edit projects | ✓ | — | — | ✓ | — | — | |
| Create / edit components | ✓ | — | ✓ | ✓ | — | — | |
| Set / recycle the project ingest key | ✓ | ✓ | ✓ | — | — | — | recycling breaks CI until redeployed |
| Assign roles within scope | ✓ | ◐ | — | — | — | — | at or below their own scope |

Note that **Admin cannot accept risk** — that is an Authorizing Official decision, not a systems
privilege.

### Separation of duties

Conflicting combinations are **flagged, not blocked**, by default:

- Lead Dev + InfoSec Officer — remediates and accepts risk on the same finding
- Architect + InfoSec Officer — authors the waiver and approves it

The flag is recorded on the assignment so an assessor can see it was a deliberate choice rather than an
oversight. A single instance-level switch, *Enforce separation of duties*, turns the advisory into a
refusal for larger programs. Default off.

### RBAC UI

A People table (user, role chips, scope, SoD flag) where selecting a person adds an **Effective**
column to the capability matrix — the union of their roles — and dims the roles they don't hold. Below
it, the granular assignments table (user, role, tier, scope, granted by, since, revoke). The grant
dialog is multi-select: pick every role the person actually performs, set tier and scope, and see the
SoD advisory inline before granting.

---

## Interactions and behaviour

- **Navigation** is screen state today; implement as routes. Sidebar, tab strip, breadcrumb and every
  drill affordance change the URL.
- **Hover:** rows take a 5–6% ink tint; nav items and menu items take a 7% tint; buttons follow the
  design system's accent-ramp hover.
- **Focus:** `:focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }` — never
  the browser default.
- **Dialogs:** fixed overlay at `rgba(8,10,12,0.62)`, centred, blueprint frame on
  `--color-neutral-100` with `--shadow-lg`. Escape closes; the × closes. Scroll goes on an inner
  wrapper (see the POA&M dialog note).
- **Destructive actions** always state the consequence in plain language and offer the non-destructive
  path beside the destructive one.
- **Secrets** (ingest tokens, project keys) reveal exactly once, in an accent panel that says so.
- **Empty and never-scanned states** are distinct from clean states, everywhere, always.

## State

| State | Purpose |
|---|---|
| Route: client / project / component / build / spine / selection | Replaces every `useState` tab switch; drives deep links |
| Density (comfortable / compact) | Persona-dependent row density |
| Show deltas | Per-build comparison on or off |
| Policy draft: selected policy, weight overrides, threshold overrides, band overrides, dirty flag | Live recomputation of effective maxima and score before saving |
| Enabled category / gate overrides | Same |
| Dialog state: POA&M create-edit, entity create-edit, confirmations, role grant, export, key recycle | One at a time |
| Selected user for the RBAC effective-access column | Read-only view state |
| Instance: enforce separation of duties | Deployment policy |

In Blazor, most of this is ordinary component state; the scope route parameters and the policy draft
are the two pieces worth lifting into scoped services so several components can read them.

The only genuinely new computation is the ranked score breakdown — points, effective maxima against the
enabled basis, and the saturation flag. `RiskScorer` already produces it server-side; expose it per
category rather than recomputing it in the UI. Sharing the domain types directly with the UI is the
main reason this port is worth doing: the "9 gates enabled" string that contradicted a computed 10 was
a DTO-drift bug, and it stops being possible.

**Render mode.** Prefer Server for the dense screens: the policy editor recomputes effective maxima on
every keystroke and the explorer tree re-renders on selection, and both are chatty over SignalR only in
the sense of small diffs. Two screens need attention regardless of mode:

- **Explorer trees and tables** — coverage runs to thousands of files, findings to 5,000 rows. Wrap
  both panes in `<Virtualize>`; do not render a full tree.
- **Source viewer** — tokenize server-side in C# (Roslyn is already a dependency) and render spans,
  rather than shipping a JS highlighter. Line rows are fixed-height, so they virtualize cleanly.

## Workflow (Elsa)

Elsa owns the transitions that need approval, delay, or an audit trail — the places where this design
shows a status change that is really a process. The UI should render workflow state, not re-implement it.

**Transitions to model as workflows:**

| Transition | Why it is a workflow |
|---|---|
| POA&M → **Risk accepted** | An AO decision. Needs a request, an approver who is not the requester, and a recorded rationale. The capability matrix already restricts it to InfoSec Officer; Elsa makes the approval itself auditable. |
| POA&M → **Completed** | Should wait on a verifying build rather than a button. The workflow closes the item when a canonical build shows the weakness gone. |
| **AO extension request** | The "Request AO extension" action on the POA&M record: a request, an approval, and a new scheduled completion date. |
| VEX **draft → published** | The matrix has Lead Dev drafting and InfoSec publishing. That is a two-step approval, not a permission check. |
| **POA&M due-date reminders** | Scheduled: fires ahead of the scheduled completion date and again when an item goes past due. The `poamPastDue` gate reads the same dates. |
| **Gate failure notification** | Triggered on ingest when a canonical build fails a gate. |
| **Attestation sign-off** | Generate → route to the signatory → record the signature and freeze the evidence snapshot. Today the design ends at a printed signature block; this is the natural next step. |
| **Ingest key recycling** | Optional grace period: issue the new key, keep the old one valid for a window, notify, then revoke. Removes the "breaks CI immediately" hazard the design currently warns about. |

**UI consequences — small, but real:**

- Statuses gain **pending** states. A POA&M awaiting risk-acceptance approval is neither Open nor Risk
  accepted; render it as its terminal-status chip with a monospace `pending approval` qualifier beside
  it, and disable the actions that would race the workflow.
- Anything awaiting *this* user shows up as an action, not a notification — an "Awaiting you" filter on
  the POA&M table is enough; no separate inbox screen.
- The audit log gains workflow entries. It already classifies `risk` and `access` events; approvals
  belong in `risk`.
- **Where Elsa Studio lives.** If workflow authoring is exposed to users at all, put it under the System
  layer as its own panel — instance-level, alongside Authentication and Scanners. It is not project
  scope. Because Studio is MudBlazor-based, mount it on its own route so its CSS and theme do not leak
  into the rest of the app; do not try to make it look like these screens. Most deployments will not
  need it: ship the workflows as definitions and expose only their *state* in the screens above.

## Assets

None. No images, no photographs, no custom illustration.

Icons are **lucide at stroke-width 1.5**. There is no official Blazor package and none is needed —
lucide icons are plain SVG. Vendor the ~20 glyphs this design uses as a static asset or a small
`<Icon Name="..." />` component wrapping inline SVG on `currentColor`. Do not substitute a Material or
Fluent icon set; the stroke weight is part of the aesthetic.

The severity ladders, status marks and registration corners are text glyphs and CSS, not assets.

## Files

| File | What it is |
|---|---|
| `Tamp Findings Redesign.dc.html` | The full prototype — all screens, states and dialogs |
| `industry.css` | The design system stylesheet the prototype consumes (light palette; the prototype overrides it with the dark values documented above) |
| `github.md` | Repository association and the screen → source-file map |

A light-ground variant of the prototype exists in the project as
`Tamp Findings Redesign (light).dc.html`, from before the dark direction was chosen. It is not part of
this handoff.

## Screen → source map

Two columns: the **React file to read** for existing behaviour and API usage (being retired, but it is
the working reference), and the **server-side source of truth** that carries over unchanged. Blazor
component paths are a suggestion, not a requirement.

| Screen | Read for behaviour (React, retiring) | Carries over unchanged |
|---|---|---|
| Shell, routing, sidebar | `web/src/App.tsx`, `components/DrillBreadcrumb.tsx` | — (routing is new; Blazor's router replaces the `useState` tab switch) |
| Project hub | `views/ProjectPageView.tsx`, `components/RingChart.tsx` *(retired — the rings are what this redesign removes)*, `components/BuildReceiptsPanel.tsx` | `Domain/Risk/RiskScorer.cs`, `GateEvaluator.cs`, `Api/Services/RiskInputsBuilder.cs` |
| Explorer (5 spines) | `views/FindingsView.tsx`, `DastView.tsx`, `ComponentsView.tsx`, `CoverageView.tsx`, `TestsView.tsx` — all five collapse into one shell | `Domain/Entities/Finding.cs`, `SbomComponent.cs`, `CoverageReport.cs`, `TestRunReport.cs`, `Values/DastRoute.cs` |
| Severity treatment | `components/SeverityBadge.tsx`, `SeverityCountsBar.tsx` | `Domain/Values/Severity.cs` |
| POA&M | `components/PoamItemsPanel.tsx` | `Domain/Entities/PoamItem.cs` (+ Elsa: approval, verification, reminders) |
| VEX | `components/VexStatementsPanel.tsx` | `Domain/Entities/VexStatement.cs` (+ Elsa: draft → publish) |
| Attestation + export | `views/AttestationView.tsx` | `Api/Endpoints/SsdfAttestationEndpoints.cs` (+ OSCAL emitters, + Elsa: sign-off) |
| Policy & gates | `components/RiskPolicyEditor.tsx` | `Domain/Risk/RiskPolicyDefaults.cs`, `ProjectGatesConfig.cs`, `Entities/RiskPolicy.cs` |
| Project settings / keys | `components/ProjectSettingsDialog.tsx` | `Domain/Entities/IngestToken.cs`, `Api/Endpoints/ProjectVdpEndpoints.cs` |
| System · RBAC | `views/SettingsView.tsx` | `Domain/Values/ProjectRole.cs`, `Entities/ProjectRoleAssignment.cs` |
| System · auth | `lib/auth.tsx`, `views/SignInView.tsx` | ASP.NET auth pipeline — cookie auth server-side rather than a token the SPA has to carry |
| System · scanners | — (new) | `Domain/Values/ScannerKind.cs`, `ScannerKinds.cs`, `Entities/ScanRunReceipt.cs` |
| System · audit log | — (new) | new; Elsa workflow history is one of its inputs |

**Port order.** Shell and routing first (deep links are the headline fix and everything else hangs off
them), then the project hub, then the explorer shell with the SAST spine, then the remaining four
spines, then POA&M, attestation, policy, and the System layer last.

## Not covered

Deliberately out of scope in this pass, and worth a follow-up:

- The client page and the create-hierarchy flow
- Sign-in and first-run (first user becomes Admin)
- Suppressions as their own surface — they exist in the model and are only referenced here
- Provenance upload (SLSA / in-toto / DSSE) — the artefact that flips SSDF PS.2.1 from Partial to Yes
- Flavor comparison: one commit producing `net10`, `web` and `deployed` builds side by side
- The MCP server surface
- Mobile and narrow-viewport behaviour — this design assumes a 1180px desktop floor
- Elsa authoring UI beyond the placement note above, and the approval screens for the workflows listed

## Version

Design revision: 2026-08-22. Target: Blazor on .NET 10 with Elsa. Regenerate this package whenever the
prototype changes substantively — the prototype in this bundle is the authority for anything this
document does not state.
