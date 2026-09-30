# Handoff: tamp.findings redesign v3 — portfolio, project, evidence, policy

## Overview

Third redesign pass of tamp.findings, the self-hosted security and compliance evidence dashboard (`tamp-build/tamp-findings`). This pass reworks the **portfolio**, the **project dashboard**, adds a **detail page for every risk category**, a unified **evidence** surface (collected evidence, SSDF attestation evidence, ADR conformance), a **control catalog / frameworks** screen, and a **three-layer policy system** (template → client → project, harden-only).

It supersedes the relevant parts of `design_handoff_tamp_findings/` (v2). Where the two disagree, this document wins. Screens not covered here (explorer, POA&M editor, VEX editor, attestation, System panels) are unchanged from v2.

## About the design files

`Tamp Findings Redesign.dc.html` is a **design reference built in HTML** — an interactive prototype showing intended layout, copy and behaviour. It is not production code. Recreate it in the real stack:

- **Blazor on .NET 10**, Razor Class Library `Tamp.Findings.Web` hosted by `Tamp.Findings.Api` (ADR 0002).
- **All reads and writes go through `Tamp.Findings.Application`.** No component decides authorization; `Web` must not reference `Api` (ADR 0002 §1–2).
- **Elsa is gone** (ADR 0005). Scheduled work is hosted `BackgroundService` workers; approvals are `PendingApproval` rows. The root `CLAUDE.md` and the v2 README still say "Blazor + Elsa" — update both.
- **Hand-rolled primitives**, no Blazor component library. Square corners, hairline borders. Icons are lucide at stroke-width 1.5, inline SVG on `currentColor`.
- **Localization:** every user-facing string in this README and the prototype goes into `.resx` via `IStringLocalizer`. Markup inside a string uses numbered placeholders. Design for 40 % text expansion (chips, table headers and nav items must wrap or grow, never truncate).
- **Reflow (ADR 0003):** no global `min-width`. The body never scrolls horizontally at 320 px. Wide tables and code blocks scroll inside their own `overflow-x: auto` container. The prototype already follows this.

Open the prototype directly in a browser (it needs `support.js` beside it). A Tweaks toggle **Portfolio only** (on by default) limits navigation to the screens in this pass.

**All data in the prototype is mock** except the tamp-findings project dashboard, which was taken from the live `/c/BrewingCoder/p/tamp-findings/build/latest` page. Every number, finding, CVE id, rule and name elsewhere is invented to exercise the layout. Wire every screen to real Application-layer queries.

## Fidelity

**High fidelity.** Colors, type, spacing, copy and interaction states are final. Recreate them exactly, using the tokens below.

---

## Global conventions

### Shell
- Left sidebar (dark), main column. No editor-style tab strip (removed this pass).
- Header bar shows the route path. On Portfolio, project dashboard, category, evidence, frameworks and policy screens the commit/branch/framework build stamp is **hidden**.
- Breadcrumb on every drill-down: `Portfolio / <project> / <page>`, 11 px, links in `--color-accent-700`.

### Sidebar
Groups, in order: Portfolio · Scope (Project hub) · Explore · **Evidence** · Project admin · **Manage** · System · instance.
- On Portfolio, only Portfolio, Manage and System show; project groups appear once a project is open.
- **Evidence is collapsible** (▾/▸ on the group header). Collapsed, the header shows `N of M failing` (count of items with ≥1 failure — never a sum of mixed units).
- Every Evidence item shows **`fail/total`** right-aligned, monospace 10 px. Red `#e06a6a` bold when fail > 0, `--color-neutral-500` otherwise, `—` when not applicable. On the active (highlighted) row the count uses `--color-bg` so it stays legible.
- Manage: **Clients** (client policy), **Projects**, **Policy templates**. System adds **Control frameworks**.

### Severity encoding (unchanged from v2, must survive B/W print)
Glyph ladder + letter + color. `Critical ▰▰▰▰▰ C #dd5f5f` · `High ▰▰▰▰▱ H #e2894a` · `Medium ▰▰▰▱▱ M #d4bb4a` · `Low ▰▰▱▱▱ L #7db3de` · `Info ▰▱▱▱▱ I #949aa3`.

### Score bands
`green #4fb783` · `yellow #d4bb4a` · `orange #d68f42` · `red #dd5f5f`. Cut-offs come from the policy template: green < 10, yellow 10–25, orange 25–40, red ≥ 40. Lower score is better. The band name is always written, never color alone.

### Status marks (evidence tiles, receipts)
`✓ ok #4fb783` · `! warn #d4bb4a` · `✕ bad #dd5f5f` (only when an **enabled gate is failing**) · `— missing #e2894a` (dashed border) · `n/a` neutral-500. A red ✕ must mean "blocks ship"; anything that needs attention but is not gated is amber `!`.

---

## Screens

### 1. Portfolio (`/portfolio`)
**Purpose:** see every project's posture and open one.

- Title "Portfolio" (Barlow Condensed 30 px). "New project" button (primary). **No "New client" button** — clients are managed under Manage.
- Filter row: **Client** `<select>` ("All clients (N)" + one option per client with count), right-aligned `"X of Y projects · click a column to sort"`.
- Table columns: **Project** (heading font 15 px 600) · **Client** · **Score** · **30-day trend** · **Band** · **Ship** · **Blocking** · **Last build** · Actions.
  - **Score:** Barlow Condensed 600 **30 px**, line-height 1, colored by band, tabular numerals, right-aligned.
  - **30-day trend:** 96×24 sparkline (1.5 px stroke, 2 px end dot) + arrow and signed delta, monospace 11 px. Lower is better: **▼ green** = improving, **▲ red** = worsening, **— grey** = flat or no scans ("no scans"). Hover title: `30 days: 14.9 → 18.4 (worsening)`.
  - **Blocking:** one blocker per line; column is `width: 1%; white-space: nowrap` so it takes only what its longest line needs; the row grows vertically.
  - **Attestation column removed** (lives on the project page now).
- Sorting: click any sortable header (Project, Client, Score, Band, Ship, Last build). Default sort is **Client ascending**, ties by name. Clicking the active column reverses it; active header is `--color-accent-700` with ▲/▼.
- Row click → project dashboard.

### 2. Project dashboard (`/c/{client}/p/{project}/build/latest`)
Built from the live tamp-findings page. Sections top to bottom:

1. **Header:** "← Portfolio", 34 px initials square, project name (30 px), `<Client> · policy <name>` (no wrap on the policy name).
2. **Row (auto-fit, stacks below ~1000 px):**
   - **How are we trending** — score 46 px band-colored, band chip, delta vs prior build; 220×44 trend of recent builds with `▼/▲ n over N builds`. **Ranked category table** (grid: Category · Contribution bar · Pts/max · Evidence), sorted by points desc. Rows with a detail page are clickable; their label is `--color-accent-700`. **No "details →" text.**
   - **Can this ship** — verdict chip: `✓ Clear to ship` (green outline) / `✕ Blocked` (red fill) / `— No recent scan`. Sub-line, then the list of **enabled gates** each with a PASS/FAIL mark and observed value, then "Configured but disabled: …".
3. **Row:** ~~Components table + "New component"~~ _(removed — the Component tier was collapsed in TFND-205; the hierarchy is Client → Project → Build, so there is no per-project Components table)_; Project ingest key (masked key + Recycle, or dashed "No ingest key has been issued" + Issue key).
4. **Evidence · <commit>** — tiles (auto-fill, min 190 px) for ADR conformance, Dynamic scan, KEV exposure, Design & quality, Accessibility, Base image age, POA&M due dates. Each: label (accent-700, heading 15 px), status mark, one-line status, and a gate line: `✕ blocks ship` / `gated · passing` / `gate disabled` / `not gated` / `would block · not gated` (conformance under advisory). Top border 2 px in status color.
5. **Attestation evidence · SSDF** — tiles for Release provenance (PS.2.1), Disclosure policy (RV.3.1), VEX & risk acceptance (RV.3.2). Gate line shows `PS.2.1 · Yes|Partial|No`. Note: "These do not gate a build. They decide how the attestation answers."
6. Scan receipts, Container image, Build history (as v2).

### 3. Category detail pages (`…/build/latest/score/{key}`)
One page per scored category. Shared frame: breadcrumb, title + key, points `46 px` (red if saturated, orange if > 0) with `/ max` and a `SAT` tag when saturated, **Current / History tabs** (2 px accent underline on active). Current always opens first.

"How this category scores" panel shows the **count × weight = subtotal** math, raw total, and whether it is under or capped at the category max. Chips summarise counts. **Weights and caps shown are placeholders** — read them from `RiskPolicyDefaults` / the effective policy.

| Key | Current tab | History tab |
|---|---|---|
| `sastSevere` | Findings table (sev, title+rule+CWE, file:line, first seen, status, `✕ blocks`) + sticky detail panel: message, code snippet with highlighted line, Raise POA&M / Accept risk / Open in explorer | Closed findings |
| `cve` | "Fix these first" packages ranked by points removed on upgrade (installed → fixed, eco, bar) + CVE table (sev, id, pkg, CVSS, EPSS, VEX) + detail panel (fixed in, introduced via, KEV, VEX, score impact; Write VEX / Raise POA&M / Open in SBOM) | Closed findings |
| `coverage` | Measured sequence + branch coverage, gauge with target mark, formula `max × (1 − cov ÷ target)`, least-covered files table | **Coverage % per build only** (chart with dashed target + table with Δ) |
| `secrets` | Candidates table (type+detector, location+redacted match, first seen, verification chip) + detail panel (line, entropy, score impact, "Deleting the line does not remove the secret from git history"; Mark revoked / False positive / Allow-list path). Chips "By verification": verified × 5.0, unverified × 1.5, test path × 0 | Closed findings (Revoked & rotated, Removed from history, Test fixture, False positive) |
| `sbomStaleness` | Formula, stat tiles, most-drifted components (shipped → latest with dates, major/minor tag, libyears, pts) | Closed (Upgraded, Removed, Pinned · accepted) |
| `sastLow` | Grouped **by rule** (not per finding): sev, rule, count, pts, bar + panel with up to 6 instances, Mute rule (audit-logged, separate from VEX) | Closed |
| `missingScanners` | Receipts required by policy: class, tool, CI job, this build, last received | **Receipts-by-build grid** (✓ / — / n/a) |
| `tests` | Only failing, flaky and skipped — **no totals, no pass rate**. Failing (message, failing since, streak) · Flaky (record, suspected cause) · Skipped (reason, who, age; > 30 d red). Weights: failing 1.0, flaky 0.3, skipped 0.1 | Failing/flaky/skipped per build |
| `iacSevere` | Same layout as sastSevere (framework · resource as the rule sub-line) | Closed |
| `license` | Licence mix stacked bar colored **by policy class**, policy card (allowed/review/denied), Needs attention table (component + path, SPDX, class, evidence, pts); Request exception / Export NOTICE | Closed (Replaced, Licence clarified, Exception granted, Removed) |

History (findings categories): 4 stat tiles (closed 90 d, fixed, accepted/excepted, median time to fix — fixed includes Revoked & rotated, Removed from history, Upgraded, Removed, Replaced, Licence clarified), a 90-day points chart **clamped to the category cap** whose direction matches the project's build trend, and a closed-findings table with resolution filter chips.

**Empty states:** if the scanner feeding the category did not run → orange dashed `— Not scanned` ("A missing scan is not a clean scan"). If it ran clean → green `✓ Nothing found`. Never show green for an absent receipt.

**Known model gaps vs code** (decide before building): the prototype's SBOM staleness uses **libyears**; the code counts outdated components (> 180 d). Tests' flaky/skipped need per-test outcomes the code does not ingest yet. Licence weak-copyleft scoring (0.05) is not in `LicensePolicy`. IaC only scores Trivy.

### 4. Evidence detail pages (`…/build/latest/evidence/{key}`)
Shared frame: breadcrumb, title, sub-line, **gate line** (e.g. "Fails the Missing scanners gate · blocks ship", "POA&M past due gate is configured but disabled", "Answers SSDF PS.2.1 in the attestation · currently No"), status chip (right), Current / History tabs, stat tiles, meta note, a generic table, note, actions.

| Key | Gate / practice | Content |
|---|---|---|
| `dast` | Missing scanners | ZAP alerts (sev, alert+CWE, where, instances, status); target, mode, URLs, duration. If the current build has no receipt, show last received results and say so. History: receipt + counts per build |
| `kev` | KEV exposure | CVEs checked, matches, catalog version/date; watch-list of top-5 EPSS not on KEV |
| `quality` | — | Spectral, oasdiff, NetArchTest, Stryker, ReSharper, ESLint, dependency-cruiser: checks, result, pass/warn/fail/n/a |
| `a11y` | — | axe-core violations **by rule** (impact, rule+note, WCAG SC, pages, nodes). N/A for API-only; "Manual review required" for non-web UI |
| `baseImage` | Base image age | Per image: component, image, base, age at build (> 90 red, > 30 yellow), OS (EOL red). Age measured **at build** |
| `poam` | POA&M past due | Open items (id, weakness + 800-53 control, from, owner, due with "n days overdue", status). History: closed items with on-time/late |
| `provenance` | PS.2.1 | Per artifact: digest, predicate, builder, signer, verified/untrusted |
| `vdp` | RV.3.1 | Client-level policy fields (URL, security.txt, contact, form, response time, safe harbor) with daily checks; subtitle "…for <client>, inherited by <project>" |
| `vex` | RV.3.2 | VEX statements + unexpired risk acceptances in one table; CVE ids resolved from the project's CVE list |
| `conformance` | ADR conformance | See §5 |

### 5. ADR conformance (evidence key `conformance`)
Source: `conformance.evaluated` events (core ADR 0023). Each finding: `adr_ref`, `rule_id`, **four-valued verdict**, `adr_quote`, `code_evidence`, `location`, `method` (deterministic | semantic | verify), provenance (`commit_sha`, `rules_sha`, `model_id`, `verify_verdict`), `control_refs`.

- **Verdict chips — never collapse to pass/fail:**
  - `✓ PASS` green 1 px outline, sub "clear"
  - `✕ FAIL` red **fill**, sub "blocks · fix the code"
  - `? UNKNOWN` amber **dashed** border, sub "blocks · no answer" — never green
  - `! ERROR` **3 px double** neutral border, sub "blocks · evaluation broke"
  - Dispositioned fail: `✕ FAIL` red **outline** (not fill) + `⊘ DISPOSITIONED WITH JUSTIFICATION` panel
- Summary tiles in the same five styles; run line: `conformance.evaluated · commit · rules sha (adr ref) · N rules · n deterministic, m semantic · frozen <ts>`.
- **Controls filter row**: chips `CM-6 · 4`; clicking filters the list and opens the **control statement panel** (below).
- **Finding card:** verdict chip | claim (heading 16 px), `rule · ADR nnnn · title`, file:line | method badge (`≡ DETERMINISTIC` solid, `~ SEMANTIC · <model>` dashed) + verify badge (`✓ verify pass confirmed` / `✕ disputed` / `○ not run`; hidden when there is no verdict to verify) + control chips.
  - FAIL / dispositioned: **ADR quote and conflicting code side by side, always visible** (auto-fit min 320 px, stacks). Code block highlights the line in 20 % red.
  - UNKNOWN: ADR quote + "Why there is no answer" + remedy (different from fail: re-anchor rule / fix pipeline).
  - ERROR: error text + remedy ("Operator alerted"). The last good verdict is not carried forward.
  - PASS: collapsed; "show evidence" expands the satisfying code line.
  - Footer: `id · commit · rules · model · verify · verdict frozen <ts>` (or `recomputable` for deterministic).
- Dispositioned panel: id, `status: accepted_deviation`, justification, accepted by + role (**InfoSec · AcceptRisk**), date, expiry, POA&M. Reuses the VEX/suppression disposition flow; the finding stays listed.
- **Undocumented decisions · advisory** (reverse examination): dotted steel box, `◇`, "Never gates a build", Draft ADR / dismiss.
- Enforcement: tamp-findings runs advisory, so the tile and header read "would block · not gated" (ADR 0004).
- History: per build ✓/✕/?/!/⊘ counts + rules sha.

### 6. Control statement panel and Control frameworks
**Control statement panel** (opens on any control chip): id (mono 14 px bold), title (heading 18 px), family, FedRAMP Low/Moderate/High chips (member = accent outline; not a member = struck through), statement lines (lettered items indented 14 px), **organization-defined parameters** as dashed accent chips — a `[Selection …]` containing nested `[Assignment …]` is **one** chip (depth-counting parse, not regex). Footer: catalog source + import date, the project's frameworks, "manage frameworks" link.

**System · Control frameworks** (`/system/frameworks`):
- **Control catalog** card: NIST SP 800-53 Rev 5.2.0, OSCAL 1.2 JSON, imported date + sha, source (usnistgov/oscal-content or file upload for air-gapped), retained prior versions (attestations cite the catalog version they were signed against). Check for update / Import file.
- **Frameworks** table: name + version, how it got here (`OSCAL import` solid / `Curated` dashed / `Overlay` dotted), controls, parameters, used by, status.
- **Where frameworks apply** (per client; projects add, never drop).
- **Add framework · three ways** cards with +/− trade-offs: Import OSCAL profile (NIST, FedRAMP — recommended), Curate from the catalog (GovRAMP — no OSCAL), Link-only (not recommended for evidence).
- **GovRAMP is a profile over NIST 800-53 Rev 5, not a separate catalog.** Control counts, FedRAMP membership in the prototype are from memory — compute from the imported profiles.

### 7. Policy — three layers, harden-only
**Model:** `Template (library, versioned)` → `Client (picks one template + hardening layer)` → `Project (hardening layer)`. Each lower layer can only **add** rules or **tighten** thresholds. Effective value = strictest across layers; record which layer supplied it.

Layer content: enforcement mode (advisory < enforcing), required scanners, 18 acceptance gates (`on`, threshold — lower is stricter), denied licences, POA&M deadlines by severity, score bands (template only), frameworks.

Gate keys: riskReg, kev, anyCve, critCve, highCve, critSast, highSast, critDast, highDast, critIac, verSecrets, deniedLic, baseAge (days, step 15), testFail, covReg (pts, step 0.5), poamPast, missing, adrConf.

**Screens (one component, three modes):**
- **Manage → Policy templates** (`/manage/policy-templates/{id}`): template picker cards (`used by N clients`). Editable both ways; anything looser than saved shows `⚠ loosened` (amber dashed) and the save button becomes **Submit for approval** (InfoSec). Gates table has a "Hardened below" column. Table of clients using the template.
- **Manage → Clients** (`/c/{client}/policy`): client picker, **Template `<select>`** + "open template". Harden-only against the template. Switching template requires approval. Table of projects under the client.
- **Project → Policy & gates** (`/c/{client}/p/{project}/policy`): "Inherits template **X**, hardened by client **Y**." Count tiles Inherited / Hardened / Added / **Loosened (always 0)**.

Row states (monospace 10 px chips): `🔒 <source layer>` inherited · `↓ hardened` green · `+ added` accent · `off` dashed · (template only) `⚠ loosened` / `↓ tightened`.

Controls: 15 px square checkbox (🔒 when inherited-on, not clickable); − / + 22 px steppers. **+ is disabled at the inherited value** with tooltip "Cannot loosen past <layer> (≤ n)". Mode segmented control strikes through modes looser than inherited. Inherited scanner/licence chips are locked; own additions toggle/remove. Sticky save bar: note, Discard, Save / Submit for approval.

Save notes (copy): project — "Hardening applies on the next evaluation and needs no approval. Every change is written to the audit log." Client — "Hardening applies to all N projects under <client> on their next evaluation. No approval needed." Template loosen — "This loosens the template for N client(s), so it goes to InfoSec for approval. Clients and projects that hardened keep their stricter values."

Authorization: loosening a template and switching a client's template create a `PendingApproval` requiring the InfoSec AcceptRisk capability, enforced in Application (ADR 0002, ADR 0004 §5). Enforcement mode follows ADR 0004's locked floor. **Risk scoring weights are not yet in templates** — v2's policy editor still owns them; fold them in with "harden = raise weight/cap only".

---

## Interactions summary
- Portfolio row → project; category row → category page; evidence tile or sidebar item → evidence page; control chip → filter + statement panel; pivot links → other evidence for that control.
- Tabs reset to Current when a page is opened from elsewhere.
- Pass rows on conformance expand/collapse. Findings/CVE/secret/rule rows select into the sticky detail panel (first row selected by default).
- Sidebar Evidence collapse state is per-user UI state.

## State (Blazor)
Per circuit: selected project, category key + tab + selected row, evidence key + tab, conformance control filter + expanded rows, portfolio client filter + sort column/direction, sidebar collapsed groups, policy draft per layer (unsaved edits keyed by `t:/c:/p:` id). Everything else is read from Application query services.

## Design tokens (dark theme, `industry.css` + overrides in the prototype `<helmet>`)
- Ground `--color-bg #1e1f22`, surface `#252629`, text `#d7dae0`, accent `#4d9dd6`, divider `color-mix(#d7dae0 15%)`.
- Neutral ramp 100→900: `#202124 #2a2c30 #35383d #4a4e55 #8c9199 #949aa3 #aeb3bb #c6cbd2 #e2e6eb`.
- Accent ramp 100→900: `#16222e #1d2f40 #26425c #31577c #3f739f #5b9ed2 #7db3de #a2c9e9 #cbe1f5`. Paragraph-size accent text uses `--color-accent-700`.
- Status: ok `#4fb783`, warn `#d4bb4a`, bad `#dd5f5f`, missing `#e2894a`, sidebar fail count `#e06a6a`. Band orange `#d68f42`.
- Type: headings **Barlow Condensed 600**, body **Barlow**, code/numbers `ui-monospace`. Scale used: 30 (page title), 46 (category/score hero), 30 (portfolio score), 26–28 (stat tiles), 18 (panel titles), 15–16 (card titles), 12–13 (body), 11 (secondary), 10 (mono meta), 9 (uppercase section labels, letter-spacing 0.12–0.14em).
- Radius 0 everywhere. Borders 1 px hairline; dashed = missing/unknown/curated; dotted = advisory/overlay; 3 px double = error.
- Card padding 16×18; grid gaps 18 (sections), 12 (tiles), 10 (tight).
- Light theme: `Tamp Findings Redesign (light).dc.html` in the project root is from v2 and was not updated this pass.

## Assets
No images. Icons lucide 1.5 stroke. Glyphs used as encodings (must be in the font): ✓ ✕ ? ! ⊘ ◇ ≡ ~ ○ 🔒 ▾ ▸ ▲ ▼ ▰ ▱.

## Files
- `Tamp Findings Redesign.dc.html` — the prototype (logic class at the bottom holds all mock data: `PROJECT_DATA`, `CONF_DATA`, `EV_*`, `CONTROL_CATALOG`, `FRAMEWORKS`, `POLICY_TEMPLATES`, `CLIENT_POLICY`, `PROJECT_POLICY`, `POL_GATES`).
- `support.js` — runtime for the prototype only; not part of the product.
- `industry.css` — Industry design-system tokens (light). The dark overrides are in the prototype's `<helmet>`.
- `github.md` — source repo association and screen → source-file map.

## Suggested build order
1. Shell + sidebar (collapsible Evidence with fail/total), Portfolio.
2. Project dashboard wired to `ProjectHubQuery`.
3. Category detail frame + sastSevere, cve, coverage (establish the shared components), then the rest.
4. Evidence frame + the six collected-evidence pages, then provenance / VDP / VEX.
5. Policy three-layer model in Application (merge + harden-only validation + PendingApproval), then the three screens.
6. Control catalog import (OSCAL) + frameworks, then the statement panel.
7. ADR conformance ingest + screen.
Check every screen at 320 px (ADR 0003) and against the pseudo-locale before closing its ticket.
