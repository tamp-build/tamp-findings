# TFND-128 — parity record for retiring `web/`

The cutover ticket asks for one thing above all: *"Confirm parity: every route in `web/src/views` and
every panel in `web/src/components` is either ported or deliberately dropped, with the drops listed on
this ticket."*

This is that list. It is in the repo rather than only in YouTrack because the question it answers —
"where did X go?" — gets asked by someone reading the code, months later, who has no reason to open a
ticket first.

## Views

| React view | Where it went |
|---|---|
| `SignInView.tsx` | `Pages/SignIn.razor` (TFND-126) |
| `OverviewView.tsx` | `Pages/Portfolio.razor` (TFND-84) |
| `ClientPageView.tsx` | `Pages/ClientPage.razor` (TFND-127) |
| `ProjectPageView.tsx` | `Pages/ProjectHub.razor` (TFND-77 … TFND-83) |
| `ComponentsView.tsx` | `Project/ComponentsTable.razor`, on the hub (TFND-80) |
| `FindingsView.tsx` | The SAST spine (TFND-88) |
| `DastView.tsx` | The DAST spine (TFND-90) |
| `CoverageView.tsx` | The coverage spine (TFND-93) |
| `TestsView.tsx` | The tests spine (TFND-94) |
| `AttestationView.tsx` | `Pages/Attestation.razor` (TFND-100 … TFND-103) |
| `SettingsView.tsx` | Split: `Pages/ProjectSettings.razor` (project-scoped) and `Pages/SystemAdmin.razor` (instance-scoped). The split is the point — the old screen mixed the two, so a project setting and an instance-wide one looked alike. |
| `ProfileView.tsx` | The Account tab of `Pages/ProjectSettings.razor` (TFND-109) |

Two spines have no React ancestor at all: **SBOM** (TFND-92) and **POA&M** (TFND-95 … TFND-98) were
panels rather than screens, and **VEX** (TFND-99) and **Policy & gates** (TFND-104 … TFND-106) are
new surfaces.

## Panels

| React component | Where it went |
|---|---|
| `ScopeCard.tsx` | `Layout/Sidebar.razor`'s scope card (TFND-64) |
| `DrillBreadcrumb.tsx` | `Layout/AppHeader.razor` tab strip + `RouteScope` (TFND-65/66) |
| `RiskBadge.tsx` | `Project/ScoreCard.razor` (TFND-77) |
| `SeverityBadge.tsx` | `Primitives/SeverityBadge.razor` (TFND-87) |
| `SeverityCountsBar.tsx` | `Primitives/SeverityCounts.razor` |
| `BuildReceiptsPanel.tsx` | `Project/ScanReceipts.razor` (TFND-82) |
| `PoamItemsPanel.tsx` | `Pages/Poam.razor` (TFND-95) |
| `VexStatementsPanel.tsx` | `Pages/Vex.razor` (TFND-99) |
| `VdpPanel.tsx` | The Disclosure tab of `Pages/ProjectSettings.razor` (TFND-108) |
| `RiskPolicyEditor.tsx` | `Pages/Policy.razor` (TFND-105/106) |
| `ClientSettingsDialog.tsx` | The settings dialog on `Pages/ClientPage.razor` (TFND-127) |
| `ProjectSettingsDialog.tsx` | `Pages/ProjectSettings.razor` — a screen rather than a dialog, because it grew three tabs |
| `CreateHierarchyNodeDialog.tsx` | The New client / New project dialogs on Portfolio (TFND-85) |
| `LanguageSwitcher.tsx` | `Layout/AccountMenu.razor` |

## Deliberately dropped

**`RingChart.tsx`** (and `RingChart.test.ts`). Retired by TFND-78, which replaced the rings with a
ranked contribution table. The reason is in that ticket and worth repeating: a ring shows that a
category contributes without showing *how much* or *why*, and the four rings side by side invited a
comparison between categories whose maxima were not comparable. The table states the contribution in
points, names the evidence, and orders by what actually moved the score.

**`EcosystemBadge.tsx`**. Not dropped so much as absorbed: the SBOM spine GROUPS by ecosystem, so
every row under a heading shares one, and a per-row badge would have repeated the heading on every
line.

## Also removed with the directory

- The `web-build` Docker stage (Node 22 + pnpm). The image no longer contains a JS bundle, and the
  build is one SDK rather than two.
- `UseDefaultFiles()` and `MapFallbackToFile("index.html")` from `Program.cs`. An unmatched URL now
  reaches Blazor's `NotFound` — which renders inside the shell with the reader's navigation intact,
  rather than silently serving `index.html` for an address nothing answers, which is how a typo used
  to look like a working page that failed to load.
- The `spa` CI job.
- The preview auth bypass in `AuthEndpoints.cs`, which the ticket required not outlive the port. It
  was removed earlier, when the user confirmed it was no longer needed.

## Found afterwards (TFND-131)

The parity audit above covered `web/src`. It did not cover the BUILD, and three
things in `build/Build.cs` pointed at the deleted directory:

- **`SecurityScanAxeCore`** resolved `@axe-core/cli` out of `web/`'s
  devDependencies. With `web/` gone it reported "not installed" and skipped —
  so a scan that had been running stopped running, silently, and the
  accessibility evidence TFND-27 depends on quietly stopped arriving. The
  tooling now lives in `build/tools/node/`, which holds no application, only
  the two CLIs the build shells out to. This repository has no JavaScript
  application any more, but it still has a browser-rendered UI that Section 508
  applies to.
- **`SecurityScanAxeCore`'s default URL** rewrote `:5080` to `:5173` to reach
  the Vite dev server. That server is not started any more, so the default
  pointed at nothing. The app and the API are one host now.
- **`TestSpa`** and the Vitest coverage ingest leg ran against `web/`. Removed
  with `VitestCoverageIngestMapper`, which nothing called afterwards. Leaving
  the ingest leg in would have kept a `web` flavor on the dashboard whose
  coverage silently stopped updating, and a stale number is worse than an
  absent one.

`SecurityScanEslint` was KEPT and re-pointed. It degrades to a skip when no
JavaScript source tree is present, which is the correct behaviour for a
multi-tenant product where another project may well have one.

The lesson worth recording: a retirement audit that reads the application tree
and not the build will miss the scans that were feeding it.

## Localisation

The React catalogue had no untranslated survivors to carry over: the SPA shipped `en` only, and the
Blazor side starts from `UiStrings.resx` plus the pseudo-locale (TFND-67). Nothing was lost, because
there was nothing but English to lose — which is itself the honest statement of where localisation
stands.
