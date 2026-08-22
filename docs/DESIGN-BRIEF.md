# tamp.findings — product brief for a UX rework

Written for a designer with no prior exposure to this codebase. Everything below reflects the app as deployed, not as planned.

**Live instance:** <https://tamp-findings.brewingcoder.com>
**Frontend:** React 19 · Vite 8 · TanStack Query · Tailwind v4 · shadcn-style primitives · lucide icons. Dark-first; a `.dark` class variant drives theming from `web/src/index.css`.
**Backend:** .NET 10 minimal API · PostgreSQL. The SPA is served same-origin from the API in production.

---

## 1. What this product is

A **self-hosted security and quality dashboard** that ingests the output of many scanners across many builds, scores each build against a configurable risk policy, and produces **federal-grade compliance evidence** for the software you ship.

It is not a scanner. It runs nothing itself. Scanners run in someone's CI pipeline and POST their results here. The product's value is entirely in **aggregation, scoring, and evidence generation** — turning a dozen unrelated tool outputs into one defensible answer to *"is this safe to release, and can you prove it?"*

### Who uses it, and what they actually want

| Persona | Comes here to answer | Visits |
|---|---|---|
| **Developer** | "What did I break? Where is it?" | Several times a day |
| **Security lead** | "Which of our projects is worst right now?" | Weekly |
| **Compliance / auditor** | "Prove this release met the contract." | Quarterly, under pressure |
| **Release manager** | "Can this build ship, yes or no?" | Per release |

These four want *very* different densities of information from the same data. The current UI mostly serves the first, which is the central design problem.

### The commercial reason it exists

Federal software contracts increasingly require attestation against **NIST SSDF (SP 800-218)** — the CISA Secure Software Development Attestation Form. A human signatory personally attests that specified practices were followed. This product auto-populates that form from real scan evidence and flags what a human must attest manually. **The attestation is the money feature.** Everything else feeds it.

---

## 2. The domain model — read this before designing anything

Four nested levels. This hierarchy is load-bearing and appears in almost every screen.

```
Client            an organisation or customer          "BrewingCoder"
└── Project       a product; owns policy + gates       "tamp"
    └── Component a deployable unit within it          "tamp-findings"
        └── ComponentVersion   one build               commit 179fe8b
```

- **ComponentVersion is the atom.** Every finding, SBOM, coverage report and test run attaches to one. A version carries a commit sha, a branch, and a **flavor** — a build variant such as `net10`, `web`, or `deployed`. The same commit can produce several versions with different flavors.
- **Risk policy, acceptance gates, VEX, POA&M and VDP all scope to Project.**
- **"Canonical"** means the default-branch, non-PR build. Risk scores always use canonical builds, so a pull request cannot move the project's headline number.

---

## 3. The two numbers everything revolves around

### Risk score — 0 to 100, lower is better

A weighted sum over roughly twelve categories, banded **green ≤10 · yellow ≤25 · orange ≤50 · red**.

Two properties a designer must understand:

1. **Categories saturate.** Each contributes `min(1, Σ count × weight) × its share of the scale`. Two critical CVEs max out the CVE category — the 50th scores identically to the 2nd. The score is a **posture indicator, not a volume meter.** Any visual implying "more findings = proportionally worse" is lying to the user.
2. **Weights are relative and renormalise.** Disabling categories redistributes the scale across whatever remains. A category's displayed ceiling therefore depends on which *other* categories are switched on — it is not a fixed number.

### Acceptance gates — pass/fail, per build

Independent of the score. A gate is a release blocker: *"zero KEV-listed CVEs"*, *"no critical SAST"*, *"coverage didn't drop"*, *"no overdue POA&M items"*.

Gates answer **"can this ship?"** The score answers **"how are we trending?"** Users conflate them constantly, and the two are currently presented on different screens.

---

## 4. What gets ingested

| Class | Source tools | Becomes |
|---|---|---|
| **SAST** | Roslyn, ReSharper, OpenGrep, CodeQL, ESLint | Findings against source files + line numbers |
| **DAST** | ZAP, Nuclei | Findings against **URLs** — no file, no line |
| **Secrets** | TruffleHog, Trivy | Verified (live credential) vs unverified |
| **IaC** | Trivy | Misconfigurations |
| **SCA / CVEs** | OSV-Scanner, Grype, Syft | Vulnerabilities on SBOM components |
| **SBOM** | CycloneDX, Syft | Dependency inventory, licences, dependency graph |
| **Coverage** | Coverlet, vitest | Line/sequence coverage per file |
| **Tests** | TRX, vitest junit | Pass/fail per suite and per case |
| **Accessibility** | axe-core | WCAG violations |
| **Scan receipts** | all of the above | *Which scanners ran* |

That last row matters more than it looks. **"No findings" and "no scan" look identical unless the UI distinguishes them** — and conflating them is exactly how a compliance attestation becomes false.

### Compliance artefacts (entered by humans, not scanners)

- **VEX** — "this CVE does not affect us, because…". Suppresses matching CVEs from counts and gates.
- **POA&M** — Plan of Action & Milestones. A tracked remediation item with an owner and a due date; overdue items can fail a gate.
- **VDP** — Vulnerability Disclosure Policy metadata.
- **Provenance** — SLSA / in-toto / DSSE attestations proving build integrity.
- **Suppressions** — rule-level mutes with a stated reason.

---

## 5. Screens as they exist today

| Screen | Purpose | Notes |
|---|---|---|
| **Overview** | All clients; risk rings + summary tiles | Entry point. Concentric donut of six metrics. |
| **Client page** | One client and its projects | Thin — barely more than a list. |
| **Project page** | The hub: rings, scan receipts, drill-outs | Most-used screen; gateway to everything else. |
| **Findings** | SAST: module → file tree, plus a source viewer with severity-tinted lines | Two-pane explorer. |
| **Dynamic scan** | DAST: host → route tree, findings inline | Same grammar, different spine. Newest screen. |
| **Components** | SBOM inventory, licences, vulnerabilities | Table-driven. |
| **Coverage** | Module → file tree, covered/uncovered lines | Two-pane explorer. |
| **Tests** | Assembly → class tree, failures with stack traces | Two-pane explorer. |
| **Attestation** | The CISA SSDF form: 22 practices, Yes/Partial/No/Manual, with evidence strings | Print-to-PDF and JSON export. **The deliverable.** |
| **Settings** | Risk policies, role assignments | Admin. |
| **Profile / Sign-in** | GitHub OAuth | Minimal. |

Dialogs: project settings (policy, gates, VEX, POA&M, VDP, ingest tokens), client settings, create-hierarchy-node.

### Navigation, honestly

There is **no router**. Navigation is `useState` tab switching in `App.tsx`. Consequences a redesign should weigh:

- **No deep links.** You cannot send someone a URL to a finding, a project, or an attestation.
- **No browser back button.** Breadcrumbs are the only way back.
- **Nothing is bookmarkable** — including the attestation an auditor may need to revisit.

---

## 6. Known problems — a candid list

Ordered by how much they hurt.

1. **No deep linking.** The single biggest structural limitation.
2. **Risk rings show six of ~twelve scored categories.** Coverage, code quality, SBOM, secrets, licences and IaC are drawn. CVEs, tests, DAST and dependency staleness are scored but invisible. A user cannot see what is driving their number.
3. **Score and gates live apart.** The two questions users actually ask are answered on different screens.
4. **Four near-identical two-pane explorers** (Findings, Dynamic scan, Coverage, Tests) with no shared shell and no cross-navigation between them.
5. **"Clean" versus "never scanned" is weakly conveyed.** Scan receipts exist in the data model and barely surface in the UI.
6. **DAST does not fit the SAST model.** A DAST finding has a URL, an HTTP method and an injected parameter — no file, no line, no source to display. It required an entirely separate screen. There may be a unifying abstraction.
7. **The same app can appear as two hosts** in the DAST tree when two scanners reach it by different addresses. Findings are attributed to *how the scanner connected* rather than to the application.
8. **Severity has five levels and no visual hierarchy beyond colour** — Info / Low / Medium / High / Critical, all rendered as coloured dots.
9. **Nothing is time-aware.** No trends, no sparklines, no "since last release". The data fully supports it (`FirstSeen` / `LastSeen` per finding, one row per build) — the UI shows only the present.
10. **Density is one-size-fits-all.** The auditor's quarterly deep read and the developer's daily glance get the same layout.

---

## 7. Constraints

- **Dark-first.** Light mode should work, but dark is the default and the primary target.
- **Print matters.** The attestation is printed to PDF and attached to contract packages. It must survive a black-and-white printer — **colour cannot be the only signal.**
- **Data volume is lumpy.** A project may have 5 findings or 5,000; 20 SBOM components or 600. Coverage trees run to thousands of files. DAST is usually tens. Layouts need to hold up at both ends.
- **Everything is scoped.** Most screens accept client / project / component filters and must show the active scope unambiguously.
- **Accessibility is not optional** for a product that ships an accessibility scanner and sells into federal contracts. WCAG 2.1 AA is the bar.
- Existing primitives are Tailwind v4 with shadcn-style components and lucide icons. A redesign may replace these — but should say so explicitly rather than silently.

---

## 8. If only three things get fixed

1. **Make the score legible.** A user should see, without clicking, which categories drive their number and by how much — including the ones no ring currently draws.
2. **Put "can this ship?" next to "how are we doing?"** Gates and score belong in one view, with any failing gate named in place.
3. **Give things addressable URLs.** Almost everything else compounds from being able to link to a thing.
