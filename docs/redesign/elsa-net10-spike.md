# Spike findings — Elsa 3.x and Elsa Studio on .NET 10

Ticket: TFND-58 (under TFND-40) · Date: 2026-08-22 · SDK 10.0.202 / runtime .NET 10.0.10

ADR 0001 accepted Elsa on a benchmark taken in a throwaway harness against Elsa 3.7.1, and noted the
figures were *"reproducible from the description"* rather than retained. This spike re-ran that
measurement inside a `net10.0` host and checked the packaging questions the redesign depends on.

**Verdict: proceed. Pin Elsa `3.7.1`.** No blockers found. One finding materially changes the Studio
recommendation.

---

## 1. Elsa targets .NET 10 natively

Not merely forward-compatible via `net9.0` — the packages ship real `net10.0` lib targets and dependency
groups.

| Package | Version | lib TFMs |
|---|---|---|
| `Elsa` | 3.7.1 (latest stable) | `net8.0`, `net9.0`, **`net10.0`** |
| `Elsa` | 3.8.0-rc2 (prerelease) | `net8.0`, `net9.0`, **`net10.0`** |
| `Elsa.Studio` | 3.7.1 | `net8.0`, `net9.0`, **`net10.0`** |
| `Elsa.Studio.Core` / `.Shell` / `.Shared` / `.Workflows` / `.Dashboard` | 3.7.1 | same |

Use **3.7.1**, the latest stable. 3.8.0 is at rc2; there is no reason to take a prerelease for the
runtime when the stable line already targets net10.

## 2. The benchmark holds on .NET 10

A trivial predicate workflow (one integer comparison inside an `Inline` in a `Sequence`), run in-process
through `IWorkflowRunner` — synchronous, no persistence — warmed with 50 runs first:

```
runtime: .NET 10.0.10
Elsa assembly: 3.7.1.0
   100 runs      67 ms    0.676 ms/run  ~1480/sec
  1000 runs     776 ms    0.776 ms/run  ~1288/sec
  5000 runs    3827 ms    0.765 ms/run  ~1306/sec
```

Flat across all three sizes — steady state, not warm-up — and consistent with ADR 0001's ~0.8 ms/run on
.NET 9. **ADR 0001's constraint therefore stands unchanged:**

> Rule workflows evaluate a finding *set*, not a finding.

Ten rules over 5,000 findings is ten invocations (~8 ms). Per-finding evaluation would be 50,000
invocations (~38 s at the measured rate) and remains non-viable.

The harness is not retained, per the ADR 0001 precedent. It is ~40 lines: `services.AddElsa()`, resolve
`IWorkflowRunner`, loop `RunAsync` over a `Sequence { new Inline(...) }`, and assert the body actually
executed so the timing is not measuring a no-op.

## 3. Persistence — the obvious package name is the wrong one

The correct coordinate is **`Elsa.Persistence.EFCore.PostgreSql` 3.7.1**.

`Elsa.EntityFrameworkCore.PostgreSql` also exists on nuget.org but is stale at **3.2.4** — it is the
older naming and will silently give a version four minors behind. Do not reach for it.

It resolves `Npgsql` and `Npgsql.EntityFrameworkCore.PostgreSQL` at **10.0.0**. This repo pins
`Npgsql.EntityFrameworkCore.PostgreSQL` **10.0.1** in `Directory.Packages.props`; central package
management resolves to 10.0.1 and Elsa's floor is satisfied. **No conflict.**

## 4. Studio pulls two component libraries, not one — and a prerelease

This is the finding that changes something. The hand-off says:

> The exception is **Elsa Studio, which is built on MudBlazor** […] If it is embedded rather than run as
> a separate app, MudBlazor is in the build regardless.

That understates it. `Elsa.Studio.Core` 3.7.1 declares:

| Package | Version | Note |
|---|---|---|
| `MudBlazor` | 9.0.0 | as documented |
| `Radzen.Blazor` | 9.0.5 | **not mentioned in the hand-off** |
| `CodeBeam.MudBlazor.Extensions` | 9.0.0-rc.1 | **prerelease, transitive** |

Confirmed as resolved, not merely declared — `dotnet list package --include-transitive` on a
`Microsoft.NET.Sdk.Razor` project referencing `Elsa.Studio` 3.7.1 lists all three.

Two consequences:

* **The CSS isolation risk is doubled.** The hand-off's recommendation — mount Studio on its own route,
  isolate rather than theme — was correct for one component library and is more strongly correct for
  two. Theming was never advisable; it is now clearly not worth attempting.
* **A prerelease arrives transitively.** For a product that scans its own supply chain and generates
  attestation evidence, `9.0.0-rc.1` appearing in a dependency graph is worth a deliberate decision
  rather than a surprise in its own SBOM. It affects **only** the Studio authoring UI, not the workflow
  runtime.

Both reinforce the existing plan: **TFND-125 (mount Studio) stays Minor and deferrable.** Ship the
workflows as definitions, expose only their state in the redesigned screens, and adopt Studio only if
someone actually asks to author workflows in the UI. Nothing in Phase 13 depends on it.

## 5. Studio compiles on net10

A `Microsoft.NET.Sdk.Razor` class library referencing `Elsa.Studio` 3.7.1, with a component using a
MudBlazor primitive and `@using Elsa.Studio.Dashboard`, builds clean on `net10.0` — 0 warnings,
0 errors. So the RCL layering in ADR 0002 is compatible with hosting Studio later, should it be wanted.

---

## Package coordinates for TFND-115

```xml
<PackageVersion Include="Elsa" Version="3.7.1" />
<PackageVersion Include="Elsa.Persistence.EFCore.PostgreSql" Version="3.7.1" />
<!-- Studio: only if TFND-125 is taken. Brings MudBlazor 9.0.0,
     Radzen.Blazor 9.0.5 and CodeBeam.MudBlazor.Extensions 9.0.0-rc.1. -->
<!-- <PackageVersion Include="Elsa.Studio" Version="3.7.1" /> -->
```

## Not covered by this spike

* Migrations against the live schema — Elsa owns its own tables; whether they share this repo's
  `Migrations` history or run as a separate context is a TFND-115 decision.
* `IWorkflowDispatcher` (the background-queue path) was not exercised. Only `IWorkflowRunner`, which is
  the path ADR 0001's rule-evaluation decision rests on. The approvals in Phase 13 use the dispatcher and
  should be measured when the first real one exists.
* Realistic rule cost. ADR 0001 already flags the benchmark as a **floor** — the simplest workflow that
  still makes a decision. Re-measure once a real rule exists.
