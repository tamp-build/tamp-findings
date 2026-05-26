# tamp-ingest-v1 — golden fixtures

Round-trip reference payloads for the `tamp-ingest-v1` contract. One JSON file per endpoint, matching the shapes documented in the spec (published via the interagent server as `tamp-ingest-v1` v1.2+).

These are the shapes the **production sink at `https://tamp-findings.brewingcoder.com` accepts today** — captured from real `dotnet tamp Ingest` runs that landed against the live API.

## Coverage

| File | Endpoint | Notes |
|---|---|---|
| `01-sbom-request.json` | `POST /ingest/sbom` | Normalized DTO; CycloneDX inputs pre-transformed via `SbomIngestMapper` |
| `02-findings-roslyn-request.json` | `POST /ingest/findings` | Scanner in body, SARIF pre-flattened to per-finding rows |
| `03-findings-eslint-request.json` | `POST /ingest/findings` | ESLint variant — same shape, `Flavor: "web"` to attach to SPA CV |
| `04-findings-trivy-request.json` | `POST /ingest/findings` | Trivy variant with `SubCategory: "misconfiguration"` |
| `05-coverage-dotnet-request.json` | `POST /ingest/coverage` | OpenCover → normalized; modules + classes + source files |
| `06-coverage-vitest-request.json` | `POST /ingest/coverage` | vitest lcov → normalized; `Flavor: "web"` |
| `07-test-results-request.json` | `POST /ingest/test-results` | TRX → flat assemblies/suites/cases |
| `08-scan-runs-request.json` | `POST /ingest/scan-runs` | Per-scanner receipts; `status: Succeeded\|Failed\|Skipped` |
| `09-sbom-vulnerabilities-upsert-request.json` | `POST /sbom-vulnerabilities/upsert` | Keyed by `snapshotId` (returned by `/ingest/sbom`); no `/ingest/` prefix |
| `10-sbom-provenance-slsa-request.json` | `POST /ingest/sbom-snapshots/{id}/provenance` | SLSA v1 Provenance |
| `11-sbom-provenance-dsse-request.json` | `POST /ingest/sbom-snapshots/{id}/provenance` | DSSE-wrapped attestation |

## Invariants

- **Auth**: every request carries `Authorization: Bearer cli_… | prj_…`. Tokens are sink-side state; not in the fixtures.
- **Hierarchy in body, not query params**: `client / project / component / componentKind? / flavor? / version / commitSha? / branch? / buildId? / pullRequestRef?` appears flat in the request body. No `?clientName=` query strings.
- **Enum casing on the wire**: PascalCase canonical (`"Roslyn"`, `"Succeeded"`, `"Critical"`). Sink accepts case-insensitively, but PascalCase is what the dashboard emits and what these fixtures use.
- **Date format**: ISO-8601 with `Z` suffix (UTC). The sink parses any valid `DateTimeOffset` string.
- **Replace-vs-append per endpoint**: see spec §4. `/ingest/sbom` and `/ingest/coverage` and `/ingest/test-results` replace per-CV; `/ingest/findings` is hash-keyed upsert (append-with-dedup); `/ingest/scan-runs` replaces per (CV, Scanner); `/sbom-vulnerabilities/upsert` is upsert-by-(SbomComponentId, AdvisoryId).

## Round-trip pattern (recommended for `Tamp.Ingest.V1` test suite)

```csharp
[Fact]
public void SbomRequest_RoundTrips()
{
    var raw = File.ReadAllText("Fixtures/Ingest/v1/01-sbom-request.json");
    var req = JsonSerializer.Deserialize<SbomIngestRequest>(raw, JsonOpts);
    var emitted = JsonSerializer.Serialize(req, JsonOpts);
    Assert.Equal(
        JsonSerializer.Deserialize<JsonElement>(raw).GetRawText(),
        JsonSerializer.Deserialize<JsonElement>(emitted).GetRawText());
}
```

`JsonOpts` is the sink's `JsonStringEnumConverter` + camelCase property naming if you want strict match (the sink accepts either casing on input).
