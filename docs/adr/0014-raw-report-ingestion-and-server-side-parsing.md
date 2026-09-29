# ADR 0014: Raw report ingestion — the sink parses, and the raw report is the evidence of record

* Status: Accepted
* Date: 2026-09-29
* Deciders: scott
* Tracking: TFND-209
* Companion: [0018](https://github.com/tamp-build/tamp) (the tamp emission contract — the normalized wire shape, owned upstream); [0006](0006-adr-conformance-as-evidence-and-frozen-non-pure-verdicts.md) (evidence is frozen at the build it was measured against)

## Context and Problem Statement

Findings ingests test results and coverage through **normalized JSON** endpoints
(`/ingest/test-results`, `/ingest/coverage`): the producer parses its tool's native report
(a Visual Studio `.trx`, a Cobertura/OpenCover XML) into our canonical request shape and POSTs
that. `Tamp.Ingest.V1` ships mapper helpers for **SBOM** (`CycloneDxSbomMapper`) and **findings**
(`SarifFindingsMapper`) but **none for tests or coverage**. So every adopter re-implements those
two parsers by hand — and they are exactly the fiddly, error-prone transforms a shared component
should own:

* **.trx**: a `<UnitTestResult>` carries only a `testId`; the class name and assembly live on a
  separate `<TestDefinitions>/<UnitTest>/<TestMethod>`, joined by `testId`, under a default XML
  namespace. Get the join wrong and failures are silently mis-attributed or dropped.
* **Cobertura**: line/branch **rates** are 0..1 fractions that must be scaled to percentages, and
  per-package counts have to be summed from `<line hits>` when the roll-up attributes are absent.

The dogfood producer (tamp) hit this directly: to run a full-evidence ship-gate on tamp-core it
hand-rolled both a `.trx` and a Cobertura parser just to post the normalized JSON. Two problems
follow. First, the parser drift: N adopters, N subtly different implementations of the same reshape,
none tested against real files by the party that owns the model. Second, and more fundamental for a
compliance product: the **evidence we attest to is a client's reshape of the tool output**, not the
tool output itself. When an auditor asks "show me the test run for this build," the honest answer is
the `.trx`, not our JSON derived from it by code we don't control.

## Decision Drivers

* Kill the mapper gap at its source, not by shipping yet another client-side mapper.
* For an attestation product, the **raw artifact is the evidence** — reshaping belongs to the party
  that owns the sink and the canonical model, and the raw file should be retained as the record.
* Accepting an untrusted file server-side is a new attack surface (XXE, entity expansion, oversized
  bodies) — it must be hardened once, in one place, rather than left to each adopter's unknown posture.
* Don't break the existing normalized path or the line-level coverage it can carry.

## Decision

**Findings accepts raw report files directly, owns the parse server-side, and retains the raw report
as the evidence of record.** `Tamp.Ingest.V1` does **not** grow test/coverage mappers; it collapses
to a thin "POST this file" client.

1. **Raw endpoints.** Two new endpoints take the file the CI run already produced as the request
   body, with the hierarchy on the query string (`client`, `project`, `version` required;
   `commitSha`, `branch`, `buildId`, `pullRequestRef`, `flavor`, `toolVersion` optional). Auth is the
   same `cli_`/`prj_` Bearer token as the normalized endpoints.
   * `POST /ingest/test-results/raw` — Visual Studio **.trx** or **JUnit** XML.
   * `POST /ingest/coverage/raw` — **Cobertura** or **OpenCover** XML.
   The format is detected by root element (`<TestRun>`, `<testsuites>`/`<testsuite>`, `<coverage>`,
   `<CoverageSession>`), so a producer POSTs the file without declaring its dialect.

2. **The parse lives in findings.** `src/Tamp.Findings.Api/Ingest/Raw/` holds one parser per format.
   Each raw handler parses the file into the **existing canonical request** and calls the same
   `IngestAsync` the normalized endpoint uses — so storage, scoring, snapshotting, and audit are
   byte-identical to the normalized path. The raw path is a new front door, not a second pipeline.

3. **Hardened intake.** `RawReportXml` loads the body with `DtdProcessing.Prohibit` and a null
   `XmlResolver` (no DOCTYPE, no external entities — XXE and billion-laughs closed) and caps the body
   at 32 MB. A malformed document, an unrecognised root, or a well-formed but wrong-shape file is a
   **400**, never a 500. One hardened parser replaces N hand-rolled ones of unknown posture.

4. **The raw report is retained as the evidence of record.** The raw file the producer POSTs is
   persisted (`RawReportArtifact`), linked to the build, so the evidence we attest to is the tool's own
   output and we can re-parse it as the canonical model grows (per-test timing, categories, rerun data)
   without asking adopters to re-ingest. It is stored in Postgres — a dedicated table, gzip-compressed
   `bytea`, written in the same transaction as the parsed evidence and cascade-deleted with the build —
   not an object store: there is none deployed, the files are small (XML compresses ~10-20×), and the
   evidence must never be a dangling reference to a blob the DB backup doesn't cover. Retention is
   **replace-by-file with content dedup**: the supersession identity is the producer's filename (an
   optional `?filename=`) or `sha256:<hash>` when none is given, so re-posting the same file replaces
   it, a build's several files coexist, and identical bytes are a no-op — the stored raw always mirrors
   the current parsed evidence, and the audit log remains the per-event trail. (TFND-209.)

5. **The normalized endpoints remain.** `/ingest/test-results` and `/ingest/coverage` stay supported:
   they are the canonical model the raw path parses **into**, the fallback for formats we don't parse
   yet, and — importantly — the **only** way to ship **line-level coverage**. Raw Cobertura/OpenCover
   carry no source text, so the raw coverage path produces overall + per-module coverage only (enough
   for the score and the `coverageFloor` gate); the line-by-line Explorer overlay still requires the
   normalized `/ingest/coverage` with its `SourceFiles`.

6. **Build identity is the commit, not the version string.** A build's identity is the commit it was
   built from; the version string a producer stamps is a label, not an identity. `BuildResolver`
   therefore reconciles an incoming ingest against any prior build for the same `(project, flavor)`
   whose commit matches — exactly or by git short/full-sha prefix — within the same PR context, and
   only falls back to the version string when no commit is supplied. Evidence about one commit lands
   on one build even when two producers stamp different versions. This closes the failure mode the
   raw dogfood surfaced: a test-results ingest under `version=1.17.3, commitSha=6648825` and a
   coverage ingest under `version=0.0.0+6648825, commitSha=6648825947…` (the same commit, abbreviated
   vs full) split into two builds, and the ship gate read the split as evidence missing. The rule
   applies to every ingest endpoint, raw and normalized, since they share the resolver.

## Consequences

* **The mapper gap closes upstream-side.** Adopters POST the file; no one hand-rolls a `.trx` join or
  a Cobertura scaler again. `Tamp.Ingest.V1` should **not** add `TrxTestResultsMapper` /
  `CoberturaCoverageMapper` — the parse is here now.
* **Findings owns format coverage** (.trx, JUnit, Cobertura, OpenCover today; more later) and the
  parsing risk that comes with it. That risk is contained to one hardened, tested component and is
  strictly safer than the status quo of many unaudited client parsers.
* **The evidence gets more honest.** Once raw persistence lands, the artifact of record is the tool's
  own file, not a reshape — the right footing for an attestation product, and re-parseable as the
  model grows.
* **Storage grows**, bounded: reports are small and ingest is replace-on-ingest (one per build). The
  storage medium (Postgres column vs. object store) is deferred to the TFND-209 follow-up.
* **Test-results raw is full fidelity** (suites, cases, outcomes, error messages); **coverage raw is
  intentionally partial** (no line-level overlay). This asymmetry is documented on the endpoint and is
  a property of the source files, not a shortcut.
