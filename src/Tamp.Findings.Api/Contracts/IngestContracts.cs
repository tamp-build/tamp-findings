using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Contracts;

// v0 ingest payload. Adopters POST this to /ingest/findings; the server
// find-or-creates the Client/Project and the build (ComponentVersion, keyed on
// project+flavor+version — the Component tier was collapsed in TFND-205; the
// `component` field is still accepted for wire compat but no longer modelled),
// then upserts findings using the (component-version, hash)
// dedup invariant. Idempotent re-ingest is the goal: posting the same
// payload twice should produce the same row count and bump LastSeen.
public sealed record IngestRequest(
    string Client,
    string Project,
    string? Component,
    string? ComponentKind,
    string? Flavor,
    string Version,
    string? CommitSha,
    string? Branch,
    string? BuildId,
    string? PullRequestRef,
    ScannerKind Scanner,
    IReadOnlyList<IngestFinding> Findings,
    // TFND-165: who produced this ingest (optional, additive).
    IngestActor? Actor = null,
    // TFND-183: the component's capability profile — "code-package" (default) |
    // "container" | "service". Declares which conditional scanners it can even
    // produce; the build knows what it is. Absent → code-package (unchanged for
    // an existing component that was already classified).
    string? ComponentProfile = null);

public sealed record IngestFinding(
    string RuleId,
    Severity Severity,
    string Title,
    string? Description,
    string? FilePath,
    int? Line,
    string? Snippet,
    // TFND-17: scanner-internal sub-category (e.g. Trivy's secret /
    // misconfiguration / vulnerability). Null when the scanner doesn't
    // sub-categorise; the server stores it on Finding.SubCategory so
    // aggregates can route to the right ring.
    string? SubCategory = null,
    // TFND-16: the package this finding is about, for dependency scanners.
    //
    // Optional and additive — every existing emitter keeps working. Supplying
    // it is what lets a CVE found by OsvScanner or Trivy be reconciled against
    // the SBOM component Grype would have attached it to, so the same CVE on
    // the same package is not counted twice.
    //
    // Full purl including version ("pkg:nuget/Log4Net@2.0.5") or bare
    // ("pkg:nuget/Log4Net") — the reconciler normalises both.
    string? Purl = null,
    // TFND-175 typed-unified routing: the issue TYPE (bug|code_smell|vulnerability|
    // security_hotspot). Populates Finding.SubCategory and drives quality-vs-SAST
    // routing, overriding the scanner's default bucket. Prefer this over SubCategory
    // for quality/SAST sources; if both are sent, Type wins.
    string? Type = null,
    // Opaque native-tool provenance (severityRaw, MQR impacts, effort, analysisId),
    // stored verbatim for drill-down. Findings does not parse it.
    string? Source = null);

public sealed record IngestResponse(
    Guid ComponentVersionId,
    int FindingsInserted,
    int FindingsUpdated,
    // TFND-6 / F5.4 — lifecycle transitions effected by this batch.
    // Reopened: existing Fixed/Suppressed findings whose hash reappeared
    //           AND no active suppression covers them anymore.
    // Closed:   existing Open findings whose hash disappeared from this
    //           scanner's results for this component version.
    // Suppressed: findings (new or existing) that an active Suppression
    //           covers — transitioned to Status=Suppressed during upsert
    //           (TFND-11 / F10).
    int FindingsReopened,
    int FindingsClosed,
    int FindingsSuppressed,
    // TFND-16 — advisory findings attached to an SBOM component by this batch,
    // and those that could not be.
    //
    // Unattached is the number worth watching from a pipeline: those CVEs exist
    // as findings and are NOT in the CVE count. Either no SBOM has been
    // ingested for this build yet, or the scanner did not report which package
    // it found them in. Returning it rather than only logging it means a build
    // can fail on it if the team wants to.
    int CvesAttached = 0,
    int CvesUnattached = 0);
