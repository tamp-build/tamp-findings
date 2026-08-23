namespace Tamp.Findings.Domain.Values;

// Canonical scanner groupings.
//
// These sets decide three separate things that must agree: which hash a
// finding gets at ingest, which risk-score bucket it lands in, and which
// browse surface renders it. They were previously duplicated per call site,
// which is exactly the shape of bug where a scanner is added to the scoring
// set but not the hashing set and nobody notices — the findings score
// correctly and churn silently.
public static class ScannerKinds
{
    // Static analysis over source. Feeds sastSevere / sastLow and the Code
    // Quality ring.
    public static readonly IReadOnlySet<ScannerKind> Sast = new HashSet<ScannerKind>
    {
        ScannerKind.Roslyn,
        ScannerKind.ReSharper,
        ScannerKind.OpenGrep,
        ScannerKind.CodeQL,
        ScannerKind.ESLint,
    };

    // Dynamic analysis against a running deployment. Feeds dastSevere /
    // dastLow, the criticalDast gate, SSDF PW.8.1, and — critically — selects
    // FindingHasher.ComputeForDynamic instead of the file/line hasher.
    public static readonly IReadOnlySet<ScannerKind> Dast = new HashSet<ScannerKind>
    {
        ScannerKind.Zap,
        ScannerKind.Nuclei,
    };

    // Static analysis that finds DESIGN and MAINTAINABILITY problems rather
    // than vulnerabilities (TFND-33 … TFND-37).
    //
    // These five had ScannerKind values and belonged to no set, which meant
    // their findings were ingested and then invisible: absent from every spine,
    // absent from the score. Ingesting evidence and then not showing it is the
    // worst of both — the pipeline pays for the scan and nobody sees the result.
    //
    // Deliberately NOT folded into Sast. An OpenAPI style nit is not a static
    // analysis SECURITY finding, and putting one there would let it block a
    // release through the criticalSast gate — which is how a team learns to
    // turn a gate off.
    public static readonly IReadOnlySet<ScannerKind> Quality = new HashSet<ScannerKind>
    {
        // OpenAPI lint: a spec that contradicts itself or omits security
        // definitions.
        ScannerKind.Spectral,
        // OpenAPI breaking-change detection against the previous spec.
        ScannerKind.Oasdiff,
        // Mutation testing: tests that pass whether or not the code works.
        ScannerKind.Stryker,
        // .NET architecture rules — layering violations, forbidden references.
        ScannerKind.NetArchTest,
        // The TS/JS analogue.
        ScannerKind.DependencyCruiser,
    };

    // Every scanner that reports against a location in the source tree, whether
    // it is looking for a vulnerability or a design problem. This is what the
    // explorer's static spine shows: a reader looking at "what did the analysis
    // find in this file" wants both, and splitting them across two screens would
    // mean checking two screens.
    public static readonly IReadOnlySet<ScannerKind> Static =
        new HashSet<ScannerKind>(Sast.Concat(Quality));

    // Section 508 / WCAG 2.1 AA conformance (TFND-27).
    //
    // Its own set, not part of Sast or Dast, because the AUDIENCE is different:
    // an accessibility defect is read by UX and by compliance, not by whoever
    // triages CVEs. Folding it into a security bucket would put it in front of
    // the wrong people and hide it from the right ones.
    //
    // For federal work this is not optional — any UI-facing software must
    // conform under 29 U.S.C. § 794d, and a gap here blocks acceptance as
    // surely as an unpatched CVE does.
    public static readonly IReadOnlySet<ScannerKind> Accessibility = new HashSet<ScannerKind>
    {
        ScannerKind.AxeCore,
    };

    // True when a finding from this scanner describes a request rather than a
    // location in the source tree, and so needs the dynamic hash.
    //
    // Accessibility findings qualify: axe reports a URL and a CSS selector, not
    // a file and a line, so the file/line hasher would produce a hash from two
    // nulls and collapse every violation on a page into one finding.
    public static bool IsDynamic(ScannerKind scanner) =>
        Dast.Contains(scanner) || Accessibility.Contains(scanner);
}
