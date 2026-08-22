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

    // True when a finding from this scanner describes a request rather than a
    // location in the source tree, and so needs the dynamic hash.
    public static bool IsDynamic(ScannerKind scanner) => Dast.Contains(scanner);
}
