using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

public sealed class Finding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    // Stable line-independent hash used for dedup across builds and across
    // overlapping OpenGrep models — see TFND-6 / F5.
    public required string Hash { get; set; }

    public ScannerKind Scanner { get; set; }
    public required string RuleId { get; set; }
    public Severity Severity { get; set; }

    public required string Title { get; set; }
    public string? Description { get; set; }
    public string? FilePath { get; set; }
    public int? Line { get; set; }
    public string? Snippet { get; set; }

    // TFND-17: Trivy emits secrets / misconfigurations / vulnerabilities all
    // under one scanner name. SARIF rule tags distinguish them; the value
    // here is null for scanners that don't sub-categorise.
    public string? SubCategory { get; set; }

    // TFND-16: the package this finding is ABOUT, for scanners that report
    // against a dependency rather than against source.
    //
    // OsvScanner and Trivy's vulnerability detector both find CVEs in
    // dependencies, and both arrive as Finding rows — while Grype's arrive as
    // Vulnerability rows through the SBOM path. Two parallel CVE paths, and
    // only one of them fed the SBOM picture: the same CVE on the same package
    // counted once or twice depending on which scanner happened to see it.
    //
    // The purl is what lets the reconciler attach one to the other, giving each
    // (component, advisory) pair ONE source of truth. Null for everything that
    // is not a dependency finding — and, importantly, also null when a scanner
    // reports a CVE but does not say which package, which is a state the
    // reconciler reports rather than guesses at.
    public string? Purl { get; set; }

    public FindingStatus Status { get; set; } = FindingStatus.Open;

    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
}
