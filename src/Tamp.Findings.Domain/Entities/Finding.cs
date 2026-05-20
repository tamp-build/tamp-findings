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

    public FindingStatus Status { get; set; } = FindingStatus.Open;

    public DateTimeOffset FirstSeen { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset LastSeen { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
}
