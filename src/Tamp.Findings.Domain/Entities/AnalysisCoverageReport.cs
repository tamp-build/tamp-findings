namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// Analysis-coverage completeness for a build (TFND-175): what fraction of the
/// codebase was actually put through a quality/SAST analyzer, per language, and
/// what was left UNANALYZED.
///
/// This is the honesty layer under "0 findings". Only the producer (a full CI
/// checkout) can compute it — neither the analyzer (it only knows what it was
/// fed) nor findings (no checkout) can. Without it, a mixed-language repo that
/// runs only C# silently reports the whole front-end as clean. Distinct from
/// TEST coverage: this is "was this code analyzed at all", not "was it exercised
/// by tests." Replace-on-ingest per build.
/// </summary>
public sealed class AnalysisCoverageReport
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    public DateTimeOffset ObservedAt { get; set; }
    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>The producer's authoritative gap list: languages with real footprint and NO
    /// analyzer, comma-joined. The analysisCoverage gate reads this — a non-empty list blocks.</summary>
    public string? GapLanguages { get; set; }

    /// <summary>Path globs excluded from analysis (generated/vendored), comma-joined — context for the panel.</summary>
    public string? Excludes { get; set; }

    public ComponentVersion? ComponentVersion { get; set; }
    public ICollection<AnalysisCoverageLanguage> Languages { get; set; } = [];
}

/// <summary>One language's analysis coverage within a build.</summary>
public sealed class AnalysisCoverageLanguage
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid AnalysisCoverageReportId { get; set; }

    public string Language { get; set; } = "";       // "csharp", "typescript", …
    public int FilesTotal { get; set; }
    public int FilesAnalyzed { get; set; }
    public long LinesTotal { get; set; }
    public long LinesAnalyzed { get; set; }

    /// <summary>The tools that analyzed this language, comma-joined ("sonarqube, roslyn"); empty = none.</summary>
    public string? AnalyzedBy { get; set; }

    /// <summary>0..100. When no tool ran, 0 — a visible gap, not a silent pass.</summary>
    public double PercentAnalyzed { get; set; }

    /// <summary>A sample of unanalyzed paths, for the evidence drill-down (not necessarily exhaustive).</summary>
    public string? UnanalyzedSample { get; set; }

    public AnalysisCoverageReport? Report { get; set; }
}
