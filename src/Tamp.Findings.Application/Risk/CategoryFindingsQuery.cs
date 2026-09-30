using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

/// <summary>
/// The findings that make up one scored category, for the category detail page
/// (v3 §3). This resolves the build's canonical component-version set the same
/// way the hub does, then filters the Findings table by the category's own
/// classification — the SAME scanner/severity/sub-category rules RiskInputsBuilder
/// scores against, so the list and the number cannot disagree.
///
/// Only the FINDINGS-table categories are answered here (sastSevere, sastLow,
/// secrets, iacSevere). cve (SBOM vulnerabilities), coverage, tests, license,
/// sbomStaleness and missingScanners have their own data sources and their own
/// queries; this returns an empty list for them.
/// </summary>
public sealed class CategoryFindingsQuery(FindingsDbContext db, Licensing.LicenseResolutionService licenses)
{
    // The build's CV set: the requested commit, or the latest canonical one.
    private async Task<Guid[]> ResolveCvIdsAsync(Guid projectId, string? commitSha, CancellationToken ct)
    {
        var sha = commitSha;
        if (string.IsNullOrWhiteSpace(sha))
        {
            sha = await db.ComponentVersions.AsNoTracking()
                .Where(cv => cv.ProjectId == projectId)
                .OrderByDescending(cv => cv.CreatedAt)
                .Select(cv => cv.CommitSha)
                .FirstOrDefaultAsync(ct);
        }
        if (sha is null) return [];

        return await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.CommitSha == sha
                && cv.ProjectId == projectId)
            .Select(cv => cv.Id)
            .ToArrayAsync(ct);
    }

    public async Task<IReadOnlyList<CategoryFinding>> LoadAsync(
        Guid projectId, string? commitSha, string categoryKey, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        var dupeIds = (await FindingDedupe.DuplicateIdsAsync(db, cvIds, ct)).ToArray();
        var q = db.Findings.AsNoTracking().Where(f => cvIds.Contains(f.ComponentVersionId) && !dupeIds.Contains(f.Id));
        q = Filter(categoryKey, q);
        if (q is null) return [];

        return await q
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.FilePath)
            .ThenBy(f => f.Line)
            .Select(f => new CategoryFinding(
                f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description,
                f.FilePath, f.Line, f.Snippet, f.SubCategory, f.Status, f.FirstSeen))
            .ToListAsync(ct);
    }

    /// <summary>Known-CVE rows for the `cve` category, from the SBOM vulnerabilities.</summary>
    public async Task<IReadOnlyList<CveRow>> CvesAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        return await db.Vulnerabilities.AsNoTracking()
            .Where(v => cvIds.Contains(v.SbomComponent!.SbomSnapshot!.ComponentVersionId))
            .OrderByDescending(v => v.Severity).ThenByDescending(v => v.CvssScore ?? 0)
            .Select(v => new CveRow(
                v.AdvisoryId, v.Severity, v.SbomComponent!.Name, v.SbomComponent!.Version,
                v.CvssScore, v.FixedInVersion, v.ReferenceUrl))
            .ToListAsync(ct);
    }

    /// <summary>Per-build CVE scan evidence for the history strip — the actual scan behind each build's
    /// "0 CVEs", not just that a build happened: commit, when, the SCA scanner + its advisory-DB
    /// provenance (from the receipt notes), and how many CVEs it found. A build with no SCA receipt is
    /// marked unscanned so a bare zero can't read as clean.</summary>
    public async Task<IReadOnlyList<CveScanHistoryRow>> CveScanHistoryAsync(
        Guid projectId, int take = 12, CancellationToken ct = default)
    {
        var cvs = await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.ProjectId == projectId && cv.CommitSha != null)
            .OrderByDescending(cv => cv.CreatedAt)
            .Take(take)
            .Select(cv => new { cv.Id, cv.CommitSha, cv.CreatedAt })
            .ToListAsync(ct);
        if (cvs.Count == 0) return [];
        var ids = cvs.Select(c => c.Id).ToArray();

        var scaKinds = new[] { ScannerKind.OsvScanner, ScannerKind.Grype };
        var receipts = (await db.ScanRunReceipts.AsNoTracking()
                .Where(r => ids.Contains(r.ComponentVersionId) && scaKinds.Contains(r.Scanner)
                    && r.Status == Domain.Entities.ScanRunStatus.Succeeded)
                .Select(r => new { r.ComponentVersionId, r.ToolName, r.ToolVersion, r.Notes, r.CompletedAt })
                .ToListAsync(ct))
            .GroupBy(r => r.ComponentVersionId)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(r => r.CompletedAt).First());

        var cveCounts = (await db.Vulnerabilities.AsNoTracking()
                .Where(v => ids.Contains(v.SbomComponent!.SbomSnapshot!.ComponentVersionId))
                .GroupBy(v => v.SbomComponent!.SbomSnapshot!.ComponentVersionId)
                .Select(g => new { CvId = g.Key, Count = g.Count() })
                .ToListAsync(ct))
            .ToDictionary(x => x.CvId, x => x.Count);

        return cvs.Select(c =>
        {
            receipts.TryGetValue(c.Id, out var r);
            return new CveScanHistoryRow(
                c.CommitSha, c.CreatedAt, r is not null,
                r?.ToolName, r?.ToolVersion, r?.Notes, cveCounts.GetValueOrDefault(c.Id, 0));
        }).ToList();
    }

    /// <summary>Aggregated coverage for the `coverage` category, or null when never measured.</summary>
    public async Task<CoverageSummary?> CoverageAsync(
        Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return null;

        var reports = await db.CoverageReports.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .Select(r => new { r.CoveredSequences, r.TotalSequences, r.CoveredBranches, r.TotalBranches })
            .ToListAsync(ct);
        if (reports.Count == 0) return null;

        var cs = reports.Sum(r => r.CoveredSequences); var ts = reports.Sum(r => r.TotalSequences);
        var cb = reports.Sum(r => r.CoveredBranches); var tb = reports.Sum(r => r.TotalBranches);
        return new CoverageSummary(
            ts == 0 ? 0 : 100.0 * cs / ts, cs, ts,
            tb == 0 ? 0 : 100.0 * cb / tb, cb, tb);
    }

    /// <summary>Test outcomes for the `tests` category. Suite-level — per-test flaky/skipped
    /// detail is not ingested yet (a known model gap), so this reports the suites that failed
    /// or skipped, plus the run totals.</summary>
    public async Task<TestsSummary?> TestsAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return null;

        var reports = await db.TestRunReports.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .Select(r => new { r.Id, r.TotalCount, r.PassedCount, r.FailedCount, r.SkippedCount, r.DurationMs, r.ToolName, r.ToolVersion, r.CompletedAt })
            .ToListAsync(ct);
        if (reports.Count == 0) return null;

        var reportIds = reports.Select(r => r.Id).ToArray();
        var suites = await db.TestSuiteResults.AsNoTracking()
            .Where(s => reportIds.Contains(s.TestRunReportId) && (s.FailedCount > 0 || s.SkippedCount > 0))
            .OrderByDescending(s => s.FailedCount).ThenByDescending(s => s.SkippedCount)
            .Select(s => new TestSuiteRow(s.AssemblyName + " · " + s.ClassName, s.FailedCount, s.SkippedCount))
            .Take(200).ToListAsync(ct);

        // Full per-assembly breakdown (the "what was actually tested" evidence), failing-first.
        var byAssembly = (await db.TestSuiteResults.AsNoTracking()
                .Where(s => reportIds.Contains(s.TestRunReportId))
                .GroupBy(s => s.AssemblyName)
                .Select(g => new TestAssemblyRow(g.Key, g.Sum(s => s.TotalCount), g.Sum(s => s.PassedCount), g.Sum(s => s.FailedCount), g.Sum(s => s.SkippedCount)))
                .ToListAsync(ct))
            .OrderByDescending(a => a.Failed).ThenByDescending(a => a.Skipped).ThenByDescending(a => a.Total)
            .ToList();
        var suiteCount = await db.TestSuiteResults.AsNoTracking().CountAsync(s => reportIds.Contains(s.TestRunReportId), ct);

        var head = reports[0];
        return new TestsSummary(
            reports.Sum(r => r.TotalCount), reports.Sum(r => r.PassedCount),
            reports.Sum(r => r.FailedCount), reports.Sum(r => r.SkippedCount), suites,
            head.ToolName, head.ToolVersion, reports.Max(r => (DateTimeOffset?)r.CompletedAt),
            reports.Sum(r => r.DurationMs), suiteCount, byAssembly.Count, byAssembly);
    }

    /// <summary>Failed test cases for a build — name, class, assembly, error message + stack trace. The
    /// actual proof of what broke, not just a count (TFND-217).</summary>
    public async Task<IReadOnlyList<TestFailureRow>> TestFailuresAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];
        var reportIds = await db.TestRunReports.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId)).Select(r => r.Id).ToArrayAsync(ct);
        if (reportIds.Length == 0) return [];

        return await db.TestCaseResults.AsNoTracking()
            .Where(c => reportIds.Contains(c.Suite!.TestRunReportId) && c.Outcome == Domain.Values.TestOutcome.Failed)
            .OrderBy(c => c.Suite!.AssemblyName).ThenBy(c => c.Suite!.ClassName).ThenBy(c => c.Name)
            .Take(500)
            .Select(c => new TestFailureRow(c.Suite!.AssemblyName, c.Suite!.ClassName, c.Name, c.ErrorMessage, c.ErrorStackTrace))
            .ToListAsync(ct);
    }

    /// <summary>Per-build test evidence for the history strip — commit, when, tool, counts, coverage.</summary>
    public async Task<IReadOnlyList<TestScanHistoryRow>> TestScanHistoryAsync(Guid projectId, int take = 12, CancellationToken ct = default)
    {
        var cvs = await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.ProjectId == projectId && cv.CommitSha != null)
            .OrderByDescending(cv => cv.CreatedAt).Take(take)
            .Select(cv => new { cv.Id, cv.CommitSha, cv.CreatedAt })
            .ToListAsync(ct);
        if (cvs.Count == 0) return [];
        var ids = cvs.Select(c => c.Id).ToArray();

        var reports = (await db.TestRunReports.AsNoTracking()
                .Where(r => ids.Contains(r.ComponentVersionId))
                .Select(r => new { r.ComponentVersionId, r.ToolName, r.TotalCount, r.PassedCount, r.FailedCount, r.SkippedCount })
                .ToListAsync(ct))
            .ToDictionary(r => r.ComponentVersionId);
        var coverage = (await db.CoverageReports.AsNoTracking()
                .Where(r => ids.Contains(r.ComponentVersionId))
                .Select(r => new { r.ComponentVersionId, r.SequenceCoverage })
                .ToListAsync(ct))
            .GroupBy(r => r.ComponentVersionId).ToDictionary(g => g.Key, g => g.First().SequenceCoverage);

        return cvs.Select(c =>
        {
            reports.TryGetValue(c.Id, out var r);
            return new TestScanHistoryRow(
                c.CommitSha, c.CreatedAt, r is not null, r?.ToolName,
                r?.TotalCount ?? 0, r?.PassedCount ?? 0, r?.FailedCount ?? 0, r?.SkippedCount ?? 0,
                coverage.TryGetValue(c.Id, out var cov) ? cov : null);
        }).ToList();
    }

    /// <summary>The stored raw artifacts of a kind for a build, for download (evidence of record).</summary>
    public async Task<BuildRawArtifacts?> RawArtifactsAsync(Guid projectId, string? commitSha, Domain.Values.RawArtifactKind kind, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return null;
        var cvId = cvIds[0];
        var arts = await db.RawReportArtifacts.AsNoTracking()
            .Where(a => a.ComponentVersionId == cvId && a.Kind == kind)
            .OrderBy(a => a.FileName ?? a.Format).ThenBy(a => a.IngestedAt)
            .Select(a => new RawArtifactRef(a.Id, a.Format, a.FileName, a.SizeBytes, a.IngestedAt))
            .ToListAsync(ct);
        return arts.Count == 0 ? null : new BuildRawArtifacts(cvId, arts);
    }

    /// <summary>Licence mix for the `license` category.</summary>
    public async Task<IReadOnlyList<LicenseGroup>> LicensesAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var snapIds = await SnapshotIdsAsync(projectId, commitSha, ct);
        if (snapIds.Length == 0) return [];

        var groups = await db.SbomComponents.AsNoTracking()
            .Where(c => snapIds.Contains(c.SbomSnapshotId))
            .GroupBy(c => c.License)
            .Select(g => new { g.Key, Count = g.Count() })
            .OrderByDescending(g => g.Count)
            .ToListAsync(ct);

        return groups.Select(g => new LicenseGroup(g.Key ?? "unknown", g.Count)).ToArray();
    }

    /// <summary>
    /// Everything the license category page needs to be self-explanatory (TFND-222):
    /// the tier of each license, the policy in force, WHY the score is what it is,
    /// and the still-unknown packages a human can resolve. Applies the global
    /// license knowledge base before classifying — the same map the scorer uses —
    /// so the page and the number agree.
    /// </summary>
    public async Task<LicenseOverview?> LicenseOverviewAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var snapIds = await SnapshotIdsAsync(projectId, commitSha, ct);
        if (snapIds.Length == 0) return null;

        var comps = await db.SbomComponents.AsNoTracking()
            .Where(c => snapIds.Contains(c.SbomSnapshotId))
            .Select(c => new { c.Purl, c.Name, c.Version, c.License })
            .ToListAsync(ct);
        if (comps.Count == 0) return null;

        var policy = await LicensePolicyAsync(projectId, ct);
        var rules = policy.Licenses;
        var map = await licenses.MapAsync(ct);

        // Apply the knowledge base, then classify — exactly as the scorer does.
        string Effective(string purl, string? declared) =>
            map.TryGetValue(purl, out var s) ? s : (declared ?? "");

        var resolvedApplied = 0;
        var tierCounts = new Dictionary<LicensePolicy.Tier, int>();
        var groups = new Dictionary<string, (LicensePolicy.Tier Tier, int Count)>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in comps)
        {
            var eff = Effective(c.Purl, c.License);
            if (map.ContainsKey(c.Purl)) resolvedApplied++;
            var tier = LicensePolicy.Classify(string.IsNullOrWhiteSpace(eff) ? null : eff, rules);
            tierCounts[tier] = tierCounts.GetValueOrDefault(tier) + 1;
            var label = string.IsNullOrWhiteSpace(eff) ? "unknown" : eff;
            var cur = groups.GetValueOrDefault(label);
            groups[label] = (tier, cur.Count + 1);
        }

        // Still-unknown packages, distinct by purl — the human-resolution worklist.
        var unknowns = comps
            .Where(c => LicensePolicy.Classify(
                string.IsNullOrWhiteSpace(Effective(c.Purl, c.License)) ? null : Effective(c.Purl, c.License), rules)
                == LicensePolicy.Tier.Unknown)
            .GroupBy(c => c.Purl, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
            .Select(c => new UnknownComponent(c.Purl, c.Name, c.Version, c.License))
            .ToArray();

        var total = comps.Count;
        int Count(LicensePolicy.Tier t) => tierCounts.GetValueOrDefault(t);
        var denied = Count(LicensePolicy.Tier.Denied);
        var strong = Count(LicensePolicy.Tier.StrongCopyleft);
        var unknown = Count(LicensePolicy.Tier.Unknown);

        // The score math, mirrored from RiskScorer's License case so the page can
        // show its own working.
        double W(string k, double dflt) =>
            policy.Categories.TryGetValue(RiskCategoryNames.License, out var cat) && cat.Weights.TryGetValue(k, out var w)
                ? w : dflt;
        var wDenied = W("denied", 0.5);
        var wStrong = W("strongCopyleft", 0.1);
        var wUnknownMul = W("unknownPctMul", 0.2);
        var catMax = policy.Categories.TryGetValue(RiskCategoryNames.License, out var lc) && lc.Max > 0 ? lc.Max : 5;
        var unknownPct = (double)unknown / Math.Max(1, total);
        var raw = Math.Clamp(denied * wDenied + strong * wStrong + unknownPct * wUnknownMul, 0, 1);

        var groupRows = groups
            .Select(kv => new LicenseTierGroup(kv.Key, kv.Value.Tier, kv.Value.Count))
            .OrderByDescending(g => g.Tier == LicensePolicy.Tier.Denied)
            .ThenByDescending(g => g.Tier == LicensePolicy.Tier.StrongCopyleft)
            .ThenByDescending(g => g.Tier == LicensePolicy.Tier.Unknown)
            .ThenByDescending(g => g.Count)
            .ToArray();

        return new LicenseOverview(
            groupRows, unknowns, total,
            denied, strong, Count(LicensePolicy.Tier.WeakCopyleft), Count(LicensePolicy.Tier.Permissive), unknown,
            wDenied, wStrong, wUnknownMul, catMax, raw * catMax,
            rules.Deny.ToArray(), rules.Allow.ToArray(), rules.DenyUnknown, resolvedApplied);
    }

    /// <summary>The policy in force for a project — project override, then client, then instance
    /// default (the chain the scorer walks). Empty config when the instance has no default.</summary>
    private async Task<RiskPolicyConfig> LicensePolicyAsync(Guid projectId, CancellationToken ct)
    {
        var project = await db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new { p.RiskPolicyId, ClientPolicyId = p.Client!.RiskPolicyId })
            .SingleOrDefaultAsync(ct);
        var policyId = project?.RiskPolicyId ?? project?.ClientPolicyId;
        var policy = policyId is { } id
            ? await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct)
            : null;
        policy ??= await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        return policy?.Config ?? new RiskPolicyConfig();
    }

    /// <summary>The outdated SBOM components behind the `sbomStaleness` score.
    ///
    /// Mirrors RiskInputsBuilder EXACTLY so the list and the number cannot
    /// disagree: skip vulnerable rows (they score under cve, not here), keep the
    /// rows with a newer version available (<c>outdated</c>), and mark the ones
    /// whose newer release itself shipped over 180 days ago (<c>stale</c> — you
    /// have had the time to adopt it and have not).</summary>
    public async Task<IReadOnlyList<StaleComponent>> SbomStalenessAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var snapIds = await SnapshotIdsAsync(projectId, commitSha, ct);
        if (snapIds.Length == 0) return [];

        var cutoff = DateTimeOffset.UtcNow.AddDays(-180);
        var rows = await db.SbomComponents.AsNoTracking()
            .Where(c => snapIds.Contains(c.SbomSnapshotId)
                && c.Vulnerabilities.Count == 0
                && c.LatestVersion != null && c.LatestVersion != "" && c.LatestVersion != c.Version)
            .Select(c => new { c.Name, c.Version, c.LatestVersion, c.LatestReleasedAt })
            .ToListAsync(ct);

        var now = DateTimeOffset.UtcNow;
        return rows
            .Select(c => new StaleComponent(
                c.Name, c.Version, c.LatestVersion,
                c.LatestReleasedAt is { } at ? (int)(now - at).TotalDays : null,
                c.LatestReleasedAt is { } s && s < cutoff))
            .OrderByDescending(c => c.Stale)
            .ThenByDescending(c => c.DaysBehind ?? -1)
            .ThenBy(c => c.Name)
            .Take(100).ToArray();
    }

    /// <summary>Scan-run receipts for the `missingScanners` category — which scanners ran.</summary>
    public async Task<IReadOnlyList<ReceiptRow>> ReceiptsAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];

        return await db.ScanRunReceipts.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .OrderBy(r => r.Scanner)
            .Select(r => new ReceiptRow(r.Scanner, r.Status.ToString(), r.FindingsCount, r.CompletedAt, r.ToolName, r.ToolVersion, r.Notes))
            .ToListAsync(ct);
    }

    /// <summary>Everything the quality surfaces show for one build: type-routed findings (SonarQube or
    /// any quality-lane tool), the SonarQube quality-gate verdict with its named conditions, analysis
    /// coverage, the scan-run provenance, and per-build history. "Ran" is true only with real evidence
    /// (a successful quality receipt, a gate verdict or findings) — never inferred from a bare zero.</summary>
    public async Task<QualityOverview> QualityOverviewAsync(Guid projectId, string? commitSha, CancellationToken ct = default)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return QualityOverview.Empty;

        var dupeIds = (await FindingDedupe.DuplicateIdsAsync(db, cvIds, ct)).ToArray();
        var findings = await Filter("quality", db.Findings.AsNoTracking().Where(f => cvIds.Contains(f.ComponentVersionId) && !dupeIds.Contains(f.Id)))!
            .OrderByDescending(f => f.Severity).ThenBy(f => f.FilePath).ThenBy(f => f.Line)
            .Select(f => new CategoryFinding(
                f.Id, f.Scanner, f.RuleId, f.Severity, f.Title, f.Description,
                f.FilePath, f.Line, f.Snippet, f.SubCategory, f.Status, f.FirstSeen))
            .ToListAsync(ct);

        var qualityKinds = QualityScanners.Append(ScannerKind.SonarQube).ToArray();
        var receipts = await db.ScanRunReceipts.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId) && qualityKinds.Contains(r.Scanner))
            .OrderBy(r => r.Scanner)
            .Select(r => new ReceiptRow(r.Scanner, r.Status.ToString(), r.FindingsCount, r.CompletedAt, r.ToolName, r.ToolVersion, r.Notes))
            .ToListAsync(ct);

        var gateRow = await db.QualityGateResults.AsNoTracking()
            .Where(g => cvIds.Contains(g.ComponentVersionId))
            .OrderByDescending(g => g.ObservedAt)
            .FirstOrDefaultAsync(ct);
        QualityGateView? gate = gateRow is null ? null : new QualityGateView(
            gateRow.Status, ParseConditions(gateRow.ConditionsJson), ParseMeasures(gateRow.MeasuresJson),
            gateRow.Source, gateRow.AnalysisId, gateRow.ObservedAt);

        var cov = await db.AnalysisCoverageReports.AsNoTracking().Include(r => r.Languages)
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .OrderByDescending(r => r.ObservedAt)
            .FirstOrDefaultAsync(ct);
        AnalysisCoverageView? coverage = cov is null ? null : new AnalysisCoverageView(
            cov.Languages.OrderByDescending(l => l.LinesTotal)
                .Select(l => new AnalysisLanguageRow(l.Language, l.FilesAnalyzed, l.FilesTotal, l.LinesTotal, l.PercentAnalyzed, l.AnalyzedBy, l.UnanalyzedSample))
                .ToList(),
            SplitList(cov.GapLanguages), SplitList(cov.Excludes), cov.ObservedAt);

        var ran = findings.Count > 0 || gate is not null
            || receipts.Any(r => r.Status == "Succeeded");

        return new QualityOverview(ran, findings, receipts, gate, coverage, await QualityHistoryAsync(projectId, ct));
    }

    private async Task<IReadOnlyList<QualityHistoryRow>> QualityHistoryAsync(Guid projectId, CancellationToken ct)
    {
        var cvs = await db.ComponentVersions.AsNoTracking()
            .Where(cv => cv.ProjectId == projectId && cv.CommitSha != null)
            .OrderByDescending(cv => cv.CreatedAt).Take(12)
            .Select(cv => new { cv.Id, cv.CommitSha, cv.CreatedAt })
            .ToListAsync(ct);
        if (cvs.Count == 0) return [];
        var ids = cvs.Select(c => c.Id).ToArray();

        var histDupes = (await FindingDedupe.DuplicateIdsAsync(db, ids, ct)).ToArray();
        var counts = (await Filter("quality", db.Findings.AsNoTracking().Where(f => ids.Contains(f.ComponentVersionId) && !histDupes.Contains(f.Id)))!
                .GroupBy(f => f.ComponentVersionId)
                .Select(g => new { CvId = g.Key, Count = g.Count() })
                .ToListAsync(ct))
            .ToDictionary(x => x.CvId, x => x.Count);
        var gates = (await db.QualityGateResults.AsNoTracking()
                .Where(g => ids.Contains(g.ComponentVersionId))
                .Select(g => new { g.ComponentVersionId, g.Status, g.ConditionsJson })
                .ToListAsync(ct))
            .GroupBy(g => g.ComponentVersionId).ToDictionary(g => g.Key, g => g.First());

        return cvs.Select(c =>
        {
            gates.TryGetValue(c.Id, out var g);
            var conds = g is null ? [] : ParseConditions(g.ConditionsJson);
            return new QualityHistoryRow(c.CommitSha, c.CreatedAt, counts.GetValueOrDefault(c.Id, 0),
                g?.Status, conds.Count(x => x.Failed), conds.Count);
        }).ToList();
    }

    private static IReadOnlyList<string> SplitList(string? s) =>
        string.IsNullOrWhiteSpace(s) ? [] : s.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

    private static IReadOnlyList<QualityCondition> ParseConditions(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Array) return [];
            static string? Str(System.Text.Json.JsonElement e, string n) =>
                e.TryGetProperty(n, out var v) ? (v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : v.ToString()) : null;
            return doc.RootElement.EnumerateArray()
                .Select(c => new QualityCondition(Str(c, "Metric") ?? "?", Str(c, "Op"), Str(c, "Threshold"), Str(c, "Actual"),
                    string.Equals(Str(c, "Status"), "ERROR", StringComparison.OrdinalIgnoreCase)))
                .ToList();
        }
        catch { return []; }
    }

    private static IReadOnlyList<KeyValuePair<string, string>> ParseMeasures(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object) return [];
            return doc.RootElement.EnumerateObject()
                .Select(p => KeyValuePair.Create(p.Name, p.Value.ToString())).ToList();
        }
        catch { return []; }
    }

    private async Task<Guid[]> SnapshotIdsAsync(Guid projectId, string? commitSha, CancellationToken ct)
    {
        var cvIds = await ResolveCvIdsAsync(projectId, commitSha, ct);
        if (cvIds.Length == 0) return [];
        return await db.SbomSnapshots.AsNoTracking()
            .Where(s => cvIds.Contains(s.ComponentVersionId))
            .Select(s => s.Id).ToArrayAsync(ct);
    }

    // Whether a category key is answered by this query (a findings table).
    public static bool IsFindingsCategory(string key) => key is
        "sastSevere" or "sastLow" or "secrets" or "iacSevere";

    private static readonly ScannerKind[] Sast = ScannerKinds.Sast.ToArray();
    private static readonly ScannerKind[] QualityScanners = ScannerKinds.Quality.ToArray();

    private static IQueryable<Finding>? Filter(string key, IQueryable<Finding> q) => key switch
    {
        // Typed-unified routing (TFND-175), mirroring RiskInputsBuilder so the list and the score
        // agree: the issue TYPE on SubCategory wins over the scanner's default bucket. A code smell
        // (any tool) is quality and can never ride criticalSast; a security issue (any tool but Trivy,
        // whose "vulnerability" rows are CVEs) is SAST.
        "quality" => q.Where(f => QualityScanners.Contains(f.Scanner)
            || f.SubCategory == "bug" || f.SubCategory == "code_smell"),
        "sastSevere" => q.Where(f =>
            f.SubCategory != "bug" && f.SubCategory != "code_smell"
            && (Sast.Contains(f.Scanner)
                || ((f.SubCategory == "vulnerability" && f.Scanner != ScannerKind.Trivy) || f.SubCategory == "security_hotspot"))
            && (f.Severity == Severity.Critical || f.Severity == Severity.High)),
        "sastLow" => q.Where(f =>
            f.SubCategory != "bug" && f.SubCategory != "code_smell"
            && (Sast.Contains(f.Scanner)
                || ((f.SubCategory == "vulnerability" && f.Scanner != ScannerKind.Trivy) || f.SubCategory == "security_hotspot"))
            && (f.Severity == Severity.Medium || f.Severity == Severity.Low)),
        // Secrets: TruffleHog, plus Trivy rows tagged secret.
        "secrets" => q.Where(f => f.Scanner == ScannerKind.TruffleHog
            || (f.Scanner == ScannerKind.Trivy && f.SubCategory == "secret")),
        // IaC: Trivy misconfiguration (or untagged Trivy), severe only.
        "iacSevere" => q.Where(f => f.Scanner == ScannerKind.Trivy
            && (f.SubCategory == null || f.SubCategory == "misconfiguration")
            && (f.Severity == Severity.Critical || f.Severity == Severity.High)),
        _ => null,
    };
}

public sealed record CategoryFinding(
    Guid Id,
    ScannerKind Scanner,
    string RuleId,
    Severity Severity,
    string Title,
    string? Description,
    string? FilePath,
    int? Line,
    string? Snippet,
    string? SubCategory,
    FindingStatus Status,
    DateTimeOffset FirstSeen);

public sealed record CveRow(
    string AdvisoryId, Severity Severity, string Package, string Version,
    double? Cvss, string? FixedIn, string? ReferenceUrl);

public sealed record CoverageSummary(
    double SequencePercent, int CoveredSequences, int TotalSequences,
    double BranchPercent, int CoveredBranches, int TotalBranches);

public sealed record TestsSummary(
    int Total, int Passed, int Failed, int Skipped, IReadOnlyList<TestSuiteRow> Suites,
    // TFND-217: provenance so "N passed" is evidence, not just a number.
    string? ToolName = null, string? ToolVersion = null, DateTimeOffset? CompletedAt = null,
    double DurationMs = 0, int SuiteCount = 0, int AssemblyCount = 0,
    IReadOnlyList<TestAssemblyRow>? Assemblies = null);

public sealed record TestAssemblyRow(string Assembly, int Total, int Passed, int Failed, int Skipped);
public sealed record TestFailureRow(string Assembly, string ClassName, string Name, string? ErrorMessage, string? ErrorStackTrace);
public sealed record TestScanHistoryRow(
    string? CommitSha, DateTimeOffset BuiltAt, bool Measured, string? ToolName,
    int Total, int Passed, int Failed, int Skipped, double? CoveragePercent);
public sealed record RawArtifactRef(Guid Id, string Format, string? FileName, long SizeBytes, DateTimeOffset IngestedAt);
public sealed record BuildRawArtifacts(Guid ComponentVersionId, IReadOnlyList<RawArtifactRef> Artifacts);

public sealed record TestSuiteRow(string Suite, int Failed, int Skipped);

public sealed record LicenseGroup(string License, int Count);

/// <summary>A license row with its resolved permissiveness tier and how many components carry it.</summary>
public sealed record LicenseTierGroup(string License, LicensePolicy.Tier Tier, int Count);

/// <summary>A package whose license is still unknown after the knowledge base — a resolution candidate.</summary>
public sealed record UnknownComponent(string Purl, string Name, string Version, string? DeclaredLicense);

/// <summary>Self-explaining data for the license category page (TFND-222).</summary>
public sealed record LicenseOverview(
    IReadOnlyList<LicenseTierGroup> Groups,
    IReadOnlyList<UnknownComponent> Unknowns,
    int TotalComponents,
    int DeniedCount, int StrongCopyleftCount, int WeakCopyleftCount, int PermissiveCount, int UnknownCount,
    double WeightDenied, double WeightStrongCopyleft, double WeightUnknownPctMul, double CategoryMax,
    double DisplayedScore,
    IReadOnlyList<string> PolicyDeny, IReadOnlyList<string> PolicyAllow, bool DenyUnknown,
    int ResolvedApplied);

public sealed record StaleComponent(string Name, string Version, string? LatestVersion, int? DaysBehind, bool Stale);

public sealed record ReceiptRow(
    ScannerKind Scanner, string Status, int FindingsCount, DateTimeOffset? CompletedAt, string? ToolName,
    string? ToolVersion = null, string? Notes = null);

// Per-build CVE scan evidence for the history strip (TFND-217): commit, when it was built, whether an
// SCA scan actually ran, the scanner + version, its advisory-DB provenance (receipt notes), CVE count.
public sealed record CveScanHistoryRow(
    string? CommitSha, DateTimeOffset BuiltAt, bool Scanned,
    string? ScannerTool, string? ScannerVersion, string? Notes, int CveCount);

public sealed record QualityCondition(string Metric, string? Op, string? Threshold, string? Actual, bool Failed);
public sealed record QualityGateView(
    string Status, IReadOnlyList<QualityCondition> Conditions, IReadOnlyList<KeyValuePair<string, string>> Measures,
    string? Source, string? AnalysisId, DateTimeOffset ObservedAt);
public sealed record AnalysisLanguageRow(
    string Language, int FilesAnalyzed, int FilesTotal, long Lines, double PercentAnalyzed, string? AnalyzedBy, string? UnanalyzedSample);
public sealed record AnalysisCoverageView(
    IReadOnlyList<AnalysisLanguageRow> Languages, IReadOnlyList<string> GapLanguages,
    IReadOnlyList<string> Excludes, DateTimeOffset ObservedAt);
public sealed record QualityHistoryRow(
    string? CommitSha, DateTimeOffset BuiltAt, int FindingCount, string? GateStatus, int FailedConditions, int TotalConditions);
public sealed record QualityOverview(
    bool Ran, IReadOnlyList<CategoryFinding> Findings, IReadOnlyList<ReceiptRow> Receipts,
    QualityGateView? Gate, AnalysisCoverageView? Coverage, IReadOnlyList<QualityHistoryRow> History)
{
    public static readonly QualityOverview Empty = new(false, [], [], null, null, []);
}
