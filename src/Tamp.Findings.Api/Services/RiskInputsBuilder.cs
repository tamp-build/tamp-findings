using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Services;

// Builds RiskInputs for an explicit set of ComponentVersions. The
// /aggregates endpoint computes the same shape inline against the
// project's "latest canonical" CV set; this service is for the
// per-build evaluator path where we need to score a specific commit's
// CV set OR an arbitrary prior CV set.
public sealed class RiskInputsBuilder(FindingsDbContext db)
{
    private static readonly HashSet<ScannerKind> SastSet =
    [
        ScannerKind.Roslyn, ScannerKind.ReSharper, ScannerKind.OpenGrep,
        ScannerKind.CodeQL, ScannerKind.ESLint,
    ];

    public async Task<RiskInputs> BuildAsync(IReadOnlyList<Guid> cvIds, RiskPolicyConfig policy, CancellationToken ct)
    {
        if (cvIds.Count == 0) return Empty();

        // Open findings grouped by scanner + severity + sub-category.
        // SubCategory disambiguates Trivy's misconfig vs secret rows.
        var rawFindings = await db.Findings.AsNoTracking()
            .Where(f => cvIds.Contains(f.ComponentVersionId) && f.Status == FindingStatus.Open)
            .GroupBy(f => new { f.Scanner, f.Severity, f.SubCategory })
            .Select(g => new { g.Key.Scanner, g.Key.Severity, g.Key.SubCategory, Count = g.Count() })
            .ToListAsync(ct);

        // Apply per-scanner severity ceiling from the policy BEFORE
        // bucketing — preserves SubCategory so Trivy stays split across
        // IaC vs secret. Default (no overrides) leaves data unchanged.
        var findings = rawFindings
            .Select(x => new
            {
                x.Scanner,
                Severity = CapSeverity(x.Scanner, x.Severity, policy.ScannerOverrides),
                x.SubCategory,
                x.Count,
            })
            .ToList();

        var sastCrit = findings.Where(x => SastSet.Contains(x.Scanner) && x.Severity == Severity.Critical).Sum(x => x.Count);
        var sastHigh = findings.Where(x => SastSet.Contains(x.Scanner) && x.Severity == Severity.High).Sum(x => x.Count);
        var sastMed  = findings.Where(x => SastSet.Contains(x.Scanner) && x.Severity == Severity.Medium).Sum(x => x.Count);
        var sastLow  = findings.Where(x => SastSet.Contains(x.Scanner) && x.Severity == Severity.Low).Sum(x => x.Count);

        // Trivy splits across IaC vs secret vs vuln via SubCategory.
        bool IsIac(ScannerKind s, string? sub) => s == ScannerKind.Trivy && (sub is null || sub == "misconfiguration");
        var iacCrit = findings.Where(x => IsIac(x.Scanner, x.SubCategory) && x.Severity == Severity.Critical).Sum(x => x.Count);
        var iacHigh = findings.Where(x => IsIac(x.Scanner, x.SubCategory) && x.Severity == Severity.High).Sum(x => x.Count);

        bool IsSecret(ScannerKind s, string? sub) => s == ScannerKind.TruffleHog
            || (s == ScannerKind.Trivy && sub == "secret");
        var secretsVerified   = findings.Where(x => IsSecret(x.Scanner, x.SubCategory) && x.Severity == Severity.Critical).Sum(x => x.Count);
        var secretsUnverified = findings.Where(x => IsSecret(x.Scanner, x.SubCategory) && x.Severity == Severity.High).Sum(x => x.Count);

        // CVE severities — Vulnerabilities live on SbomComponents under
        // SbomSnapshots whose CV is in the set.
        var cveBySev = await db.Vulnerabilities.AsNoTracking()
            .Where(v => cvIds.Contains(v.SbomComponent!.SbomSnapshot!.ComponentVersionId))
            .GroupBy(v => v.Severity)
            .Select(g => new { Sev = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Sev, x => x.Count, ct);

        // KEV exposure — count distinct (AdvisoryId, SbomComponentId)
        // tuples where the advisory is on the CISA Known Exploited
        // Vulnerabilities catalog. JOIN on AdvisoryId == CveId; the KEV
        // cache is small (~1k rows) so EF translates this efficiently.
        var kevListedCves = await db.Vulnerabilities.AsNoTracking()
            .Where(v => cvIds.Contains(v.SbomComponent!.SbomSnapshot!.ComponentVersionId))
            .Where(v => db.KevAdvisories.Any(k => k.CveId == v.AdvisoryId))
            .CountAsync(ct);

        // SBOM components: count + health buckets + license tiers.
        var snapshots = await db.SbomSnapshots.AsNoTracking()
            .Where(s => cvIds.Contains(s.ComponentVersionId))
            .Select(s => new { s.Id })
            .ToListAsync(ct);
        var snapshotIds = snapshots.Select(s => s.Id).ToList();
        var sbomComponents = await db.SbomComponents.AsNoTracking()
            .Where(c => snapshotIds.Contains(c.SbomSnapshotId))
            .Select(c => new
            {
                c.Version, c.LatestVersion, c.LatestReleasedAt, c.License,
                VulnCount = c.Vulnerabilities.Count,
            })
            .ToListAsync(ct);

        var compsCount = sbomComponents.Count;
        var staleCutoff = DateTimeOffset.UtcNow.AddDays(-180);
        int outdated = 0, stale = 0;
        var denied = 0; var strong = 0; var unknown = 0;
        foreach (var c in sbomComponents)
        {
            // Vulnerable trumps outdated/stale in the health roll-up;
            // for the scorer's stale-input we only count the strictly
            // outdated rows here, mirroring /aggregates.
            if (c.VulnCount > 0) continue;
            var hasNewer = !string.IsNullOrEmpty(c.LatestVersion) && c.LatestVersion != c.Version;
            if (hasNewer)
            {
                outdated++;
                if (c.LatestReleasedAt is { } when_ && when_ < staleCutoff) stale++;
            }
        }
        foreach (var c in sbomComponents)
        {
            switch (LicensePolicy.Classify(c.License))
            {
                case LicensePolicy.Tier.StrongCopyleft: strong++; break;
                case LicensePolicy.Tier.Denied:         denied++; break;
                case LicensePolicy.Tier.Unknown:        unknown++; break;
            }
        }

        // Coverage: sum across reports tied to these CVs.
        var coverageReports = await db.CoverageReports.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .Select(r => new { r.CoveredSequences, r.TotalSequences })
            .ToListAsync(ct);
        var coverageMeasured = coverageReports.Count > 0;
        var coveredSeq = coverageReports.Sum(r => r.CoveredSequences);
        var totalSeq = coverageReports.Sum(r => r.TotalSequences);
        var coveragePct = totalSeq == 0 ? 0 : 100.0 * coveredSeq / totalSeq;

        // Tests: sum across reports tied to these CVs.
        var testReports = await db.TestRunReports.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId))
            .Select(r => new { r.TotalCount, r.FailedCount })
            .ToListAsync(ct);
        var testsMeasured = testReports.Count > 0;
        var testsTotal = testReports.Sum(r => r.TotalCount);
        var testsFailed = testReports.Sum(r => r.FailedCount);

        // Which scanner classes left a successful receipt in scope.
        var receipts = await db.ScanRunReceipts.AsNoTracking()
            .Where(r => cvIds.Contains(r.ComponentVersionId) && r.Status == ScanRunStatus.Succeeded)
            .Select(r => r.Scanner)
            .ToListAsync(ct);
        var receiptSet = new HashSet<ScannerKind>(receipts);
        var ranSast = SastSet.Any(s => receiptSet.Contains(s));
        var ranSecrets = receiptSet.Contains(ScannerKind.TruffleHog);
        var ranIac = receiptSet.Contains(ScannerKind.Trivy);
        var ranSbom = compsCount > 0 || receiptSet.Contains(ScannerKind.Syft) || receiptSet.Contains(ScannerKind.OsvScanner);
        var ranCoverage = coverageMeasured;

        return new RiskInputs(
            CveCritical: cveBySev.GetValueOrDefault(Severity.Critical, 0),
            CveHigh:     cveBySev.GetValueOrDefault(Severity.High, 0),
            CveMedium:   cveBySev.GetValueOrDefault(Severity.Medium, 0),
            CveLow:      cveBySev.GetValueOrDefault(Severity.Low, 0),
            KevListedCves: kevListedCves,
            SecretsVerified: secretsVerified, SecretsUnverified: secretsUnverified,
            SastCritical: sastCrit, SastHigh: sastHigh, SastMedium: sastMed, SastLow: sastLow,
            IacCritical: iacCrit, IacHigh: iacHigh,
            CoverageMeasured: coverageMeasured, SequenceCoveragePercent: coveragePct,
            SbomComponents: compsCount, SbomOutdated: outdated, SbomStale: stale,
            TestsMeasured: testsMeasured, TestsTotal: testsTotal, TestsFailed: testsFailed,
            LicenseDenied: denied, LicenseStrongCopyleft: strong, LicenseUnknown: unknown,
            RanSast: ranSast, RanSecrets: ranSecrets, RanIac: ranIac,
            RanSbom: ranSbom, RanCoverage: ranCoverage);
    }

    // Per-policy severity ceiling. Default (no override) returns the
    // ingested severity unchanged.
    private static Severity CapSeverity(ScannerKind scanner, Severity raw, IReadOnlyDictionary<string, ScannerOverride> overrides)
    {
        if (overrides.TryGetValue(scanner.ToString(), out var ov)
            && ov.SeverityCeiling is { } ceiling
            && raw > ceiling)
        {
            return ceiling;
        }
        return raw;
    }

    private static RiskInputs Empty() => new(
        0, 0, 0, 0, KevListedCves: 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        CoverageMeasured: false, SequenceCoveragePercent: 0,
        SbomComponents: 0, SbomOutdated: 0, SbomStale: 0,
        TestsMeasured: false, TestsTotal: 0, TestsFailed: 0,
        LicenseDenied: 0, LicenseStrongCopyleft: 0, LicenseUnknown: 0,
        RanSast: false, RanSecrets: false, RanIac: false, RanSbom: false, RanCoverage: false);
}
