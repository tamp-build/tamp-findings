using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Application coverage: every CategoryFindingsQuery method, every filter key, empty and populated builds.
[Collection(DatabaseCollection.Name)]
public class AppCovCategoryFindingsQueryTests
{
    private readonly DatabaseFixture _fx;
    public AppCovCategoryFindingsQueryTests(DatabaseFixture fx) => _fx = fx;

    private sealed record Seed(Guid ProjectId, Guid CvId, string Sha, string Suffix, Guid ClientId);

    private async Task<Seed> NewProjectAsync(bool withCv = true)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"cov-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"cov-project-{s}" };
        db.Clients.Add(client);
        db.Projects.Add(project);
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}aa" };
        if (withCv) db.ComponentVersions.Add(cv);
        await db.SaveChangesAsync();
        return new Seed(project.Id, cv.Id, cv.CommitSha!, s, client.Id);
    }

    private static Finding F(Guid cv, ScannerKind sc, Severity sev, string? sub, string tag) => new()
    {
        ComponentVersionId = cv, Hash = $"{tag}-{Guid.NewGuid():N}", Scanner = sc, RuleId = $"rule-{tag}",
        Severity = sev, Title = $"t-{tag}", FilePath = $"f/{tag}.cs", Line = 3, SubCategory = sub,
    };

    [SkippableFact]
    public async Task Empty_project_returns_empty_everywhere()
    {
        Skip.IfNot(_fx.Available);
        var p = await NewProjectAsync(withCv: false);
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        Assert.Empty(await q.LoadAsync(p.ProjectId, null, "secrets"));
        Assert.Empty(await q.CvesAsync(p.ProjectId, null));
        Assert.Empty(await q.CveScanHistoryAsync(p.ProjectId));
        Assert.Null(await q.CoverageAsync(p.ProjectId, null));
        Assert.Null(await q.TestsAsync(p.ProjectId, null));
        Assert.Empty(await q.TestFailuresAsync(p.ProjectId, null));
        Assert.Empty(await q.TestScanHistoryAsync(p.ProjectId));
        Assert.Null(await q.RawArtifactsAsync(p.ProjectId, null, RawArtifactKind.Coverage));
        Assert.Empty(await q.LicensesAsync(p.ProjectId, null));
        Assert.Null(await q.LicenseOverviewAsync(p.ProjectId, null));
        Assert.Empty(await q.SbomStalenessAsync(p.ProjectId, null));
        Assert.Empty(await q.StalenessClosureAsync(p.ProjectId, null, "pkg:nuget/x@1"));
        Assert.Null(await q.SbomSummaryAsync(p.ProjectId, null));
        Assert.Empty(await q.ReceiptsAsync(p.ProjectId, null));
        Assert.Same(QualityOverview.Empty, await q.QualityOverviewAsync(p.ProjectId, null));
    }

    [SkippableFact]
    public async Task Build_without_any_data_returns_null_or_empty()
    {
        Skip.IfNot(_fx.Available);
        var p = await NewProjectAsync();
        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        Assert.Empty(await q.LoadAsync(p.ProjectId, p.Sha, "sastSevere"));
        Assert.Empty(await q.LoadAsync(p.ProjectId, p.Sha, "nonsense"));
        Assert.Null(await q.CoverageAsync(p.ProjectId, p.Sha));
        Assert.Null(await q.TestsAsync(p.ProjectId, p.Sha));
        Assert.Empty(await q.TestFailuresAsync(p.ProjectId, p.Sha));
        Assert.Null(await q.RawArtifactsAsync(p.ProjectId, p.Sha, RawArtifactKind.TestResults));
        Assert.Empty(await q.LicensesAsync(p.ProjectId, p.Sha));
        Assert.Null(await q.LicenseOverviewAsync(p.ProjectId, p.Sha));
        Assert.Null(await q.SbomSummaryAsync(p.ProjectId, p.Sha));
        var hist = await q.TestScanHistoryAsync(p.ProjectId);
        Assert.False(hist.Single().Measured);
        var cveHist = await q.CveScanHistoryAsync(p.ProjectId);
        Assert.False(cveHist.Single().Scanned);
        var qo = await q.QualityOverviewAsync(p.ProjectId, p.Sha);
        Assert.False(qo.Ran);
        Assert.Null(qo.Gate);
        Assert.Null(qo.Coverage);
        Assert.Single(qo.History);
    }

    [SkippableFact]
    public async Task Findings_filters_route_every_scanner_and_severity()
    {
        Skip.IfNot(_fx.Available);
        var p = await NewProjectAsync();
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var i = 0;
            foreach (var sc in Enum.GetValues<ScannerKind>())
                foreach (var sev in Enum.GetValues<Severity>())
                    foreach (var sub in new string?[] { null, "vulnerability", "security_hotspot", "bug", "code_smell", "secret", "misconfiguration" })
                        db.Findings.Add(F(p.CvId, sc, sev, sub, $"x{i++}"));
            await db.SaveChangesAsync();
        }

        using var s2 = _fx.Scope();
        var q = s2.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        var severe = await q.LoadAsync(p.ProjectId, p.Sha, "sastSevere");
        var low = await q.LoadAsync(p.ProjectId, p.Sha, "sastLow");
        var secrets = await q.LoadAsync(p.ProjectId, p.Sha, "secrets");
        var iac = await q.LoadAsync(p.ProjectId, p.Sha, "iacSevere");
        var quality = await q.LoadAsync(p.ProjectId, p.Sha, "quality");

        Assert.NotEmpty(severe); Assert.NotEmpty(low); Assert.NotEmpty(secrets); Assert.NotEmpty(iac); Assert.NotEmpty(quality);
        Assert.All(severe, f => Assert.True(f.Severity is Severity.Critical or Severity.High));
        Assert.All(low, f => Assert.True(f.Severity is Severity.Medium or Severity.Low));
        Assert.All(iac, f => Assert.Equal(ScannerKind.Trivy, f.Scanner));
        Assert.All(secrets, f => Assert.True(f.Scanner == ScannerKind.TruffleHog || f.SubCategory == "secret"));
        Assert.DoesNotContain(severe, f => f.SubCategory is "bug" or "code_smell");
        Assert.DoesNotContain(low, f => f.SubCategory is "bug" or "code_smell");
        // severity ordering is descending
        Assert.Equal(severe.Select(f => f.Severity).OrderByDescending(x => x), severe.Select(f => f.Severity));
        Assert.Empty(await q.LoadAsync(p.ProjectId, p.Sha, "cve"));
        // Default (no commit) resolves latest build.
        Assert.Equal(severe.Count, (await q.LoadAsync(p.ProjectId, null, "sastSevere")).Count);

        var qo = await q.QualityOverviewAsync(p.ProjectId, null);
        Assert.True(qo.Ran);
        Assert.Equal(quality.Count, qo.Findings.Count);

        Assert.True(CategoryFindingsQuery.IsFindingsCategory("secrets"));
        Assert.False(CategoryFindingsQuery.IsFindingsCategory("cve"));
    }

    [SkippableFact]
    public async Task Sbom_cves_licenses_staleness_and_summary()
    {
        Skip.IfNot(_fx.Available);
        var p = await NewProjectAsync();
        var spurl = "";
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var snap = new SbomSnapshot { ComponentVersionId = p.CvId, ToolName = "syft", ToolVersion = "1.0", SpecVersion = "1.5" };
            db.SbomSnapshots.Add(snap);
            SbomComponent C(string n, string v, string? lic, string? latest, int? releasedDaysAgo, bool dev = false, bool enriched = false) => new()
            {
                SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/{n}.{p.Suffix}@{v}", Name = $"{n}.{p.Suffix}", Version = v, License = lic,
                LatestVersion = latest, LatestReleasedAt = releasedDaysAgo is { } d ? DateTimeOffset.UtcNow.AddDays(-d) : null,
                DevDependency = dev, EnrichedAt = enriched ? DateTimeOffset.UtcNow : null,
            };
            var mit = C("Mit", "1.0.0", "MIT", "1.0.0", null, enriched: true);
            var gpl = C("Gpl", "1.0.0", "GPL-3.0-only", "2.0.0", 400);
            var unk = C("Unk", "1.0.0", null, "1.1.0", 10);
            var unk2 = C("Unk2", "1.0.0", "", null, null);
            var weird = C("Weird", "1.0.0", "LicenseRef-weird", "1.2.0", null, dev: true);
            var vuln = C("Vuln", "1.0.0", "Apache-2.0", "9.0.0", 300);
            db.SbomComponents.AddRange(mit, gpl, unk, unk2, weird, vuln);
            db.Vulnerabilities.AddRange(
                new Vulnerability { SbomComponentId = vuln.Id, AdvisoryId = "CVE-1", Severity = Severity.Critical, CvssScore = 9.8, FixedInVersion = "9.1", ReferenceUrl = "http://x" },
                new Vulnerability { SbomComponentId = vuln.Id, AdvisoryId = "CVE-2", Severity = Severity.Low });
            db.SbomDependencies.AddRange(
                new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = mit.Id, ChildComponentId = gpl.Id },
                new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = mit.Id, ChildComponentId = unk.Id });
            spurl = gpl.Purl;
            await db.SaveChangesAsync();
        }

        using var s2 = _fx.Scope();
        var q = s2.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        var cves = await q.CvesAsync(p.ProjectId, p.Sha);
        Assert.Equal(2, cves.Count);
        Assert.Equal("CVE-1", cves[0].AdvisoryId);

        var lic = await q.LicensesAsync(p.ProjectId, null);
        Assert.Contains(lic, l => l.License == "unknown");
        Assert.Contains(lic, l => l.License == "MIT");

        var ov = (await q.LicenseOverviewAsync(p.ProjectId, p.Sha))!;
        Assert.Equal(6, ov.TotalComponents);
        Assert.True(ov.UnknownCount >= 2);
        Assert.NotEmpty(ov.Unknowns);
        Assert.NotEmpty(ov.Groups);
        Assert.True(ov.CategoryMax > 0);

        var stale = await q.SbomStalenessAsync(p.ProjectId, null);
        Assert.DoesNotContain(stale, s => s.Name.StartsWith("Vuln."));
        Assert.Contains(stale, s => s.Name.StartsWith("Gpl.") && s.Stale && s.DaysBehind is >= 399);
        Assert.Contains(stale, s => s.Name.StartsWith("Weird.") && !s.Stale && s.DaysBehind is null);

        var sum = (await q.SbomSummaryAsync(p.ProjectId, p.Sha))!;
        Assert.Equal(6, sum.Components);
        Assert.Equal(1, sum.Vulnerable);
        Assert.Equal(0, sum.Exempt);
        Assert.Equal("syft", sum.ToolName);

        var closure = await q.StalenessClosureAsync(p.ProjectId, p.Sha, spurl);
        Assert.True(closure[0].Clicked);
        Assert.Empty(await q.StalenessClosureAsync(p.ProjectId, p.Sha, "pkg:nuget/none@1"));
        // dev-only origin pulls in dev peers
        var dev = await q.StalenessClosureAsync(p.ProjectId, p.Sha, $"pkg:nuget/Weird.{p.Suffix}@1.0.0");
        Assert.Single(dev);
    }

    [SkippableFact]
    public async Task License_overview_applies_policy_and_knowledge_base()
    {
        Skip.IfNot(_fx.Available);
        var p = await NewProjectAsync();
        Guid policyId;
        string unkPurl;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var cfg = new RiskPolicyConfig();
            cfg.Licenses.Deny.Add("MIT");
            cfg.Licenses.DenyUnknown = true;
            cfg.Categories[RiskCategoryNames.License] = new RiskCategoryConfig { Max = 8, Weights = new() { ["denied"] = 0.3, ["strongCopyleft"] = 0.2, ["unknownPctMul"] = 0.4 } };
            var pol = new RiskPolicy { Name = $"lic-{p.Suffix}", Config = cfg };
            db.RiskPolicies.Add(pol);
            policyId = pol.Id;
            var proj = await db.Projects.FindAsync(p.ProjectId);
            proj!.RiskPolicyId = pol.Id;
            var snap = new SbomSnapshot { ComponentVersionId = p.CvId };
            db.SbomSnapshots.Add(snap);
            unkPurl = $"pkg:nuget/Kb.{p.Suffix}@1.0.0";
            db.SbomComponents.AddRange(
                new SbomComponent { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/M.{p.Suffix}@1", Name = "M", Version = "1", License = "MIT" },
                new SbomComponent { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/G.{p.Suffix}@1", Name = "G", Version = "1", License = "GPL-3.0-only" },
                new SbomComponent { SbomSnapshotId = snap.Id, Purl = unkPurl, Name = "Kb", Version = "1.0.0", License = null },
                new SbomComponent { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/U.{p.Suffix}@1", Name = "U", Version = "1" });
            db.LicenseResolutions.Add(new LicenseResolution { Purl = unkPurl, Spdx = "Apache-2.0", ResolvedBy = "tester" });
            await db.SaveChangesAsync();
        }
        using var s2 = _fx.Scope();
        var q = s2.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();
        var ov = (await q.LicenseOverviewAsync(p.ProjectId, null))!;
        Assert.Equal(1, ov.ResolvedApplied);
        Assert.Equal(8, ov.CategoryMax);
        Assert.Equal(0.3, ov.WeightDenied);
        Assert.True(ov.DenyUnknown);
        Assert.Contains("MIT", ov.PolicyDeny);
        _ = policyId;
    }

    [SkippableFact]
    public async Task Coverage_tests_receipts_raw_and_histories()
    {
        Skip.IfNot(_fx.Available);
        var p = await NewProjectAsync();
        
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var rep = new CoverageReport { ComponentVersionId = p.CvId, ToolName = "Coverlet", ToolVersion = "6", SequenceCoverage = 50, CoveredSequences = 5, TotalSequences = 10, CoveredBranches = 1, TotalBranches = 4 };
            var cv2 = new ComponentVersion { ProjectId = p.ProjectId, VersionString = "1.0.0", CommitSha = p.Sha, Flavor = "other" };
            db.ComponentVersions.Add(cv2);
            var rep2 = new CoverageReport { ComponentVersionId = cv2.Id, ToolName = "Coverlet", CoveredSequences = 0, TotalSequences = 0 };
            db.CoverageReports.AddRange(rep, rep2);
            var m1 = new CoverageModule { CoverageReportId = rep.Id, Name = "A.dll", CoveredSequences = 5, TotalSequences = 10 };
            var m2 = new CoverageModule { CoverageReportId = rep.Id, Name = "Legacy.dll", CoveredSequences = 0, TotalSequences = 0, SequenceCoverage = 33, BranchCoverage = 11 };
            var m3 = new CoverageModule { CoverageReportId = rep.Id, Name = "Legacy2.dll", CoveredSequences = 2, TotalSequences = 4, SequenceCoverage = 50 };
            db.CoverageModules.AddRange(m1, m2, m3);
            var f1 = new CoverageSourceFile { CoverageReportId = rep.Id, RelativePath = "a/One.cs" };
            var f2 = new CoverageSourceFile { CoverageReportId = rep.Id, RelativePath = "a/Two.cs" };
            db.CoverageSourceFiles.AddRange(f1, f2);
            db.CoverageClasses.AddRange(
                new CoverageClass { CoverageModuleId = m1.Id, CoverageSourceFileId = f1.Id, FullName = "My.Ns.One", CoveredSequences = 3, TotalSequences = 6, CoveredBranches = 1, TotalBranches = 2 },
                new CoverageClass { CoverageModuleId = m1.Id, CoverageSourceFileId = f1.Id, FullName = "My.Ns.One+Nested", CoveredSequences = 1, TotalSequences = 2 },
                new CoverageClass { CoverageModuleId = m1.Id, CoverageSourceFileId = f2.Id, FullName = "Global", CoveredSequences = 1, TotalSequences = 2, CoveredBranches = 0, TotalBranches = 2 });

            var tr = new TestRunReport { ComponentVersionId = p.CvId, ToolName = "trx", ToolVersion = "1", TotalCount = 10, PassedCount = 6, FailedCount = 3, SkippedCount = 1, DurationMs = 100, CompletedAt = DateTimeOffset.UtcNow };
            db.TestRunReports.Add(tr);
            var s1 = new TestSuiteResult { TestRunReportId = tr.Id, AssemblyName = "A.Tests", ClassName = "C1", TotalCount = 5, PassedCount = 2, FailedCount = 3 };
            var s2 = new TestSuiteResult { TestRunReportId = tr.Id, AssemblyName = "B.Tests", ClassName = "C2", TotalCount = 5, PassedCount = 4, SkippedCount = 1 };
            var s3 = new TestSuiteResult { TestRunReportId = tr.Id, AssemblyName = "B.Tests", ClassName = "C3", TotalCount = 5, PassedCount = 5 };
            db.TestSuiteResults.AddRange(s1, s2, s3);
            db.TestCaseResults.AddRange(
                new TestCaseResult { TestSuiteResultId = s1.Id, Name = "T1", Outcome = TestOutcome.Failed, ErrorMessage = "boom", ErrorStackTrace = "at x" },
                new TestCaseResult { TestSuiteResultId = s1.Id, Name = "T0", Outcome = TestOutcome.Failed },
                new TestCaseResult { TestSuiteResultId = s1.Id, Name = "T2", Outcome = TestOutcome.Passed });

            foreach (var (sc, st) in new[] { (ScannerKind.OsvScanner, ScanRunStatus.Succeeded), (ScannerKind.Grype, ScanRunStatus.Succeeded), (ScannerKind.Trivy, ScanRunStatus.Failed), (ScannerKind.OpenGrep, ScanRunStatus.Succeeded) })
                db.ScanRunReceipts.Add(new ScanRunReceipt
                {
                    ComponentVersionId = p.CvId, Scanner = sc, Status = st, FindingsCount = 2, ToolName = sc.ToString(), ToolVersion = "1", Notes = "n",
                    StartedAt = DateTimeOffset.UtcNow.AddMinutes(-1), CompletedAt = DateTimeOffset.UtcNow.AddMinutes(sc == ScannerKind.Grype ? 0 : -2),
                });

            var raw = new RawReportArtifact { ComponentVersionId = p.CvId, Kind = RawArtifactKind.TestResults, Format = "trx", FileName = "a.trx", SlotKey = "a", SizeBytes = 10, Sha256 = "x" };
            db.RawReportArtifacts.AddRange(raw,
                new RawReportArtifact { ComponentVersionId = p.CvId, Kind = RawArtifactKind.TestResults, Format = "junit", SlotKey = "b", SizeBytes = 5, Sha256 = "y" });

            // cv2 shares the commit; RawArtifactsAsync reads the first CV of the set, so mirror the artifacts there.
            db.RawReportArtifacts.AddRange(
                new RawReportArtifact { ComponentVersionId = cv2.Id, Kind = RawArtifactKind.TestResults, Format = "trx", FileName = "a.trx", SlotKey = "a", SizeBytes = 10, Sha256 = "x" },
                new RawReportArtifact { ComponentVersionId = cv2.Id, Kind = RawArtifactKind.TestResults, Format = "junit", SlotKey = "b", SizeBytes = 5, Sha256 = "y" });

            // Quality
            db.QualityGateResults.Add(new QualityGateResult
            {
                ComponentVersionId = p.CvId, Status = "ERROR", Source = "sonarcloud", AnalysisId = "an1", ObservedAt = DateTimeOffset.UtcNow,
                ConditionsJson = """[{"Metric":"coverage","Op":"LT","Threshold":80,"Actual":"50","Status":"ERROR"},{"Status":"OK"}]""",
                MeasuresJson = """{"ncloc":123,"bugs":"4"}""",
            });
            var cov = new AnalysisCoverageReport { ComponentVersionId = p.CvId, ObservedAt = DateTimeOffset.UtcNow, GapLanguages = "go, rust", Excludes = " a , b " };
            db.AnalysisCoverageReports.Add(cov);
            db.AnalysisCoverageLanguages.AddRange(
                new AnalysisCoverageLanguage { AnalysisCoverageReportId = cov.Id, Language = "csharp", FilesTotal = 10, FilesAnalyzed = 9, LinesTotal = 100, PercentAnalyzed = 90 },
                new AnalysisCoverageLanguage { AnalysisCoverageReportId = cov.Id, Language = "ts", FilesTotal = 10, FilesAnalyzed = 9, LinesTotal = 500, PercentAnalyzed = 90 });
            db.Findings.Add(F(p.CvId, ScannerKind.SonarQube, Severity.Medium, "code_smell", "q1"));
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var q = s.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();

        var cov2 = (await q.CoverageAsync(p.ProjectId, p.Sha))!;
        Assert.Equal(5, cov2.CoveredSequences);
        Assert.Equal(3, cov2.Modules!.Count);
        Assert.Contains(cov2.Modules, m => m.Name == "Legacy.dll" && m.SeqPercent == 33);
        Assert.Contains(cov2.Modules, m => m.Name == "Legacy2.dll" && m.SeqPercent == 50);
        var a = cov2.Modules.Single(m => m.Name == "A.dll");
        Assert.Contains(a.Namespaces, n => n.Name == "My.Ns");
        Assert.Contains(a.Namespaces, n => n.Name == "(global)");

        var t = (await q.TestsAsync(p.ProjectId, null))!;
        Assert.Equal(10, t.Total);
        Assert.Equal(2, t.Suites.Count);
        Assert.Equal(2, t.AssemblyCount);
        Assert.Equal(3, t.SuiteCount);
        Assert.Equal("A.Tests", t.Assemblies![0].Assembly);

        var fails = await q.TestFailuresAsync(p.ProjectId, p.Sha);
        Assert.Equal(2, fails.Count);
        Assert.Equal("T0", fails[0].Name);

        var th = await q.TestScanHistoryAsync(p.ProjectId, 5);
        Assert.Equal(2, th.Count);
        Assert.Equal(50, th.Single(x => x.Measured).CoveragePercent);

        var ch = await q.CveScanHistoryAsync(p.ProjectId);
        Assert.Equal("Grype", ch.Single(x => x.Scanned).ScannerTool);

        var raws = (await q.RawArtifactsAsync(p.ProjectId, p.Sha, RawArtifactKind.TestResults))!;
        Assert.Equal(2, raws.Artifacts.Count);
        Assert.Contains(raws.Artifacts, r => r.Format == "trx");
        Assert.Null(await q.RawArtifactsAsync(p.ProjectId, p.Sha, RawArtifactKind.Coverage));

        var rc = await q.ReceiptsAsync(p.ProjectId, null);
        Assert.Equal(4, rc.Count);

        var qo = await q.QualityOverviewAsync(p.ProjectId, p.Sha);
        Assert.True(qo.Ran);
        Assert.Equal("ERROR", qo.Gate!.Status);
        Assert.Equal(2, qo.Gate.Conditions.Count);
        Assert.Contains(qo.Gate.Conditions, c => c.Failed && c.Metric == "coverage");
        Assert.Contains(qo.Gate.Conditions, c => c.Metric == "?");
        Assert.Equal(2, qo.Gate.Measures.Count);
        Assert.Equal(["ts", "csharp"], qo.Coverage!.Languages.Select(l => l.Language));
        Assert.Equal(["go", "rust"], qo.Coverage.GapLanguages);
        Assert.Equal(["a", "b"], qo.Coverage.Excludes);
        Assert.Equal(1, qo.History.Single(h => h.TotalConditions > 0).FailedConditions);
        Assert.Equal(1, qo.History.Sum(h => h.FindingCount));
    }

    [SkippableFact]
    public async Task Quality_overview_tolerates_malformed_gate_json()
    {
        Skip.IfNot(_fx.Available);
        foreach (var (cond, meas) in new[] { ("not json", "also not"), ("{\"a\":1}", "[1]"), ("", "") })
        {
            var p = await NewProjectAsync();
            using (var scope = _fx.Scope())
            {
                var db = _fx.Db(scope);
                db.QualityGateResults.Add(new QualityGateResult { ComponentVersionId = p.CvId, Status = "OK", ObservedAt = DateTimeOffset.UtcNow, ConditionsJson = cond, MeasuresJson = meas });
                await db.SaveChangesAsync();
            }
            using var s = _fx.Scope();
            var q = s.ServiceProvider.GetRequiredService<CategoryFindingsQuery>();
            var qo = await q.QualityOverviewAsync(p.ProjectId, p.Sha);
            Assert.True(qo.Ran);
            Assert.Empty(qo.Gate!.Conditions);
            Assert.Empty(qo.Gate.Measures);
            Assert.Equal(0, qo.History.Single().TotalConditions);
        }
    }
}
