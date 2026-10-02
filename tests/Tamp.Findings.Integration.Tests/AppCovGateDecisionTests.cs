using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// GateDecisionService end to end, and RiskInputsBuilder over a build that touches every input.
[Collection(DatabaseCollection.Name)]
public class AppCovGateDecisionTests
{
    private readonly DatabaseFixture _fx;
    public AppCovGateDecisionTests(DatabaseFixture fx) => _fx = fx;

    private static Finding F(Guid cv, ScannerKind sc, Severity sev, string tag, string? sub = null, FindingStatus st = FindingStatus.Open) => new()
    {
        ComponentVersionId = cv, Hash = $"{tag}-{Guid.NewGuid():N}", Scanner = sc, RuleId = $"r-{tag}", Severity = sev,
        Title = $"t-{tag}", FilePath = $"f/{tag}.cs", Line = 1, SubCategory = sub, Status = st,
    };

    private static ProjectGatesConfig AllGatesOn()
    {
        var c = new ProjectGatesConfig();
        foreach (var k in GateEvaluator.WellKnownGateKeys) c.Gates[k] = new GateConfig { Enabled = true };
        return c;
    }

    [SkippableFact]
    public async Task Missing_project_and_project_without_builds()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var svc = scope.ServiceProvider.GetRequiredService<GateDecisionService>();

        Assert.Equal(GateDecisionStatus.ProjectNotFound, (await svc.ForLatestAsync(Guid.NewGuid())).Status);

        var (_, project) = await AppCovSeed.ClientProjectAsync(db, "gd-none");
        await AppCovSeed.BuildAsync(db, project.Id, branch: "feature/x");
        await AppCovSeed.BuildAsync(db, project.Id, pr: "refs/pull/1");
        Assert.Equal(GateDecisionStatus.NoBuilds, (await svc.ForLatestAsync(project.Id)).Status);
    }

    [SkippableFact]
    public async Task Rich_build_is_scored_gated_and_compared_with_the_prior_canonical_build()
    {
        Skip.IfNot(_fx.Available);
        Guid projectId;
        string currentSha, priorSha;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "gd-rich");
            projectId = project.Id;
            (await db.Projects.FindAsync(project.Id))!.GatesConfig = AllGatesOn();
            (await db.Projects.FindAsync(project.Id))!.Archetype = ProjectArchetype.ServiceApp;
            await db.SaveChangesAsync();

            var prior = await AppCovSeed.BuildAsync(db, project.Id, at: DateTimeOffset.UtcNow.AddDays(-3));
            priorSha = prior.CommitSha!;
            var cv = await AppCovSeed.BuildAsync(db, project.Id, at: DateTimeOffset.UtcNow.AddDays(-1));
            currentSha = cv.CommitSha!;
            // A second CV for the same commit (another flavor) feeding the same build.
            var cv2 = new ComponentVersion { ProjectId = project.Id, VersionString = "f", CommitSha = currentSha, Flavor = "x", BranchName = "master", CreatedAt = DateTimeOffset.UtcNow.AddDays(-1) };
            db.ComponentVersions.Add(cv2);
            await db.SaveChangesAsync();

            db.Findings.AddRange(
                F(cv.Id, ScannerKind.Roslyn, Severity.Critical, "s1"), F(cv.Id, ScannerKind.OpenGrep, Severity.High, "s2"),
                F(cv.Id, ScannerKind.CodeQL, Severity.Medium, "s3"), F(cv.Id, ScannerKind.ESLint, Severity.Low, "s4"),
                F(cv.Id, ScannerKind.SonarQube, Severity.High, "s5", "vulnerability"), F(cv.Id, ScannerKind.SonarQube, Severity.Medium, "q1", "code_smell"),
                F(cv.Id, ScannerKind.Spectral, Severity.High, "q2"), F(cv.Id, ScannerKind.Stryker, Severity.Medium, "q3"), F(cv.Id, ScannerKind.NetArchTest, Severity.Low, "q4"),
                F(cv.Id, ScannerKind.Zap, Severity.Critical, "d1"), F(cv.Id, ScannerKind.Nuclei, Severity.High, "d2"), F(cv.Id, ScannerKind.Zap, Severity.Medium, "d3"), F(cv.Id, ScannerKind.Zap, Severity.Low, "d4"),
                F(cv.Id, ScannerKind.AxeCore, Severity.Critical, "a1"), F(cv.Id, ScannerKind.AxeCore, Severity.Medium, "a2"), F(cv.Id, ScannerKind.AxeCore, Severity.Low, "a3"),
                F(cv.Id, ScannerKind.Trivy, Severity.Critical, "i1"), F(cv.Id, ScannerKind.Trivy, Severity.High, "i2", "misconfiguration"),
                F(cv.Id, ScannerKind.Trivy, Severity.Critical, "i3", "secret"), F(cv.Id, ScannerKind.TruffleHog, Severity.High, "t1"),
                F(cv.Id, ScannerKind.Roslyn, Severity.High, "closed", st: FindingStatus.Fixed));

            var snap = new SbomSnapshot { ComponentVersionId = cv.Id, IngestedAt = DateTimeOffset.UtcNow.AddDays(-5) };
            db.SbomSnapshots.Add(snap);
            var tag = project.Id.ToString("N")[..8];
            SbomComponent C(string n, string v, string? lic, string? latest = null, int? ago = null) => new()
            {
                SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/{n}{tag}@{v}", Name = n, Version = v, License = lic,
                LatestVersion = latest, LatestReleasedAt = ago is { } a ? DateTimeOffset.UtcNow.AddDays(-a) : null,
            };
            var vuln = C("Vuln", "1", "MIT"); var old = C("Old", "1", "GPL-3.0-only", "2", 400); var bad = C("Bad", "1", "AGPL-3.0-only");
            var unk = C("Unk", "1", null); var fine = C("Fine", "1", "MIT", "2", 10);
            var banned = C("Banned", "1", "MIT");
            db.SbomComponents.AddRange(vuln, old, bad, unk, fine, banned);
            var kevId = $"CVE-2098-{Random.Shared.Next(1000, 9999)}";
            db.Vulnerabilities.AddRange(
                new Vulnerability { SbomComponentId = vuln.Id, AdvisoryId = kevId, Severity = Severity.Critical },
                new Vulnerability { SbomComponentId = vuln.Id, AdvisoryId = "CVE-H", Severity = Severity.High },
                new Vulnerability { SbomComponentId = vuln.Id, AdvisoryId = "CVE-M", Severity = Severity.Medium },
                new Vulnerability { SbomComponentId = vuln.Id, AdvisoryId = "CVE-L", Severity = Severity.Low });
            db.KevAdvisories.Add(new KevAdvisory { CveId = kevId, DateAdded = new DateOnly(2024, 1, 1), DueDate = new DateOnly(2024, 2, 1) });
            db.BannedComponents.Add(new BannedComponent { Purl = $"pkg:nuget/banned{tag}", Source = "test", Versions = ["1"] });
            db.BannedComponents.Add(new BannedComponent { Purl = $"pkg:nuget/fine{tag}", Source = "test", Versions = ["9"] });

            db.CoverageReports.Add(new CoverageReport { ComponentVersionId = cv.Id, CoveredSequences = 40, TotalSequences = 100 });
            db.TestRunReports.Add(new TestRunReport { ComponentVersionId = cv.Id, TotalCount = 10, FailedCount = 2 });
            foreach (var sc in new[] { ScannerKind.Roslyn, ScannerKind.Nuclei, ScannerKind.TruffleHog, ScannerKind.Trivy, ScannerKind.OsvScanner, ScannerKind.Spectral, ScannerKind.AxeCore })
                db.ScanRunReceipts.Add(new ScanRunReceipt { ComponentVersionId = cv.Id, Scanner = sc, Status = ScanRunStatus.Succeeded, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow });
            db.QualityGateResults.Add(new QualityGateResult
            {
                ComponentVersionId = cv.Id, Status = "FAIL", ObservedAt = DateTimeOffset.UtcNow,
                ConditionsJson = """[{"Metric":"a","Status":"ERROR"},{"Metric":"b","Status":"OK"},{"Metric":"c","Status":"error"}]""",
            });
            db.AnalysisCoverageReports.Add(new AnalysisCoverageReport { ComponentVersionId = cv.Id, ObservedAt = DateTimeOffset.UtcNow, GapLanguages = "go, rust" });
            db.ContainerImages.Add(new ContainerImage { ComponentVersionId = cv.Id, Reference = "i:1", BaseImageCreatedAt = DateTimeOffset.UtcNow.AddDays(-500), InspectedAt = DateTimeOffset.UtcNow });
            db.PostureObservations.AddRange(
                new PostureObservation { ProjectId = project.Id, CheckId = "branch-protection", Status = PostureStatus.Pass, ObservedAt = DateTimeOffset.UtcNow },
                new PostureObservation { ProjectId = project.Id, CheckId = "signed-commits", Status = PostureStatus.Fail, ObservedAt = DateTimeOffset.UtcNow, Detail = "unsigned" });
            db.PoamItems.Add(new PoamItem
            {
                ProjectId = project.Id, Title = "late", WeaknessDescription = "w", Severity = Severity.High, Status = PoamStatus.Open,
                ScheduledCompletionDate = DateTimeOffset.UtcNow.AddDays(-10), AuthorUserId = Guid.NewGuid(),
            });
            // prior build: one coverage report with higher coverage so the delta gates have something to compare.
            db.CoverageReports.Add(new CoverageReport { ComponentVersionId = prior.Id, CoveredSequences = 90, TotalSequences = 100 });
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var svc = s.ServiceProvider.GetRequiredService<GateDecisionService>();
        var (status, result) = await svc.ForLatestAsync(projectId);
        Assert.Equal(GateDecisionStatus.Ok, status);
        var r = result!;
        Assert.Equal(currentSha, r.Current.CommitSha);
        Assert.Equal(priorSha, r.Prior!.CommitSha);
        Assert.NotNull(r.PriorScore);
        Assert.NotNull(r.PriorBand);
        Assert.True(r.CurrentScore > r.PriorScore);
        Assert.False(r.Evaluation.ClearToShip);
        Assert.Equal(GateEvaluator.WellKnownGateKeys.Length, r.Evaluation.Results.Count);
        Assert.Equal(GateVerdict.Fail, r.Evaluation.Results.Single(x => x.Key == GateKeys.CriticalCves).Verdict);
        Assert.Equal(GateVerdict.Fail, r.Evaluation.Results.Single(x => x.Key == GateKeys.CoverageRegression).Verdict);
        Assert.Equal(GateVerdict.Fail, r.Evaluation.Results.Single(x => x.Key == GateKeys.QualityGate).Verdict);
        Assert.Equal(GateVerdict.Fail, r.Evaluation.Results.Single(x => x.Key == GateKeys.AnalysisCoverage).Verdict);
        Assert.Equal(GateVerdict.Fail, r.Evaluation.Results.Single(x => x.Key == GateKeys.UnauthorizedComponent).Verdict);
        Assert.Equal(GateVerdict.Pass, r.Evaluation.Results.Single(x => x.Key == GateKeys.BranchProtection).Verdict);
        Assert.Equal(GateVerdict.Fail, r.Evaluation.Results.Single(x => x.Key == GateKeys.SignedCommits).Verdict);
        Assert.NotEmpty(r.PolicyName);

        // RiskInputsBuilder directly: every input populated, plus the no-VEX / no-project overloads.
        var builder = s.ServiceProvider.GetRequiredService<RiskInputsBuilder>();
        var scoring = s.ServiceProvider.GetRequiredService<ScoringPolicyResolver>();
        var policy = await scoring.ForProjectAsync(projectId);
        var db2 = _fx.Db(s);
        var cvIds = await db2.ComponentVersions.Where(c => c.ProjectId == projectId && c.CommitSha == currentSha).Select(c => c.Id).ToListAsync();
        var inputs = await builder.BuildAsync(cvIds, policy.Config, projectId, default);
        Assert.True(inputs.SastCritical >= 1);
        Assert.True(inputs.SastHigh >= 2);
        Assert.True(inputs.DastCritical >= 1 && inputs.DastHigh >= 1 && inputs.DastMedium >= 1 && inputs.DastLow >= 1);
        Assert.True(inputs.QualityHigh >= 1 && inputs.QualityMedium >= 1 && inputs.QualityLow >= 1);
        Assert.True(inputs.A11ySevere >= 1 && inputs.A11yModerate >= 1 && inputs.A11yMinor >= 1);
        Assert.True(inputs.IacCritical >= 1 && inputs.IacHigh >= 1);
        Assert.True(inputs.SecretsVerified >= 1 && inputs.SecretsUnverified >= 1);
        Assert.Equal(1, inputs.KevListedCves);
        Assert.Equal(1, inputs.CveCritical);
        Assert.Equal(1, inputs.UnauthorizedComponents);
        Assert.Equal(1, inputs.OpenPastDuePoams);
        Assert.Equal(2, inputs.QualityGateFailed);
        Assert.Equal(2, inputs.UnanalyzedLanguages);
        Assert.True(inputs.HasAnalysisCoverage && inputs.HasQualityGateVerdict);
        Assert.Equal(500, inputs.BaseImageAgeDays);
        Assert.True(inputs.LicenseDenied + inputs.LicenseStrongCopyleft >= 2 && inputs.LicenseUnknown >= 1);
        Assert.True(inputs.SbomOutdated >= 2 && inputs.SbomStale >= 1);
        Assert.True(inputs.RanSca && inputs.RanDast && inputs.RanQuality && inputs.RanAccessibility && inputs.RanImageInspect);
        Assert.Equal(2, inputs.Posture!.Count);
        Assert.Equal(2, inputs.TestsFailed);

        var noProject = await builder.BuildAsync(cvIds, policy.Config, default);
        Assert.Null(noProject.Posture);
        Assert.Equal(0, noProject.OpenPastDuePoams);
        Assert.False((await builder.BuildAsync([], policy.Config, default)).RanSbom);

        // severity ceilings downgrade scoring input without touching the stored finding
        var capped = new RiskPolicyConfig { ScannerOverrides = new() { ["Roslyn"] = new ScannerOverride { SeverityCeiling = Severity.Low } } };
        var cappedInputs = await builder.BuildAsync(cvIds, capped, projectId, default);
        Assert.True(cappedInputs.SastCritical < inputs.SastCritical);
    }

    [SkippableFact]
    public async Task Quality_gate_pass_unparsable_conditions_and_first_build_without_prior()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var (_, project) = await AppCovSeed.ClientProjectAsync(db, "gd-qg");
        (await db.Projects.FindAsync(project.Id))!.GatesConfig = AllGatesOn();
        var cv = await AppCovSeed.BuildAsync(db, project.Id, branch: null);
        db.QualityGateResults.Add(new QualityGateResult { ComponentVersionId = cv.Id, Status = "fail", ObservedAt = DateTimeOffset.UtcNow, ConditionsJson = "garbage" });
        await db.SaveChangesAsync();

        var svc = scope.ServiceProvider.GetRequiredService<GateDecisionService>();
        var (status, result) = await svc.ForLatestAsync(project.Id);
        Assert.Equal(GateDecisionStatus.Ok, status);
        Assert.Null(result!.Prior);
        Assert.Null(result.PriorScore);
        var qg = result.Evaluation.Results.Single(x => x.Key == GateKeys.QualityGate);
        Assert.Equal(GateVerdict.Fail, qg.Verdict);

        // a passing verdict, with a non-array condition payload
        var cv2 = await AppCovSeed.BuildAsync(db, project.Id, at: DateTimeOffset.UtcNow.AddMinutes(1));
        db.QualityGateResults.Add(new QualityGateResult { ComponentVersionId = cv2.Id, Status = "OK", ObservedAt = DateTimeOffset.UtcNow, ConditionsJson = "{}" });
        await db.SaveChangesAsync();
        var (_, r2) = await svc.ForLatestAsync(project.Id);
        Assert.Equal(GateVerdict.Pass, r2!.Evaluation.Results.Single(x => x.Key == GateKeys.QualityGate).Verdict);
        Assert.NotNull(r2.Prior);
    }
}
