using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// TFND-213 / RA-5(4): the discoverable-information roll-up over REAL ingested findings, and
/// the gate that reads it.
///
/// <para>
/// The unit tests cover the registry and the verdict. What only a database can show is the
/// part that actually breaks: the roll-up is a second query, keyed on rule id, over rows
/// that the main grouping reads by scanner and severity — so it has to agree with the
/// verifiedSecrets gate about which secrets are live, honour the same dedupe and open-status
/// filters, and not read a finding from another build.
/// </para>
/// </summary>
[Collection(DatabaseCollection.Name)]
public class AppCovDiscoverableInformationTests
{
    private readonly DatabaseFixture _fx;
    public AppCovDiscoverableInformationTests(DatabaseFixture fx) => _fx = fx;

    private static Finding F(
        Guid cv, ScannerKind scanner, string ruleId, Severity severity,
        string? sub = null, FindingStatus status = FindingStatus.Open) => new()
    {
        ComponentVersionId = cv,
        Hash = $"{ruleId}-{Guid.NewGuid():N}",
        Scanner = scanner,
        RuleId = ruleId,
        Severity = severity,
        Title = $"alert {ruleId}",
        SubCategory = sub,
        Status = status,
    };

    private static ProjectGatesConfig GateOn(double? threshold = null)
    {
        var c = new ProjectGatesConfig();
        c.Gates[GateKeys.DiscoverableInformation] = new GateConfig { Enabled = true, Threshold = threshold };
        return c;
    }

    [SkippableFact]
    public async Task A_dynamic_scan_is_classified_into_disclosure_and_fingerprint_tiers()
    {
        Skip.IfNot(_fx.Available);
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "exp-dast");
            projectId = project.Id;
            (await db.Projects.FindAsync(project.Id))!.GatesConfig = GateOn();
            var cv = await AppCovSeed.BuildAsync(db, project.Id);

            db.Findings.AddRange(
                // Disclosure: debug output and an identifier in a URL.
                F(cv.Id, ScannerKind.Zap, "10023", Severity.Medium, "dast"),
                F(cv.Id, ScannerKind.Zap, "10024", Severity.Medium, "dast"),
                // Fingerprint: the shape of a real ZAP run — mostly banners and artefacts.
                F(cv.Id, ScannerKind.Zap, "10036", Severity.Low, "dast"),
                F(cv.Id, ScannerKind.Zap, "10044", Severity.Low, "dast"),
                F(cv.Id, ScannerKind.Zap, "10044", Severity.Low, "dast"),
                F(cv.Id, ScannerKind.Zap, "10027", Severity.Info, "dast"),
                // Unclassified: header hardening, and a real defect that is not an exposure.
                F(cv.Id, ScannerKind.Zap, "10021", Severity.Low, "dast"),
                F(cv.Id, ScannerKind.Zap, "40018", Severity.High, "dast"),
                // Fixed findings are not discoverable any more.
                F(cv.Id, ScannerKind.Zap, "10045", Severity.High, "dast", FindingStatus.Fixed));
            db.ScanRunReceipts.Add(new ScanRunReceipt
            {
                ComponentVersionId = cv.Id, Scanner = ScannerKind.Zap, Status = ScanRunStatus.Succeeded,
                StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var inputs = await BuildInputsAsync(s, projectId);

        Assert.True(inputs.RanExposureAnalysis);
        Assert.Equal(2, inputs.DisclosureExposures);
        Assert.Equal(4, inputs.FingerprintExposures);
        // Two 10044s and one 10027 — three alerts, two rule ids, one class.
        Assert.Equal(3, inputs.ExposuresByClass![ExposureClasses.IncidentalArtifact]);
        Assert.Equal(1, inputs.ExposuresByClass[ExposureClasses.TechnologyFingerprint]);
        Assert.False(inputs.ExposuresByClass.ContainsKey(ExposureClasses.SourceOrConfig)); // the Fixed one

        var gate = await GateAsync(s, projectId);
        Assert.Equal(GateVerdict.Fail, gate.Verdict);
        Assert.Contains("Debug and diagnostic output reachable (1)", gate.Reason!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_library_with_only_a_secret_scan_still_gets_an_answer()
    {
        Skip.IfNot(_fx.Available);
        // The reason the gate is not Web-capability-conditional. A code library has no
        // deployed target to probe and is where the commonest exposure of all — a committed
        // credential — actually lives.
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "exp-lib");
            projectId = project.Id;
            var p = (await db.Projects.FindAsync(project.Id))!;
            p.GatesConfig = GateOn();
            p.Archetype = ProjectArchetype.Library;
            var cv = await AppCovSeed.BuildAsync(db, project.Id);

            db.Findings.AddRange(
                F(cv.Id, ScannerKind.TruffleHog, "aws-access-key", Severity.Critical),   // verified → disclosure
                F(cv.Id, ScannerKind.TruffleHog, "generic-api-key", Severity.High),      // unverified → fingerprint
                F(cv.Id, ScannerKind.TruffleHog, "generic-api-key", Severity.High));
            db.ScanRunReceipts.Add(new ScanRunReceipt
            {
                ComponentVersionId = cv.Id, Scanner = ScannerKind.TruffleHog, Status = ScanRunStatus.Succeeded,
                StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var inputs = await BuildInputsAsync(s, projectId);

        Assert.True(inputs.RanExposureAnalysis);
        Assert.Equal(1, inputs.DisclosureExposures);
        Assert.Equal(2, inputs.FingerprintExposures);
        // The two gates read the same rows and must agree about which secrets are live.
        Assert.Equal(inputs.SecretsVerified, inputs.ExposuresByClass![ExposureClasses.LeakedCredential]);
        Assert.Equal(inputs.SecretsUnverified, inputs.ExposuresByClass[ExposureClasses.CandidateCredential]);

        Assert.Equal(GateVerdict.Fail, (await GateAsync(s, projectId)).Verdict);
    }

    [SkippableFact]
    public async Task Neither_scan_having_run_blocks_as_unknown()
    {
        Skip.IfNot(_fx.Available);
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "exp-unknown");
            projectId = project.Id;
            (await db.Projects.FindAsync(project.Id))!.GatesConfig = GateOn();
            var cv = await AppCovSeed.BuildAsync(db, project.Id);
            // A SAST receipt is not an answer to this question.
            db.ScanRunReceipts.Add(new ScanRunReceipt
            {
                ComponentVersionId = cv.Id, Scanner = ScannerKind.Roslyn, Status = ScanRunStatus.Succeeded,
                StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        Assert.False((await BuildInputsAsync(s, projectId)).RanExposureAnalysis);

        var gate = await GateAsync(s, projectId);
        Assert.Equal(GateVerdict.Unknown, gate.Verdict);
        Assert.True(gate.Blocks);
    }

    [SkippableFact]
    public async Task A_severity_ceiling_on_the_secret_scanner_moves_both_gates_together()
    {
        Skip.IfNot(_fx.Available);
        // An admin who ceilings a secret scanner changes what "verified" means for the
        // verifiedSecrets gate. If the roll-up read the raw severity instead, one gate would
        // call a secret live and the other would not.
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "exp-ceiling");
            projectId = project.Id;
            var cv = await AppCovSeed.BuildAsync(db, project.Id);
            db.Findings.Add(F(cv.Id, ScannerKind.TruffleHog, "aws-access-key", Severity.Critical));
            db.ScanRunReceipts.Add(new ScanRunReceipt
            {
                ComponentVersionId = cv.Id, Scanner = ScannerKind.TruffleHog, Status = ScanRunStatus.Succeeded,
                StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var builder = s.ServiceProvider.GetRequiredService<RiskInputsBuilder>();
        var cvIds = await CvIdsAsync(s, projectId);

        var capped = await builder.BuildAsync(cvIds, new RiskPolicyConfig
        {
            ScannerOverrides = new() { ["TruffleHog"] = new ScannerOverride { SeverityCeiling = Severity.High } },
        }, projectId, default);

        Assert.Equal(0, capped.SecretsVerified);
        Assert.Equal(0, capped.DisclosureExposures);
        Assert.Equal(1, capped.FingerprintExposures);
        Assert.Equal(1, capped.ExposuresByClass![ExposureClasses.CandidateCredential]);
    }

    [SkippableFact]
    public async Task Another_builds_exposures_are_not_counted_against_this_one()
    {
        Skip.IfNot(_fx.Available);
        Guid projectId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "exp-scope");
            projectId = project.Id;
            var older = await AppCovSeed.BuildAsync(db, project.Id, at: DateTimeOffset.UtcNow.AddDays(-2));
            var current = await AppCovSeed.BuildAsync(db, project.Id, at: DateTimeOffset.UtcNow.AddHours(-1));

            db.Findings.AddRange(
                F(older.Id, ScannerKind.Zap, "10045", Severity.High, "dast"),      // last week's problem
                F(current.Id, ScannerKind.Zap, "10036", Severity.Low, "dast"));
            foreach (var cv in new[] { older, current })
                db.ScanRunReceipts.Add(new ScanRunReceipt
                {
                    ComponentVersionId = cv.Id, Scanner = ScannerKind.Zap, Status = ScanRunStatus.Succeeded,
                    StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var db2 = _fx.Db(s);
        var latest = await db2.ComponentVersions
            .Where(c => c.ProjectId == projectId)
            .OrderByDescending(c => c.CreatedAt)
            .Select(c => c.Id)
            .FirstAsync();

        var builder = s.ServiceProvider.GetRequiredService<RiskInputsBuilder>();
        var scoring = s.ServiceProvider.GetRequiredService<ScoringPolicyResolver>();
        var policy = await scoring.ForProjectAsync(projectId);
        var inputs = await builder.BuildAsync([latest], policy.Config, projectId, default);

        Assert.Equal(0, inputs.DisclosureExposures);
        Assert.Equal(1, inputs.FingerprintExposures);
    }

    private async Task<List<Guid>> CvIdsAsync(IServiceScope scope, Guid projectId)
    {
        var db = _fx.Db(scope);
        return await db.ComponentVersions.Where(c => c.ProjectId == projectId).Select(c => c.Id).ToListAsync();
    }

    private async Task<RiskInputs> BuildInputsAsync(IServiceScope scope, Guid projectId)
    {
        var builder = scope.ServiceProvider.GetRequiredService<RiskInputsBuilder>();
        var scoring = scope.ServiceProvider.GetRequiredService<ScoringPolicyResolver>();
        var policy = await scoring.ForProjectAsync(projectId);
        return await builder.BuildAsync(await CvIdsAsync(scope, projectId), policy.Config, projectId, default);
    }

    private static async Task<GateResult> GateAsync(IServiceScope scope, Guid projectId)
    {
        var svc = scope.ServiceProvider.GetRequiredService<GateDecisionService>();
        var (status, result) = await svc.ForLatestAsync(projectId);
        Assert.Equal(GateDecisionStatus.Ok, status);
        return result!.Evaluation.Results.Single(r => r.Key == GateKeys.DiscoverableInformation);
    }
}
