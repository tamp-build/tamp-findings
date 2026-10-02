using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Attestation;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// SsdfAttestationBuilder: each practice's Yes / Partial / No / Manual evidence branch.
[Collection(DatabaseCollection.Name)]
public class AppCovSsdfAttestationTests
{
    private readonly DatabaseFixture _fx;
    public AppCovSsdfAttestationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record Scenario
    {
        public bool Sbom { get; init; }
        public bool SbomTools { get; init; }
        public string? Provenance { get; init; }
        public bool ProvenanceVerified { get; init; }
        public int Unknown { get; init; }
        public int Denied { get; init; }
        public int CleanComponents { get; init; } = 4;
        public bool Sast { get; init; }
        public Severity? SastSeverity { get; init; }
        public bool Iac { get; init; }
        public bool IacCritical { get; init; }
        public bool Dast { get; init; }
        public Severity? DastSeverity { get; init; }
        public bool Tests { get; init; }
        public int TestsFailed { get; init; }
        public string? VdpUrl { get; init; }
        public string? VdpEmail { get; init; }
        public string? VdpForm { get; init; }
        public bool Vex { get; init; }
        public bool PoamOpen { get; init; }
        public bool PoamCompleted { get; init; }
        public bool GatesOn { get; init; }
        public bool Vuln { get; init; }
    }

    private async Task<(Guid ProjectId, string Sha)> SeedAsync(Scenario sc)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var (_, project) = await AppCovSeed.ClientProjectAsync(db, "ssdf");
        var p = await db.Projects.FindAsync(project.Id);
        p!.VdpPolicyUrl = sc.VdpUrl; p.VdpContactEmail = sc.VdpEmail; p.VdpReportingFormUrl = sc.VdpForm;
        if (sc.GatesOn)
        {
            p.GatesConfig = new ProjectGatesConfig();
            foreach (var k in new[] { GateKeys.CriticalCves, GateKeys.CriticalSast, GateKeys.TestFailures, GateKeys.CoverageFloor })
                p.GatesConfig.Gates[k] = new GateConfig { Enabled = true };
        }
        var cv = await AppCovSeed.BuildAsync(db, project.Id);
        void Receipt(ScannerKind k) => db.ScanRunReceipts.Add(new ScanRunReceipt { ComponentVersionId = cv.Id, Scanner = k, Status = ScanRunStatus.Succeeded, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow });

        if (sc.Sbom)
        {
            var snap = new SbomSnapshot
            {
                ComponentVersionId = cv.Id,
                MetadataTools = sc.SbomTools ? [new Dictionary<string, string?> { ["name"] = "syft" }] : [],
                ProvenanceType = sc.Provenance, ProvenanceUploadedAt = sc.Provenance is null ? null : DateTimeOffset.UtcNow, ProvenanceVerified = sc.ProvenanceVerified,
            };
            db.SbomSnapshots.Add(snap);
            var n = 0;
            SbomComponent C(string? lic) => new() { SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/c{n}.{project.Id:N}@1", Name = $"c{n++}", Version = "1", License = lic };
            for (var i = 0; i < sc.CleanComponents; i++) db.SbomComponents.Add(C("MIT"));
            for (var i = 0; i < sc.Unknown; i++) db.SbomComponents.Add(C(null));
            for (var i = 0; i < sc.Denied; i++) db.SbomComponents.Add(C("AGPL-3.0-only"));
            if (sc.Vuln)
            {
                var v = C("MIT");
                db.SbomComponents.Add(v);
                db.Vulnerabilities.Add(new Vulnerability { SbomComponentId = v.Id, AdvisoryId = "CVE-COV-1", Severity = Severity.Critical });
            }
            Receipt(ScannerKind.Syft);
        }
        if (sc.Sast)
        {
            Receipt(ScannerKind.Roslyn);
            if (sc.SastSeverity is { } sev) db.Findings.Add(new Finding { ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.Roslyn, RuleId = "r", Severity = sev, Title = "t" });
        }
        if (sc.Iac)
        {
            Receipt(ScannerKind.Trivy);
            if (sc.IacCritical) db.Findings.Add(new Finding { ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.Trivy, RuleId = "r", Severity = Severity.Critical, Title = "t" });
        }
        if (sc.Dast)
        {
            Receipt(ScannerKind.Nuclei);
            if (sc.DastSeverity is { } ds) db.Findings.Add(new Finding { ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.Zap, RuleId = "r", Severity = ds, Title = "t", FilePath = "https://x/y" });
        }
        if (sc.Tests)
        {
            db.TestRunReports.Add(new TestRunReport { ComponentVersionId = cv.Id, TotalCount = 10, FailedCount = sc.TestsFailed });
            db.CoverageReports.Add(new CoverageReport { ComponentVersionId = cv.Id, CoveredSequences = 50, TotalSequences = 100 });
        }
        if (sc.Vex)
            db.VexStatements.AddRange(
                new VexStatement { ProjectId = project.Id, Purl = "pkg:nuget/a", AdvisoryId = "CVE-A", Status = VexStatementStatus.NotAffected, AuthorUserId = Guid.NewGuid() },
                new VexStatement { ProjectId = project.Id, Purl = "pkg:nuget/b", AdvisoryId = "CVE-B", Status = VexStatementStatus.Fixed, AuthorUserId = Guid.NewGuid() },
                new VexStatement { ProjectId = project.Id, Purl = "pkg:nuget/c", AdvisoryId = "CVE-C", Status = VexStatementStatus.Affected, AuthorUserId = Guid.NewGuid() },
                new VexStatement { ProjectId = project.Id, Purl = "pkg:nuget/d", AdvisoryId = "CVE-D", Status = VexStatementStatus.Fixed, AuthorUserId = Guid.NewGuid(), RetiredAt = DateTimeOffset.UtcNow });
        if (sc.PoamOpen)
            db.PoamItems.Add(new PoamItem { ProjectId = project.Id, Title = "t", WeaknessDescription = "w", Severity = Severity.Low, Status = PoamStatus.Open, AuthorUserId = Guid.NewGuid() });
        if (sc.PoamCompleted)
            db.PoamItems.Add(new PoamItem { ProjectId = project.Id, Title = "t2", WeaknessDescription = "w", Severity = Severity.Low, Status = PoamStatus.Completed, ClosedAt = DateTimeOffset.UtcNow, AuthorUserId = Guid.NewGuid() });
        await db.SaveChangesAsync();
        return (project.Id, cv.CommitSha!);
    }

    private async Task<SsdfAttestationDoc> BuildAsync(Scenario sc, string? sha = null)
    {
        var (id, commit) = await SeedAsync(sc);
        using var scope = _fx.Scope();
        var doc = await scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>().BuildAsync(id, sha == "own" ? commit : sha);
        return doc!;
    }

    private static string S(SsdfAttestationDoc d, string id) => d.Practices.Single(p => p.Id == id).Status;
    private static string E(SsdfAttestationDoc d, string id) => d.Practices.Single(p => p.Id == id).Evidence;

    [SkippableFact]
    public async Task Missing_project_empty_project_and_unmatched_commit()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var b = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        Assert.Null(await b.BuildAsync(Guid.NewGuid()));

        var (_, project) = await AppCovSeed.ClientProjectAsync(db, "ssdf-empty");
        var empty = (await b.BuildAsync(project.Id))!;
        Assert.Null(empty.Build);
        Assert.Empty(empty.Practices);
        Assert.Contains("no canonical builds", empty.Summary.Headline);

        await AppCovSeed.BuildAsync(db, project.Id);
        var miss = (await b.BuildAsync(project.Id, "deadbeefdeadbeef"))!;
        Assert.Null(miss.Build);
    }

    [SkippableFact]
    public async Task Bare_build_reports_no_and_partial_with_manual_rows()
    {
        Skip.IfNot(_fx.Available);
        var d = await BuildAsync(new Scenario { Tests = true, TestsFailed = 2, VdpEmail = "sec@example.test", Vuln = false }, "own");
        Assert.NotNull(d.Build);
        Assert.Equal("Manual", S(d, "PO.1.1"));
        Assert.Equal("No", S(d, "PO.3.1"));
        Assert.Equal("Partial", S(d, "PO.4.1"));
        Assert.Equal("No", S(d, "PS.2.1"));
        Assert.Equal("Partial", S(d, "PS.3.1"));
        Assert.Equal("No", S(d, "PS.3.2"));
        Assert.Equal("No", S(d, "PW.4.1"));
        Assert.Equal("No", S(d, "PW.5.1"));
        Assert.Equal("No", S(d, "PW.8.1"));
        Assert.Equal("No", S(d, "PW.9.1"));
        Assert.Equal("Partial", S(d, "RV.1.1"));
        Assert.Equal("Partial", S(d, "RV.1.2"));
        Assert.Equal("Partial", S(d, "RV.3.1"));
        Assert.Contains("contact email", E(d, "RV.3.1"));
        Assert.Equal("Partial", S(d, "RV.3.2"));
        Assert.Contains("failing", d.Summary.Headline);
        Assert.True(d.Summary.Manual >= 8);
    }

    [SkippableFact]
    public async Task Fully_evidenced_build_attests_yes()
    {
        Skip.IfNot(_fx.Available);
        var d = await BuildAsync(new Scenario
        {
            Sbom = true, SbomTools = true, Provenance = "slsa", ProvenanceVerified = true, Sast = true, Iac = true, Dast = true, Tests = true,
            VdpUrl = "https://vdp.example.test", VdpEmail = "sec@example.test", VdpForm = "https://form.example.test", Vex = true, PoamOpen = true, PoamCompleted = true, GatesOn = true,
        });
        Assert.Equal("Yes", S(d, "PO.3.1"));
        Assert.Equal("Yes", S(d, "PO.4.1"));
        Assert.Equal("Yes", S(d, "PS.2.1"));
        Assert.Contains("VERIFIED", E(d, "PS.2.1"));
        Assert.Equal("Yes", S(d, "PS.3.1"));
        Assert.Equal("Yes", S(d, "PS.3.2"));
        Assert.Equal("Yes", S(d, "PW.4.1"));
        Assert.Equal("Yes", S(d, "PW.5.1"));
        Assert.Equal("Yes", S(d, "PW.7.1"));
        Assert.Equal("Yes", S(d, "PW.8.1"));
        Assert.Equal("Yes", S(d, "PW.9.1"));
        Assert.Equal("Yes", S(d, "RV.1.1"));
        Assert.Equal("Yes", S(d, "RV.1.2"));
        Assert.Equal("Yes", S(d, "RV.3.1"));
        Assert.Contains("form:", E(d, "RV.3.1"));
        Assert.Equal("Yes", S(d, "RV.3.2"));
        Assert.Equal(4, d.Gates!.Enabled);
        Assert.Contains("practice(s)", d.Summary.Headline);
        Assert.Equal(d.Practices.Count, d.Summary.Yes + d.Summary.Partial + d.Summary.No + d.Summary.Manual);
    }

    [SkippableFact]
    public async Task Evidence_branches_for_provenance_licences_sast_dast_and_iac()
    {
        Skip.IfNot(_fx.Available);
        var unverified = await BuildAsync(new Scenario { Sbom = true, Provenance = "in-toto", Unknown = 4 });
        Assert.Equal("Partial", S(unverified, "PS.2.1"));
        Assert.Contains("NOT verified", E(unverified, "PS.2.1"));
        Assert.Equal("Partial", S(unverified, "PW.4.1"));

        var toolsOnly = await BuildAsync(new Scenario { Sbom = true, SbomTools = true, Denied = 1 });
        Assert.Equal("Partial", S(toolsOnly, "PS.2.1"));
        Assert.Contains("tool metadata", E(toolsOnly, "PS.2.1"));
        Assert.Equal("No", S(toolsOnly, "PW.4.1"));

        var critSast = await BuildAsync(new Scenario { Sast = true, SastSeverity = Severity.Critical, Iac = true, IacCritical = true, Dast = true, DastSeverity = Severity.Critical, Tests = true });
        Assert.Equal("No", S(critSast, "PW.5.1"));
        Assert.Equal("Partial", S(critSast, "PW.9.1"));
        Assert.Equal("Partial", S(critSast, "PW.8.1"));
        Assert.Contains("critical", E(critSast, "PW.8.1"));

        var highSast = await BuildAsync(new Scenario { Sast = true, SastSeverity = Severity.High, Dast = true, DastSeverity = Severity.High, Tests = true, TestsFailed = 1 });
        Assert.Equal("Partial", S(highSast, "PW.5.1"));
        Assert.Equal("Partial", S(highSast, "PW.8.1"));
        Assert.Contains("no critical", E(highSast, "PW.8.1"));

        var dastNoTests = await BuildAsync(new Scenario { Dast = true });
        Assert.Equal("Partial", S(dastNoTests, "PW.8.1"));
        Assert.Contains("no critical/high", E(dastNoTests, "PW.8.1"));

        var testsNoDast = await BuildAsync(new Scenario { Tests = true });
        Assert.Equal("Partial", S(testsNoDast, "PW.8.1"));

        var vdpUrl = await BuildAsync(new Scenario { VdpUrl = "https://v.example.test" });
        Assert.Equal("Yes", S(vdpUrl, "RV.3.1"));
        Assert.DoesNotContain("contact", E(vdpUrl, "RV.3.1"));
    }
}
