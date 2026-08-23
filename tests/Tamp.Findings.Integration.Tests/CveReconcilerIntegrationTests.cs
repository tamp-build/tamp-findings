using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// One source of truth per component-CVE (TFND-16).
//
// The defect: Grype's CVEs arrived as Vulnerability rows and counted, while
// OsvScanner's and Trivy's arrived as Finding rows and did not. The same CVE on
// the same package counted once, twice or not at all depending on which scanner
// saw it — and a project running only OsvScanner had a clean CVE count nobody
// had measured.
[Collection(DatabaseCollection.Name)]
public class CveReconcilerIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public CveReconcilerIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- The rule-id guard --------------------------------------------------

    [Theory]
    [InlineData("CVE-2021-44228", true)]
    [InlineData("GHSA-jfh8-c2jp-5v3q", true)]
    [InlineData("GO-2024-2687", true)]
    [InlineData("PYSEC-2024-48", true)]
    [InlineData("RUSTSEC-2024-0019", true)]
    // The ones that matter: a SAST rule written into the CVE table would
    // inflate a count somebody ships against.
    [InlineData("S2094", false)]
    [InlineData("S2094-3", false)]
    [InlineData("RCS1075", false)]
    [InlineData("generic-jwt-token", false)]
    [InlineData("DS002", false)]
    [InlineData("", false)]
    public void Only_advisory_shaped_rule_ids_reach_the_cve_table(string ruleId, bool isAdvisory)
    {
        Assert.Equal(isAdvisory, CveReconciler.LooksLikeAdvisory(ruleId));
    }

    // ---- Attaching ----------------------------------------------------------

    [SkippableFact]
    public async Task An_osv_finding_becomes_a_vulnerability_on_its_component()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: "pkg:nuget/Log4Net@2.0.5");

        var result = await reconciler.ReconcileAsync([world.VersionId]);

        Assert.Equal(1, result.Attached);
        // Scoped to this world: the collection shares a database, and other
        // tests seed the same well-known advisory id.
        var vuln = await db.Vulnerabilities
            .SingleAsync(v => v.AdvisoryId == "CVE-2021-44228"
                           && v.SbomComponent!.SbomSnapshot!.ComponentVersionId == world.VersionId);
        Assert.Equal(world.Log4NetId, vuln.SbomComponentId);
        // The scanner that actually found it — "where did this come from" is a
        // question people ask when a CVE appears.
        Assert.Equal(ScannerKind.OsvScanner, vuln.Source);
    }

    [SkippableFact]
    public async Task A_bare_purl_matches_a_versioned_component()
    {
        Skip.IfNot(_fx.Available);

        // SbomComponent.Purl carries the version; a scanner may report either
        // form. Comparing them directly would attach nothing.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: "pkg:nuget/Log4Net");

        Assert.Equal(1, (await reconciler.ReconcileAsync([world.VersionId])).Attached);
    }

    [SkippableFact]
    public async Task A_trivy_vulnerability_finding_is_reconciled_too()
    {
        Skip.IfNot(_fx.Available);

        // Trivy emits secrets, misconfigurations and CVEs under one scanner
        // name. Only the CVE sub-category belongs in this table.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.Trivy, "CVE-2024-0001", Severity.High,
                      purl: "pkg:nuget/Log4Net@2.0.5", subCategory: "vulnerability");

        Assert.Equal(1, (await reconciler.ReconcileAsync([world.VersionId])).Attached);
    }

    [SkippableFact]
    public async Task A_trivy_misconfiguration_is_left_alone()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.Trivy, "DS002", Severity.High,
                      purl: "pkg:nuget/Log4Net@2.0.5", subCategory: "misconfiguration");

        Assert.Equal(0, (await reconciler.ReconcileAsync([world.VersionId])).Attached);
    }

    [SkippableFact]
    public async Task A_sast_finding_is_never_written_into_the_cve_table()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.Roslyn, "S2094", Severity.High,
                      purl: "pkg:nuget/Log4Net@2.0.5");

        Assert.Equal(0, (await reconciler.ReconcileAsync([world.VersionId])).Attached);
    }

    // ---- Deduplication ------------------------------------------------------

    [SkippableFact]
    public async Task A_cve_grype_already_reported_is_not_duplicated()
    {
        Skip.IfNot(_fx.Available);

        // THE POINT OF THE WHOLE CLASS. One advisory on one component is one
        // row, whichever scanner found it first.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        db.Vulnerabilities.Add(new Vulnerability
        {
            SbomComponentId = world.Log4NetId,
            AdvisoryId = "CVE-2021-44228",
            Severity = Severity.Critical,
            Source = ScannerKind.Grype,
        });
        await db.SaveChangesAsync();

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: "pkg:nuget/Log4Net@2.0.5");

        var result = await reconciler.ReconcileAsync([world.VersionId]);

        Assert.Equal(0, result.Attached);
        Assert.Equal(1, result.AlreadyKnown);
        Assert.Equal(1, await db.Vulnerabilities.CountAsync(
            v => v.AdvisoryId == "CVE-2021-44228"
              && v.SbomComponent!.SbomSnapshot!.ComponentVersionId == world.VersionId));
    }

    [SkippableFact]
    public async Task Reconciling_twice_attaches_once()
    {
        Skip.IfNot(_fx.Available);

        // It runs on both ingest paths, so it runs repeatedly by design.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: "pkg:nuget/Log4Net@2.0.5");

        Assert.Equal(1, (await reconciler.ReconcileAsync([world.VersionId])).Attached);
        Assert.Equal(0, (await reconciler.ReconcileAsync([world.VersionId])).Attached);

        Assert.Equal(1, await db.Vulnerabilities.CountAsync(
            v => v.AdvisoryId == "CVE-2021-44228"
              && v.SbomComponent!.SbomSnapshot!.ComponentVersionId == world.VersionId));
    }

    // ---- What cannot be attached -------------------------------------------

    [SkippableFact]
    public async Task A_cve_with_no_package_is_reported_rather_than_guessed_at()
    {
        Skip.IfNot(_fx.Available);

        // Inventing a match from a file path would put a vulnerability on a
        // component that may not have it — worse than the gap, because the gap
        // is visible and the wrong answer is not.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: null);

        var result = await reconciler.ReconcileAsync([world.VersionId]);

        Assert.Equal(0, result.Attached);
        Assert.Equal(1, result.Unattached);
    }

    [SkippableFact]
    public async Task A_cve_against_a_package_this_build_does_not_ship_is_not_attached()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: "pkg:npm/not-in-this-sbom");

        var result = await reconciler.ReconcileAsync([world.VersionId]);

        Assert.Equal(0, result.Attached);
        Assert.Equal(1, result.Unattached);
    }

    [SkippableFact]
    public async Task An_sbom_ingested_afterwards_still_picks_up_the_finding()
    {
        Skip.IfNot(_fx.Available);

        // Ingest order is not guaranteed, which is why the reconciler runs on
        // both paths. This is the case that would silently lose a CVE if it
        // only ran on one.
        var world = await SeedAsync(withSbom: false);
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: "pkg:nuget/Log4Net@2.0.5");

        // Nothing to attach to yet.
        Assert.Equal(1, (await reconciler.ReconcileAsync([world.VersionId])).Unattached);

        var componentId = await AddSbomAsync(db, world);

        var result = await reconciler.ReconcileAsync([world.VersionId]);

        Assert.Equal(1, result.Attached);
        Assert.Equal(componentId, (await db.Vulnerabilities
            .SingleAsync(v => v.AdvisoryId == "CVE-2021-44228"
                           && v.SbomComponent!.SbomSnapshot!.ComponentVersionId == world.VersionId))
            .SbomComponentId);
    }

    [SkippableFact]
    public async Task A_closed_finding_is_not_reconciled()
    {
        Skip.IfNot(_fx.Available);

        // A CVE that is no longer open is one the scanner stopped reporting.
        // Attaching it would put it back into the count.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var db = _fx.Db(scope);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228", Severity.Critical,
                      purl: "pkg:nuget/Log4Net@2.0.5", status: FindingStatus.Fixed);

        Assert.Equal(0, (await reconciler.ReconcileAsync([world.VersionId])).Attached);
    }

    [SkippableFact]
    public async Task A_reconciled_cve_reaches_the_score()
    {
        Skip.IfNot(_fx.Available);

        // The whole reason the ticket exists: an orphaned CVE is a clean number
        // nobody measured.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var reconciler = scope.ServiceProvider.GetRequiredService<CveReconciler>();
        var inputs = scope.ServiceProvider
            .GetRequiredService<Tamp.Findings.Application.Risk.RiskInputsBuilder>();
        var db = _fx.Db(scope);

        var policy = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.BuildTampFederalV1();

        var before = await inputs.BuildAsync([world.VersionId], policy, world.ProjectId, default);
        Assert.Equal(0, before.CveCritical);

        await Finding(db, world, ScannerKind.OsvScanner, "CVE-2021-44228",
                      Severity.Critical, purl: "pkg:nuget/Log4Net@2.0.5");
        await reconciler.ReconcileAsync([world.VersionId]);

        var after = await inputs.BuildAsync([world.VersionId], policy, world.ProjectId, default);
        Assert.Equal(1, after.CveCritical);
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(Guid ProjectId, Guid VersionId, Guid Log4NetId, Guid SnapshotId);

    private static async Task Finding(
        FindingsDbContext db, World world, ScannerKind scanner, string ruleId, Severity severity,
        string? purl, string? subCategory = null, FindingStatus status = FindingStatus.Open)
    {
        db.Findings.Add(new Finding
        {
            ComponentVersionId = world.VersionId,
            Hash = Guid.NewGuid().ToString("N"),
            Scanner = scanner,
            RuleId = ruleId,
            Severity = severity,
            Title = $"{ruleId} in a dependency",
            SubCategory = subCategory,
            Purl = purl,
            Status = status,
        });
        await db.SaveChangesAsync();
    }

    private static async Task<Guid> AddSbomAsync(FindingsDbContext db, World world)
    {
        var snapshot = new SbomSnapshot { ComponentVersionId = world.VersionId, ToolName = "syft" };
        var component = new SbomComponent
        {
            SbomSnapshotId = snapshot.Id,
            Purl = "pkg:nuget/Log4Net@2.0.5",
            Name = "Log4Net",
            Version = "2.0.5",
        };
        db.SbomSnapshots.Add(snapshot);
        db.SbomComponents.Add(component);
        await db.SaveChangesAsync();
        return component.Id;
    }

    private async Task<World> SeedAsync(bool withSbom = true)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"cve-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"cve-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"cve-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0",
            CommitSha = suffix + "ffffff", BranchName = "main",
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);
        await db.SaveChangesAsync();

        var world = new World(project.Id, version.Id, Guid.Empty, Guid.Empty);

        if (!withSbom) return world;

        var componentId = await AddSbomAsync(db, world);
        return world with { Log4NetId = componentId };
    }
}
