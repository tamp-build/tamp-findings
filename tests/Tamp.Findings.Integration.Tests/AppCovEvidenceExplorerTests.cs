using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Evidence;
using Tamp.Findings.Application.Explorer;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// EvidenceQuery, DastExplorerQuery and HostAliasService (+ HostAliasMap heuristics).
[Collection(DatabaseCollection.Name)]
public class AppCovEvidenceExplorerTests
{
    private readonly DatabaseFixture _fx;
    public AppCovEvidenceExplorerTests(DatabaseFixture fx) => _fx = fx;

    private static Finding F(Guid cv, ScannerKind sc, Severity sev, string tag, string? path = null, string? snippet = null) => new()
    {
        ComponentVersionId = cv, Hash = $"{tag}-{Guid.NewGuid():N}", Scanner = sc, RuleId = $"r-{tag}", Severity = sev,
        Title = $"t-{tag}", FilePath = path ?? $"f/{tag}.cs", Line = 1, Snippet = snippet,
    };

    [SkippableFact]
    public async Task Evidence_query_lists_per_lane_findings_kev_and_images()
    {
        Skip.IfNot(_fx.Available);
        Guid projectId, empty;
        string sha;
        var cve = $"CVE-2099-{Random.Shared.Next(1000, 9999)}";
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "ev");
            var (_, emptyProject) = await AppCovSeed.ClientProjectAsync(db, "ev-empty");
            empty = emptyProject.Id;
            var cv = await AppCovSeed.BuildAsync(db, project.Id);
            projectId = project.Id; sha = cv.CommitSha!;
            db.Findings.AddRange(
                F(cv.Id, ScannerKind.Zap, Severity.High, "z"), F(cv.Id, ScannerKind.Nuclei, Severity.Critical, "n"),
                F(cv.Id, ScannerKind.Spectral, Severity.Low, "sp"), F(cv.Id, ScannerKind.AxeCore, Severity.Medium, "ax"),
                F(cv.Id, ScannerKind.Roslyn, Severity.High, "ro"));
            var snap = new SbomSnapshot { ComponentVersionId = cv.Id };
            db.SbomSnapshots.Add(snap);
            var c1 = new SbomComponent { SbomSnapshotId = snap.Id, Purl = "pkg:nuget/a@1", Name = "a", Version = "1" };
            var c2 = new SbomComponent { SbomSnapshotId = snap.Id, Purl = "pkg:nuget/b@1", Name = "b", Version = "1" };
            db.SbomComponents.AddRange(c1, c2);
            db.Vulnerabilities.AddRange(
                new Vulnerability { SbomComponentId = c1.Id, AdvisoryId = cve, Severity = Severity.High },
                new Vulnerability { SbomComponentId = c2.Id, AdvisoryId = cve, Severity = Severity.Critical },
                new Vulnerability { SbomComponentId = c2.Id, AdvisoryId = "CVE-NOTKEV", Severity = Severity.Low });
            db.KevAdvisories.Add(new KevAdvisory { CveId = cve, Product = "p", VulnerabilityName = "v", DateAdded = new DateOnly(2024, 1, 1), DueDate = new DateOnly(2024, 2, 1), KnownRansomwareCampaignUse = true });
            var now = DateTimeOffset.UtcNow;
            db.ContainerImages.Add(new ContainerImage { ComponentVersionId = cv.Id, Reference = "img:1", BaseImageReference = "base:1", BaseImageCreatedAt = now.AddDays(-30), InspectedAt = now, OsFamily = "debian", OsVersion = "12" });
            await db.SaveChangesAsync();
            // second CV with the same sha for another image: base created in the future, and one with no base age
            var cv2 = new ComponentVersion { ProjectId = project.Id, VersionString = "x", CommitSha = sha, Flavor = "b" };
            db.ComponentVersions.Add(cv2);
            db.ContainerImages.Add(new ContainerImage { ComponentVersionId = cv2.Id, Reference = "img:2", BaseImageCreatedAt = now.AddDays(5), InspectedAt = now });
            var cv3 = new ComponentVersion { ProjectId = project.Id, VersionString = "y", CommitSha = sha, Flavor = "c" };
            db.ComponentVersions.Add(cv3);
            db.ContainerImages.Add(new ContainerImage { ComponentVersionId = cv3.Id, Reference = "img:3", InspectedAt = now });
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var q = s.ServiceProvider.GetRequiredService<EvidenceQuery>();
        Assert.Equal(2, (await q.DastAsync(projectId, null)).Count);
        Assert.Equal(Severity.Critical, (await q.DastAsync(projectId, sha))[0].Severity);
        Assert.Single(await q.QualityAsync(projectId, sha));
        Assert.Single(await q.AccessibilityAsync(projectId, sha));
        var kev = await q.KevAsync(projectId, null);
        Assert.Single(kev);
        Assert.Equal(Severity.Critical, kev[0].Severity);
        Assert.True(kev[0].KnownRansomware);
        var imgs = await q.BaseImagesAsync(projectId, sha);
        Assert.Equal(3, imgs.Count);
        Assert.Equal(30, imgs[0].AgeDays);
        Assert.Contains(imgs, i => i.AgeDays == 0);
        Assert.Contains(imgs, i => i.AgeDays is null);

        Assert.Empty(await q.DastAsync(empty, null));
        Assert.Empty(await q.QualityAsync(empty, null));
        Assert.Empty(await q.KevAsync(empty, null));
        Assert.Empty(await q.BaseImagesAsync(empty, null));
    }

    [SkippableFact]
    public async Task Dast_tree_groups_by_host_and_route_with_evidence_and_aliases()
    {
        Skip.IfNot(_fx.Available);
        Guid projectId;
        string sha;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var (_, project) = await AppCovSeed.ClientProjectAsync(db, "dast");
            var cv = await AppCovSeed.BuildAsync(db, project.Id);
            projectId = project.Id; sha = cv.CommitSha!;
            db.Findings.AddRange(
                F(cv.Id, ScannerKind.Zap, Severity.High, "a", "https://app.example.com/api/x?id=1", "GET /api/x HTTP/1.1\n\nHTTP/1.1 200 OK\n\nbody"),
                F(cv.Id, ScannerKind.Zap, Severity.Low, "b", "https://app.example.com/api/x?id=2", "req\n\n\nresp"),
                F(cv.Id, ScannerKind.Nuclei, Severity.Critical, "c", "https://app.example.com:8443/other", "just a blob"),
                F(cv.Id, ScannerKind.Nuclei, Severity.Medium, "d", "/relative/path", "   "),
                F(cv.Id, ScannerKind.AxeCore, Severity.Low, "e", "https://app.internal/page", null),
                F(cv.Id, ScannerKind.Zap, Severity.Low, "f", "https://app.example.com/closed"));
            var closed = db.Findings.Local.Single(x => x.RuleId == "r-f");
            closed.Status = FindingStatus.Fixed;
            await db.SaveChangesAsync();
        }

        using var s = _fx.Scope();
        var q = s.ServiceProvider.GetRequiredService<DastExplorerQuery>();
        var tree = await q.TreeAsync(projectId, sha);
        Assert.True(tree.Hosts.Count >= 3);
        Assert.DoesNotContain(tree.Hosts.SelectMany(h => h.Routes), r => r.Route.Contains("closed", StringComparison.Ordinal));
        Assert.NotEmpty(tree.Duplicates);

        var host = tree.Hosts.Single(h => h.Host.Contains("app.example.com", StringComparison.Ordinal) && !h.Host.Contains("8443", StringComparison.Ordinal));
        var route = host.Routes.OrderByDescending(r => r.Count).First();
        var detail = await q.DetailAsync(projectId, null, route.Route);
        Assert.NotEmpty(detail);
        Assert.Contains(detail, d => d.Evidence.Request is not null);

        var all = await q.DetailAsync(projectId, sha, "nope");
        Assert.Empty(all);

        var axe = await q.TreeAsync(projectId, null, ScannerKinds.Accessibility);
        Assert.Single(axe.Hosts);
        Assert.NotEmpty(await q.DetailAsync(projectId, sha, axe.Hosts[0].Routes[0].Route, ScannerKinds.Accessibility));
        var blob = (await q.DetailAsync(projectId, sha, tree.Hosts.SelectMany(h => h.Routes).First(r => r.Route.Contains("other", StringComparison.Ordinal)).Route))
            .Single();
        Assert.Null(blob.Evidence.Request);
        Assert.Equal("just a blob", blob.Evidence.Response);
        var rel = tree.Hosts.SelectMany(h => h.Routes).First(r => r.Route.Contains("relative", StringComparison.Ordinal));
        var relDetail = (await q.DetailAsync(projectId, sha, rel.Route)).Single();
        Assert.Null(relDetail.Evidence.Response);
    }

    [SkippableFact]
    public async Task Host_alias_merge_rules_and_canonicalisation()
    {
        Skip.IfNot(_fx.Available);
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "alias");
        var target = Tamp.Findings.Application.Authorization.ScopeTarget.Project(client.Id, project.Id);
        var svc = scope.ServiceProvider.GetRequiredService<HostAliasService>();

        Assert.True((await svc.MergeAsync(actors.Viewer, target, project.Id, "a", "b", "r")).WasDenied);
        Assert.False((await svc.MergeAsync(actors.Admin, target, project.Id, " ", "b", "r")).Success);
        Assert.False((await svc.MergeAsync(actors.Admin, target, project.Id, "a", "A", "r")).Success);
        Assert.False((await svc.MergeAsync(actors.Admin, target, project.Id, "a", "b", " ")).Success);
        Assert.True((await svc.MergeAsync(actors.Admin, target, project.Id, "alias.local", "canon.example.com", " same app ")).Success);
        Assert.False((await svc.MergeAsync(actors.Admin, target, project.Id, "x", "alias.local", "r")).Success);
        Assert.False((await svc.MergeAsync(actors.Admin, target, project.Id, "alias.local", "other", "r")).Success);

        var map = await svc.ForProjectAsync(project.Id);
        Assert.Equal("canon.example.com", map.Canonical("ALIAS.local"));
        Assert.Equal("untouched", map.Canonical("untouched"));
    }

    [Fact]
    public void Host_alias_map_suspects_duplicates_by_port_label_and_locality()
    {
        var map = new HostAliasMap(new Dictionary<string, string>());
        var s = map.SuspectedDuplicates(["app.example.com:80", "app.example.com:8080", "web.example.com", "web.other.org", "localhost", "remote.net", "(relative)", "(unknown host)", "zz", "yy"]);
        Assert.Contains(s, x => x.Reason == "same host on different ports");
        Assert.Contains(s, x => x.Reason.StartsWith("both start with", StringComparison.Ordinal));
        Assert.Contains(s, x => x.Reason == "one address is local and the other is not");
        Assert.DoesNotContain(s, x => x.HostA == "(relative)" || x.HostB == "(relative)");
        Assert.Empty(map.SuspectedDuplicates(["a.com", "b.com"]));
        Assert.NotEmpty(map.SuspectedDuplicates(["x.local", "y.com"]));
        Assert.NotEmpty(map.SuspectedDuplicates(["127.0.0.1", "y.com"]));
    }
}
