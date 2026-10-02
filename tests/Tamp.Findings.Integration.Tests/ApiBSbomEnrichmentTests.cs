using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Canned registry answers; any URL not routed is a 404. Never touches the network.</summary>
internal sealed class ApiBFakeRegistryHandler : HttpMessageHandler
{
    public List<string> Requests { get; } = [];
    private readonly object _gate = new();

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        lock (_gate) Requests.Add(url);

        if (url.Contains("PackageId:Pkg.Boom", StringComparison.Ordinal)) throw new HttpRequestException("registry down");

        string? json = url switch
        {
            // ---- NuGet search ----
            _ when url.Contains("PackageId:Pkg.Old&", StringComparison.Ordinal) =>
                """{"data":[{"version":"2.0.0","licenseExpression":"MIT"}]}""",
            _ when url.Contains("PackageId:Pkg.Current&", StringComparison.Ordinal) =>
                """{"data":[{"version":"3.0.0","license":"Apache-2.0"}]}""",
            _ when url.Contains("PackageId:Pkg.Catalog&", StringComparison.Ordinal) =>
                """{"data":[{"version":"1.5.0","licenseUrl":"https://x"}]}""",
            _ when url.Contains("PackageId:Pkg.Pre&", StringComparison.Ordinal) =>
                """{"data":[{"version":"9.0.0-beta.1","licenseExpression":"GPL-3.0-only"}]}""",
            _ when url.Contains("PackageId:Pkg.Empty&", StringComparison.Ordinal) => """{"data":[]}""",
            _ when url.Contains("PackageId:Pkg.NoData&", StringComparison.Ordinal) => """{"nope":1}""",
            _ when url.Contains("PackageId:Pkg.Unlisted&", StringComparison.Ordinal) =>
                """{"data":[{"version":"4.0.0","licenseExpression":"MIT"}]}""",
            // ---- NuGet registration leaves ----
            "https://api.nuget.org/v3/registration5-semver1/pkg.old/2.0.0.json" =>
                """{"published":"2024-03-01T00:00:00Z"}""",
            "https://api.nuget.org/v3/registration5-semver1/pkg.current/3.0.0.json" =>
                """{"published":"2024-05-01T00:00:00Z"}""",
            "https://api.nuget.org/v3/registration5-semver1/pkg.catalog/1.5.0.json" =>
                """{"published":"2024-06-01T00:00:00Z","catalogEntry":"https://catalog.test/pkg.catalog.1.5.0.json"}""",
            "https://api.nuget.org/v3/registration5-semver1/pkg.unlisted/4.0.0.json" =>
                """{"published":"1900-01-01T00:00:00Z"}""",
            "https://catalog.test/pkg.catalog.1.5.0.json" => """{"licenseExpression":"BSD-3-Clause"}""",
            // ---- npm ----
            "https://registry.npmjs.org/left-pad" =>
                """{"dist-tags":{"latest":"1.3.0"},"time":{"1.3.0":"2023-01-02T00:00:00Z"},"versions":{"1.3.0":{"license":"MIT"}}}""",
            "https://registry.npmjs.org/%40scope%2Fpkg" =>
                """{"dist-tags":{"latest":"2.0.0"},"license":{"type":"ISC"}}""",
            "https://registry.npmjs.org/legacy-array" =>
                """{"dist-tags":{"latest":"0.9.0"},"licenses":[{"type":"BSD-2-Clause"}]}""",
            "https://registry.npmjs.org/legacy-string" =>
                """{"dist-tags":{"latest":"0.8.0"},"licenses":["WTFPL"]}""",
            "https://registry.npmjs.org/no-tags" => """{"name":"no-tags"}""",
            "https://registry.npmjs.org/no-license" => """{"dist-tags":{"latest":"5.0.0"}}""",
            _ => null,
        };

        var resp = json is null
            ? new HttpResponseMessage(HttpStatusCode.NotFound)
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        return Task.FromResult(resp);
    }
}

[Collection(DatabaseCollection.Name)]
public class ApiBSbomEnrichmentTests
{
    private readonly DatabaseFixture _fx;
    public ApiBSbomEnrichmentTests(DatabaseFixture fx) => _fx = fx;

    private static SbomComponent C(Guid snap, string purl, string name, string version, string? license = null,
        string? latest = null, DateTimeOffset? latestAt = null) =>
        new() { SbomSnapshotId = snap, Purl = purl, Name = name, Version = version, License = license, LatestVersion = latest, LatestReleasedAt = latestAt };

    private async Task<(Guid snapshotId, string token, ApiBSupport.World w)> SeedAsync()
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var w = await ApiBSupport.SeedWorldAsync(db, s);
        var cv = await ApiBSupport.SeedBuildAsync(db, w.ProjectId);
        var snap = new SbomSnapshot { ComponentVersionId = cv };
        db.SbomSnapshots.Add(snap);
        db.SbomComponents.AddRange(
            C(snap.Id, "pkg:nuget/Pkg.Old@1.0.0", "Pkg.Old", "1.0.0"),
            C(snap.Id, "pkg:nuget/Pkg.Current@3.0.0", "Pkg.Current", "3.0.0", latest: "9.9.9", latestAt: DateTimeOffset.UtcNow),
            C(snap.Id, "pkg:nuget/Pkg.Catalog@1.0.0?arch=x#sub", "Pkg.Catalog", "1.0.0"),
            C(snap.Id, "pkg:nuget/Pkg.Pre@1.0.0", "Pkg.Pre", "1.0.0"),
            C(snap.Id, "pkg:nuget/Pkg.Empty@1.0.0", "Pkg.Empty", "1.0.0"),
            C(snap.Id, "pkg:nuget/Pkg.NoData@1.0.0", "Pkg.NoData", "1.0.0"),
            C(snap.Id, "pkg:nuget/Pkg.Missing@1.0.0", "Pkg.Missing", "1.0.0"),
            C(snap.Id, "pkg:nuget/Pkg.Boom@1.0.0", "Pkg.Boom", "1.0.0"),
            C(snap.Id, "pkg:nuget/Pkg.Unlisted@1.0.0", "Pkg.Unlisted", "1.0.0", license: "Proprietary"),
            C(snap.Id, "pkg:npm/left-pad@1.0.0", "left-pad", "1.0.0"),
            C(snap.Id, "pkg:npm/%40scope/pkg@1.0.0", "@scope/pkg", "1.0.0"),
            C(snap.Id, "pkg:npm/legacy-array@0.1.0", "legacy-array", "0.1.0"),
            C(snap.Id, "pkg:npm/legacy-string@0.1.0", "legacy-string", "0.1.0"),
            C(snap.Id, "pkg:npm/no-tags@1.0.0", "no-tags", "1.0.0"),
            C(snap.Id, "pkg:npm/no-license@5.0.0", "no-license", "5.0.0"),
            C(snap.Id, "pkg:npm/gone@1.0.0", "gone", "1.0.0"),
            C(snap.Id, "pkg:maven/org.x/y@1.0", "y", "1.0"));
        await db.SaveChangesAsync();
        var token = await ApiBSupport.MintProjectTokenAsync(scope.ServiceProvider, w.ProjectId, w.AdminId);
        return (snap.Id, token, w);
    }

    private WebApplicationFactory<Program> WithFakeRegistries(ApiBFakeRegistryHandler handler) =>
        _fx.Factory!.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
            services.AddHttpClient("registries").ConfigurePrimaryHttpMessageHandler(() => handler)));

    [SkippableFact]
    public async Task Enrichment_updates_versions_licenses_and_counts_each_outcome()
    {
        Skip.IfNot(_fx.Available);
        var (snapId, token, _) = await SeedAsync();
        var handler = new ApiBFakeRegistryHandler();
        var http = WithFakeRegistries(handler).Bearer(token);

        var resp = await http.PostAsync($"/sbom-components/enrich-versions?snapshotId={snapId}", null);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var result = (await resp.Content.ReadFromJsonAsync<SbomEnrichmentService.Result>(ApiBSupport.Json))!;
        Assert.Equal(1, result.Skipped);          // maven
        Assert.Equal(16, result.Checked);
        Assert.Equal(1, result.Errors);           // Pkg.Boom
        Assert.Equal(1, result.Cleared);          // Pkg.Current is already the latest
        Assert.True(result.Updated >= 7, $"updated={result.Updated}");
        Assert.True(result.LicensesFilled >= 7, $"licenses={result.LicensesFilled}");
        // The app's own background feed workers (KEV, OSV malicious packages) share the "registries" named
        // client, so on a slow runner their requests can land in this handler too. They are not enrichment.
        Assert.DoesNotContain(handler.Requests, u => !u.StartsWith("https://www.cisa.gov/", StringComparison.Ordinal)
            && !u.StartsWith("https://osv-vulnerabilities.storage.googleapis.com/", StringComparison.Ordinal)
            && !u.StartsWith("https://azuresearch-usnc.nuget.org/", StringComparison.Ordinal)
            && !u.StartsWith("https://api.nuget.org/", StringComparison.Ordinal)
            && !u.StartsWith("https://registry.npmjs.org/", StringComparison.Ordinal)
            && !u.StartsWith("https://catalog.test/", StringComparison.Ordinal));

        using var scope = _fx.Scope();
        var rows = await _fx.Db(scope).SbomComponents.AsNoTracking().Where(c => c.SbomSnapshotId == snapId).ToDictionaryAsync(c => c.Name);

        Assert.Equal("2.0.0", rows["Pkg.Old"].LatestVersion);
        Assert.Equal("MIT", rows["Pkg.Old"].License);
        Assert.Equal(DateTimeOffset.Parse("2024-03-01T00:00:00Z"), rows["Pkg.Old"].LatestReleasedAt);
        Assert.NotNull(rows["Pkg.Old"].EnrichedAt);

        // Current: stale latest cleared, legacy license string filled.
        Assert.Null(rows["Pkg.Current"].LatestVersion);
        Assert.Null(rows["Pkg.Current"].LatestReleasedAt);
        Assert.Equal("Apache-2.0", rows["Pkg.Current"].License);

        // License reached through registration -> catalogEntry; purl qualifiers and subpath stripped.
        Assert.Equal("1.5.0", rows["Pkg.Catalog"].LatestVersion);
        Assert.Equal("BSD-3-Clause", rows["Pkg.Catalog"].License);

        // Prerelease-only: no latest, but the license from the search entry is still taken.
        Assert.Null(rows["Pkg.Pre"].LatestVersion);
        Assert.Equal("GPL-3.0-only", rows["Pkg.Pre"].License);

        // Empty / malformed / missing / failing registry answers leave the row untouched.
        foreach (var name in new[] { "Pkg.Empty", "Pkg.NoData", "Pkg.Missing", "Pkg.Boom", "gone", "no-tags", "y" })
        {
            Assert.Null(rows[name].LatestVersion);
            Assert.Null(rows[name].EnrichedAt);
        }

        // An SBOM-declared license is never overwritten; unlisted (1900) publish date is not stored.
        Assert.Equal("Proprietary", rows["Pkg.Unlisted"].License);
        Assert.Equal("4.0.0", rows["Pkg.Unlisted"].LatestVersion);
        Assert.Null(rows["Pkg.Unlisted"].LatestReleasedAt);

        // npm: per-version license, scoped name with object license, legacy arrays, missing license.
        Assert.Equal("1.3.0", rows["left-pad"].LatestVersion);
        Assert.Equal("MIT", rows["left-pad"].License);
        Assert.Equal(DateTimeOffset.Parse("2023-01-02T00:00:00Z"), rows["left-pad"].LatestReleasedAt);
        Assert.Equal("2.0.0", rows["@scope/pkg"].LatestVersion);
        Assert.Equal("ISC", rows["@scope/pkg"].License);
        Assert.Equal("BSD-2-Clause", rows["legacy-array"].License);
        Assert.Equal("WTFPL", rows["legacy-string"].License);
        Assert.Null(rows["no-license"].License);
        Assert.Null(rows["no-license"].LatestVersion);   // 5.0.0 equals current
        Assert.NotNull(rows["no-license"].EnrichedAt);
    }

    [SkippableFact]
    public async Task The_endpoint_requires_a_bearer_token()
    {
        Skip.IfNot(_fx.Available);
        var anon = WithFakeRegistries(new ApiBFakeRegistryHandler()).CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsync("/sbom-components/enrich-versions", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await _fx.Factory!.Bearer("cli_not-a-real-token").PostAsync("/sbom-components/enrich-versions", null)).StatusCode);
    }

    [SkippableFact]
    public async Task A_snapshot_with_no_components_yields_an_empty_summary()
    {
        Skip.IfNot(_fx.Available);
        var (_, token, _) = await SeedAsync();
        var http = WithFakeRegistries(new ApiBFakeRegistryHandler()).Bearer(token);

        var resp = await http.PostAsync($"/sbom-components/enrich-versions?snapshotId={Guid.NewGuid()}", null);
        var result = (await resp.Content.ReadFromJsonAsync<SbomEnrichmentService.Result>(ApiBSupport.Json))!;

        Assert.Equal(0, result.Checked + result.Updated + result.Errors + result.Skipped);
    }
}
