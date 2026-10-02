using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.GitHub;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// GitHubCheckPublisher driven end to end against a fake HttpMessageHandler (never the network).
[Collection(DatabaseCollection.Name)]
public class AppCovGitHubCheckPublisherTests
{
    private readonly DatabaseFixture _fx;
    public AppCovGitHubCheckPublisherTests(DatabaseFixture fx) => _fx = fx;

    private sealed class FakeHandler(Func<HttpRequestMessage, string?, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Calls { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            Calls.Add((request.Method, request.RequestUri!.AbsolutePath, body));
            return respond(request, body);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string json) =>
        new(code) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static string NewPem() { using var rsa = RSA.Create(2048); return rsa.ExportPkcs8PrivateKeyPem(); }

    private sealed record World(Guid ProjectId, string Sha, string Client, string Project);

    private async Task<World> SeedAsync(string? repo, bool withPrior = false, bool withBuild = true)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"gh client {s}" };
        var project = new Project { ClientId = client.Id, Name = $"gh/project {s}", GitHubRepository = repo };
        db.Clients.Add(client);
        db.Projects.Add(project);
        var sha = $"{s}abcdef0123456789";
        if (withBuild)
            db.ComponentVersions.Add(new ComponentVersion { ProjectId = project.Id, VersionString = "2", CommitSha = sha, BranchName = "feature/x", CreatedAt = DateTimeOffset.UtcNow });
        if (withPrior)
            db.ComponentVersions.Add(new ComponentVersion { ProjectId = project.Id, VersionString = "1", CommitSha = $"{s}prior", BranchName = "main", CreatedAt = DateTimeOffset.UtcNow.AddDays(-2) });
        await db.SaveChangesAsync();
        return new World(project.Id, sha, client.Name, project.Name);
    }

    private async Task WithSettingsAsync(Action<InstanceSettings> mutate, Func<Task> body)
    {
        InstanceSettings? original;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            original = await db.InstanceSettings.AsNoTracking().SingleOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
            var row = await db.InstanceSettings.SingleOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
            if (row is null) { row = new InstanceSettings(); db.InstanceSettings.Add(row); }
            mutate(row);
            await db.SaveChangesAsync();
        }
        try { await body(); }
        finally
        {
            using var scope = _fx.Scope();
            var db = _fx.Db(scope);
            var row = await db.InstanceSettings.SingleOrDefaultAsync(x => x.Id == InstanceSettings.SingletonId);
            if (row is not null)
            {
                if (original is null) db.InstanceSettings.Remove(row);
                else
                {
                    row.GitHubChecksEnabled = original.GitHubChecksEnabled;
                    row.GitHubAppId = original.GitHubAppId;
                    row.GitHubAppPrivateKeyProtected = original.GitHubAppPrivateKeyProtected;
                    row.GitHubCheckName = original.GitHubCheckName;
                    row.InstanceUrl = original.InstanceUrl;
                }
                await db.SaveChangesAsync();
            }
        }
    }

    private GitHubCheckPublisher Publisher(IServiceScope scope, FakeHandler handler)
    {
        var sp = scope.ServiceProvider;
        return new GitHubCheckPublisher(
            sp.GetRequiredService<FindingsDbContext>(), sp.GetRequiredService<RiskInputsBuilder>(),
            sp.GetRequiredService<ProviderSecretProtector>(), sp.GetRequiredService<AuditLog>(),
            new HttpClient(handler) { BaseAddress = new Uri("https://api.github.com/") },
            NullLogger<GitHubCheckPublisher>.Instance, TimeProvider.System, sp.GetRequiredService<ScoringPolicyResolver>());
    }

    private string Protected(string pem)
    {
        using var scope = _fx.Scope();
        return scope.ServiceProvider.GetRequiredService<ProviderSecretProtector>()
            .Protect(ProviderSecretProtector.GitHubAppPurpose, pem);
    }

    [SkippableFact]
    public async Task Skips_when_disabled_unconfigured_or_unmapped()
    {
        Skip.IfNot(_fx.Available);
        var mapped = await SeedAsync("acme/widgets");
        var unmapped = await SeedAsync(null);

        await WithSettingsAsync(s => s.GitHubChecksEnabled = false, async () =>
        {
            using var scope = _fx.Scope();
            var o = await Publisher(scope, new FakeHandler((_, _) => Json(HttpStatusCode.OK, "{}"))).PublishAsync(mapped.ProjectId, mapped.Sha);
            Assert.False(o.Success);
            Assert.Contains("not enabled", o.Reason);
        });

        await WithSettingsAsync(s => { s.GitHubChecksEnabled = true; s.GitHubAppId = null; s.GitHubAppPrivateKeyProtected = null; }, async () =>
        {
            using var scope = _fx.Scope();
            var o = await Publisher(scope, new FakeHandler((_, _) => Json(HttpStatusCode.OK, "{}"))).PublishAsync(mapped.ProjectId, mapped.Sha);
            Assert.Contains("credentials", o.Reason);
        });

        var prot = Protected(NewPem());
        await WithSettingsAsync(s => { s.GitHubChecksEnabled = true; s.GitHubAppId = "123"; s.GitHubAppPrivateKeyProtected = prot; }, async () =>
        {
            using var scope = _fx.Scope();
            var h = new FakeHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
            var pub = Publisher(scope, h);
            Assert.Contains("not mapped", (await pub.PublishAsync(unmapped.ProjectId, unmapped.Sha)).Reason);
            Assert.Contains("not mapped", (await pub.PublishAsync(Guid.NewGuid(), "x")).Reason);
            var noBuild = await SeedAsync("acme/nobuild", withBuild: false);
            Assert.Contains("No build matching", (await pub.PublishAsync(noBuild.ProjectId, "zzz")).Reason);
            Assert.Empty(h.Calls);
        });
    }

    [SkippableFact]
    public async Task Undecryptable_key_fails_without_calling_github()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync("acme/widgets");
        await WithSettingsAsync(s => { s.GitHubChecksEnabled = true; s.GitHubAppId = "1"; s.GitHubAppPrivateKeyProtected = "garbage-not-protected"; }, async () =>
        {
            using var scope = _fx.Scope();
            var h = new FakeHandler((_, _) => Json(HttpStatusCode.OK, "{}"));
            var o = await Publisher(scope, h).PublishAsync(w.ProjectId, w.Sha);
            Assert.False(o.Success);
            Assert.Contains("could not be decrypted", o.Reason);
            Assert.Empty(h.Calls);
        });
    }

    [SkippableFact]
    public async Task Publishes_a_check_run_and_audits_it()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync("acme/widgets", withPrior: true);
        var prot = Protected(NewPem());
        await WithSettingsAsync(s => { s.GitHubChecksEnabled = true; s.GitHubAppId = "42"; s.GitHubAppPrivateKeyProtected = prot; s.GitHubCheckName = "tamp-gate"; s.InstanceUrl = "https://findings.example/"; }, async () =>
        {
            using var scope = _fx.Scope();
            var h = new FakeHandler((req, _) => req.RequestUri!.AbsolutePath switch
            {
                "/repos/acme/widgets/installation" => Json(HttpStatusCode.OK, """{"id":777}"""),
                "/app/installations/777/access_tokens" => Json(HttpStatusCode.Created, """{"token":"ghs_tok"}"""),
                "/repos/acme/widgets/check-runs" => Json(HttpStatusCode.Created, "{}"),
                _ => Json(HttpStatusCode.NotFound, "{}"),
            });
            var o = await Publisher(scope, h).PublishAsync(w.ProjectId, w.Sha);

            Assert.True(o.Success);
            Assert.NotNull(o.Conclusion);
            Assert.Equal(3, h.Calls.Count);
            var post = h.Calls[2];
            Assert.Equal(HttpMethod.Post, post.Method);
            Assert.Contains("\"name\":\"tamp-gate\"", post.Body);
            Assert.Contains($"\"head_sha\":\"{w.Sha}\"", post.Body);
            Assert.Contains("\"status\":\"completed\"", post.Body);
            Assert.Contains("https://findings.example/c/", post.Body);
            Assert.Contains("/build/", post.Body);
        });

        using var verify = _fx.Scope();
        var audits = await _fx.Db(verify).AuditEntries.AsNoTracking().Where(a => a.SubjectId == w.ProjectId && a.Action == "github.check_published").ToListAsync();
        Assert.Single(audits);
    }

    [SkippableFact]
    public async Task Reports_not_installed_and_unreachable_and_mint_failures()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync("acme/widgets");
        var prot = Protected(NewPem());
        await WithSettingsAsync(s => { s.GitHubChecksEnabled = true; s.GitHubAppId = "42"; s.GitHubAppPrivateKeyProtected = prot; s.InstanceUrl = null; }, async () =>
        {
            using var scope = _fx.Scope();
            var o1 = await Publisher(scope, new FakeHandler((_, _) => Json(HttpStatusCode.NotFound, "{}"))).PublishAsync(w.ProjectId, w.Sha);
            Assert.Contains("not installed", o1.Reason);

            var o2 = await Publisher(scope, new FakeHandler((_, _) => throw new HttpRequestException("down"))).PublishAsync(w.ProjectId, w.Sha);
            Assert.Contains("unreachable", o2.Reason);

            var o3 = await Publisher(scope, new FakeHandler((req, _) => req.RequestUri!.AbsolutePath.EndsWith("installation", StringComparison.Ordinal)
                ? Json(HttpStatusCode.OK, """{"id":1}""") : Json(HttpStatusCode.Forbidden, "{}"))).PublishAsync(w.ProjectId, w.Sha);
            Assert.Contains("unreachable", o3.Reason);
        });
    }
}
