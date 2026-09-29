using System.Net;
using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Integration.Tests;

// TFND-177 / ADR 0008: the ingest-token compliance-profile read. A conformance
// producer reads its own project's profile with the same token the evidence
// flows through — so the tests pin the scope discipline (project token only,
// not-found for a client token) and the derived payload.
[Collection(DatabaseCollection.Name)]
public class ComplianceProfileIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ComplianceProfileIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(Guid ProjectId, Guid ClientId, Guid UserId)> SeedAsync(bool withFramework, bool withTemplate)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var suffix = Guid.NewGuid().ToString("N")[..8];

        var user = new User { Login = $"cp-{suffix}", DisplayName = "CP", Email = $"cp-{suffix}@example.test", IsApproved = true };
        db.Users.Add(user);

        Guid? fwId = withFramework
            ? await db.Frameworks.Where(f => f.Slug == "nist-mod").Select(f => (Guid?)f.Id).FirstAsync()
            : null;
        Guid? tplId = withTemplate
            ? await db.PolicyTemplates.Where(t => t.IsSeeded).Select(t => (Guid?)t.Id).FirstOrDefaultAsync()
            : null;

        var client = new Client { Name = $"cp-client-{suffix}", FrameworkId = fwId, PolicyTemplateId = tplId };
        db.Clients.Add(client);
        var project = new Project { ClientId = client.Id, Name = $"cp-project-{suffix}" };
        db.Projects.Add(project);
        await db.SaveChangesAsync();

        return (project.Id, client.Id, user.Id);
    }

    [SkippableFact]
    public async Task A_profile_carries_the_framework_its_computed_controls_and_a_template()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, _) = await SeedAsync(withFramework: true, withTemplate: true);

        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<ComplianceProfileQuery>();
        var p = await q.ForProjectAsync(projectId);

        Assert.NotNull(p);
        Assert.Equal("1.1", p!.SchemaVersion);   // TFND-185: added disposition + coverage
        Assert.Equal("nist-mod", p.Framework!.Id);
        // Applicable controls are COMPUTED from the Moderate baseline of the
        // seeded catalog — so there are some, each with title + family.
        Assert.NotEmpty(p.Controls);
        Assert.All(p.Controls, c => Assert.False(string.IsNullOrWhiteSpace(c.Title) || string.IsNullOrWhiteSpace(c.Family)));
        // Every in-scope control now carries a disposition, and the coverage
        // roll-up is present and totals the in-scope count (TFND-185 / ADR 0009).
        Assert.All(p.Controls, c => Assert.False(string.IsNullOrWhiteSpace(c.Disposition)));
        Assert.NotNull(p.Coverage);
        Assert.Equal(p.Controls.Count, p.Coverage!.InScope);
        Assert.Equal(p.Coverage.InScope,
            p.Coverage.Gated + p.Coverage.Inherited + p.Coverage.NotApplicable + p.Coverage.Unmapped);
        Assert.Single(p.PolicyTemplates);
        Assert.False(string.IsNullOrWhiteSpace(p.Enforcement.Mode));
    }

    // Regression (ADR 0015): a project-authored control disposition must flow through the policy
    // merge. ProjectLayer() bridging once dropped PolicyLayer.Assertions, so admin overrides were
    // silently ignored and the control stayed Unmapped.
    [SkippableFact]
    public async Task A_project_layer_assertion_dispositions_a_control()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, _) = await SeedAsync(withFramework: true, withTemplate: false);

        // Pick a real in-scope control that starts Unmapped (no template layer here).
        string controlId;
        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ComplianceProfileQuery>();
            var before = await q.ForProjectAsync(projectId);
            var unmapped = before!.Controls.First(c => c.Disposition == "Unmapped");
            controlId = unmapped.Id;
        }

        // Author a project-layer NotApplicable assertion for it.
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var project = await db.Projects.FirstAsync(p => p.Id == projectId);
            project.PolicyLayer = new Tamp.Findings.Domain.Risk.PolicyLayer
            {
                Assertions =
                [
                    new Tamp.Findings.Domain.Risk.ControlAssertion
                    {
                        Kind = Tamp.Findings.Domain.Risk.ControlDispositionKind.NotApplicable,
                        ControlIds = [controlId],
                        Justification = "regression: project override",
                    },
                ],
            };
            db.Entry(project).Property(p => p.PolicyLayer).IsModified = true;
            await db.SaveChangesAsync();
        }

        using (var scope = _fx.Scope())
        {
            var q = scope.ServiceProvider.GetRequiredService<ComplianceProfileQuery>();
            var after = await q.ForProjectAsync(projectId);
            var control = after!.Controls.First(c => c.Id == controlId);
            Assert.Equal("NotApplicable", control.Disposition);   // the project assertion won through the merge
            Assert.True(after.Coverage!.NotApplicable >= 1);
        }
    }

    [SkippableFact]
    public async Task A_project_with_no_framework_and_no_template_has_no_profile()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, _) = await SeedAsync(withFramework: false, withTemplate: false);

        using var scope = _fx.Scope();
        var q = scope.ServiceProvider.GetRequiredService<ComplianceProfileQuery>();
        Assert.Null(await q.ForProjectAsync(projectId));
    }

    [SkippableFact]
    public async Task The_endpoint_returns_the_profile_for_a_project_token()
    {
        Skip.IfNot(_fx.Available);
        var (projectId, _, userId) = await SeedAsync(withFramework: true, withTemplate: true);
        var plaintext = await MintProjectAsync(projectId, userId);

        using var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", plaintext);
        var resp = await http.GetAsync("/projects/self/compliance-profile");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("schemaVersion", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("nist-mod", body);
    }

    [SkippableFact]
    public async Task The_endpoint_rejects_a_missing_token_with_401()
    {
        Skip.IfNot(_fx.Available);
        using var http = _fx.Factory!.CreateClient();
        var resp = await http.GetAsync("/projects/self/compliance-profile");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [SkippableFact]
    public async Task The_endpoint_is_not_found_for_a_client_token()
    {
        // 'self' is ambiguous for a client token — refused as not-found, never a
        // confirmation of which projects exist under the client.
        Skip.IfNot(_fx.Available);
        var (_, clientId, userId) = await SeedAsync(withFramework: true, withTemplate: true);
        string plaintext;
        using (var scope = _fx.Scope())
        {
            var tokens = scope.ServiceProvider.GetRequiredService<IngestTokenService>();
            plaintext = (await tokens.MintClientTokenAsync(clientId, "cp-cli", userId, default)).Plaintext;
        }

        using var http = _fx.Factory!.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", plaintext);
        var resp = await http.GetAsync("/projects/self/compliance-profile");

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
    }

    private async Task<string> MintProjectAsync(Guid projectId, Guid userId)
    {
        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider.GetRequiredService<IngestTokenService>();
        return (await tokens.MintProjectTokenAsync(projectId, "cp-tok", userId, default)).Plaintext;
    }
}
