using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Minting agent tokens over HTTP (TFND-259).
///
/// MintAsync used to be callable from two Razor pages and nowhere else, so an
/// operator could not get an agent onto the MCP surface without a browser and a
/// navigable client page — and on a fresh instance that made the whole surface
/// unreachable.
///
/// These cover the route, and more importantly they pin the properties that
/// must NOT have been loosened by opening it up: the scope rule, the capability,
/// and the refusal to mint an agent that accepts risk.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBAgentTokenEndpointTests
{
    private readonly DatabaseFixture _fx;
    public ApiBAgentTokenEndpointTests(DatabaseFixture fx) => _fx = fx;

    private async Task<HttpClient> AdminAsync() => Http(_fx, await UserAsync(_fx, admin: true));

    private async Task<HttpClient> AuditorAsync(Guid clientId)
    {
        var id = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, id, ProjectRole.Auditor, clientId, null);
        return Http(_fx, id);
    }

    [SkippableFact]
    public async Task An_admin_mints_a_project_scoped_token_and_the_plaintext_comes_back_once()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var response = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "claude · remediation" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();

        Assert.Equal("Project", body!["scope"].ToString());
        var token = body["token"].ToString()!;
        Assert.StartsWith("mcp_", token, StringComparison.Ordinal);

        // Only a hash is stored, so the plaintext is genuinely unrecoverable —
        // listing must never hand it back.
        var listed = await admin.GetFromJsonAsync<List<Dictionary<string, object>>>(
            $"/projects/{tree.ProjectId}/agent-tokens");
        Assert.DoesNotContain(listed!, row => row.Values.Any(v => v?.ToString() == token));
    }

    [SkippableFact]
    public async Task A_client_scoped_token_can_be_minted_too()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var response = await admin.PostAsJsonAsync(
            $"/clients/{tree.ClientId}/agent-tokens", new { name = "portfolio agent" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        Assert.Equal("Client", body!["scope"].ToString());
    }

    [SkippableFact]
    public async Task The_minted_token_actually_works_at_the_mcp_endpoint()
    {
        Skip.IfNot(_fx.Available);

        // The point of the whole ticket: a token obtained WITHOUT a browser can
        // drive the agent surface. Anything less and the route is decoration.
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var minted = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "resolves" });
        var body = await minted.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        var token = body!["token"].ToString()!;

        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider
            .GetRequiredService<Tamp.Findings.Application.Mcp.McpTokenService>();

        var identity = await tokens.ResolveAsync(token, DateTimeOffset.UtcNow);

        Assert.NotNull(identity);
        Assert.Equal(tree.ProjectId, identity!.Scope.ProjectId);
    }

    [SkippableFact]
    public async Task A_role_can_be_asked_for_and_an_unknown_one_is_refused()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var ok = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "auditor", role = "Auditor" });
        Assert.Equal(HttpStatusCode.Created, ok.StatusCode);

        // Silently falling back to Viewer would hand back a token quieter than
        // was asked for, and the caller would not find out until an agent could
        // not export.
        var bad = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "nope", role = "Auditorr" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
    }

    // ---- the properties that must survive the new route ---------------------

    [SkippableFact]
    public async Task InfoSecOfficer_is_still_refused_over_HTTP()
    {
        Skip.IfNot(_fx.Available);

        // TFND-242 / ADR 0019 §6: no agent carries AcceptRisk, because accepting
        // risk is an Authorizing Official's signature. The guarantee was already
        // enforced only by a dropdown once; a new route must not become the
        // second way around it.
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var response = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens",
            new { name = "too much", role = nameof(ProjectRole.InfoSecOfficer) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("InfoSecOfficer", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task A_viewer_cannot_mint_one()
    {
        Skip.IfNot(_fx.Available);

        // Minting access needs AssignRoles — the capability that grants access,
        // not the one that manages CI keys. An agent token is a standing grant
        // to whatever holds it.
        var tree = await ClientProjectAsync(_fx);
        var viewer = await AuditorAsync(tree.ClientId);

        var response = await viewer.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "sneaky" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [SkippableFact]
    public async Task An_anonymous_caller_cannot_mint_one()
    {
        Skip.IfNot(_fx.Available);
        var tree = await ClientProjectAsync(_fx);

        var response = await Http(_fx, null).PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "anon" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [SkippableFact]
    public async Task A_blank_name_is_refused_because_a_revoke_decision_needs_a_label()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var response = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "   " });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [SkippableFact]
    public async Task Revoking_stops_the_token_resolving()
    {
        Skip.IfNot(_fx.Available);
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var minted = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "short-lived" });
        var body = await minted.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        var id = Guid.Parse(body!["id"].ToString()!);
        var token = body["token"].ToString()!;

        var revoked = await admin.DeleteAsync($"/agent-tokens/{id}");
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        using var scope = _fx.Scope();
        var tokens = scope.ServiceProvider
            .GetRequiredService<Tamp.Findings.Application.Mcp.McpTokenService>();
        Assert.Null(await tokens.ResolveAsync(token, DateTimeOffset.UtcNow));
    }

    [SkippableFact]
    public async Task Minting_is_audited_as_an_access_decision()
    {
        Skip.IfNot(_fx.Available);

        // An agent token is a standing grant, so issuing one is an access event
        // whichever surface issued it.
        var admin = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);

        var minted = await admin.PostAsJsonAsync(
            $"/projects/{tree.ProjectId}/agent-tokens", new { name = "audited agent" });
        var body = await minted.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        var id = Guid.Parse(body!["id"].ToString()!);

        using var scope = _fx.Scope();
        var entry = await _fx.Db(scope).AuditEntries.SingleAsync(a => a.SubjectId == id);

        Assert.Equal(AuditClass.Access, entry.Class);
        Assert.Contains("audited agent", entry.Detail!, StringComparison.Ordinal);
    }
}
