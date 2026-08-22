using System.Net;
using System.Net.Http.Json;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Tests;

// TFND-71 / TFND-19: X-Author-Role header trust is gone.
//
// The old behaviour, from ADR 0001: "SuppressionsEndpoints reads the role from
// an X-Author-Role HTTP header and trusts it." Anyone who could reach the
// endpoint could claim any role by typing it. These assert it no longer works.
public class SuppressionAuthorizationTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public SuppressionAuthorizationTests(TestApiFactory factory) => _factory = factory;

    private static object RuleEverywhere() => new
    {
        scope = (int)SuppressionScope.RuleEverywhere,
        ruleId = "CA1822",
        reason = "test",
    };

    [Fact]
    public async Task An_anonymous_request_cannot_author_a_suppression()
    {
        var client = _factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/suppressions", RuleEverywhere());

        // 401 from the fallback policy, or 403 from the capability check —
        // either is a refusal. What must never happen is a 200.
        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Claiming_a_role_in_a_header_has_no_effect()
    {
        // The regression test for the whole ticket. This exact request used to
        // succeed and create a suppression attributed to an InfoSec Officer.
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Author-User", "mallory");
        client.DefaultRequestHeaders.Add("X-Author-Role", "InfoSecOfficer");

        var resp = await client.PostAsJsonAsync("/suppressions", RuleEverywhere());

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Claiming_to_be_an_admin_in_a_header_has_no_effect()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Author-User", "mallory");
        client.DefaultRequestHeaders.Add("X-Author-Role", "Architect");
        client.DefaultRequestHeaders.Add("X-Tamp-IsAdmin", "true");

        var resp = await client.PostAsJsonAsync("/suppressions", RuleEverywhere());

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task An_authenticated_user_with_no_role_assignment_is_refused()
    {
        // Per TFND-19's acceptance: "A user without an assignment gets 403 on
        // POST /suppressions." Authenticating is not the same as being
        // authorised — a Viewer may read everything and author nothing.
        var client = _factory.CreateSignedIn(login: "no-roles");

        var resp = await client.PostAsJsonAsync("/suppressions", RuleEverywhere());

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
        Assert.True(
            resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized,
            $"expected a refusal, got {(int)resp.StatusCode}");
    }

    [Fact]
    public async Task An_authenticated_user_cannot_elevate_themselves_with_a_header()
    {
        // THE decisive test. /suppressions was already behind the fallback
        // authorization policy, so the anonymous cases above would refuse even
        // without this ticket's change — they are belt and braces.
        //
        // The actual escalation was this: any AUTHENTICATED user, including a
        // Viewer with no assignments at all, could send
        // "X-Author-Role: InfoSecOfficer" and be treated as one. This request
        // returned 200 and created a suppression attributed to an InfoSec
        // Officer before the fix.
        var client = _factory.CreateSignedIn(login: "viewer-with-ambition");
        client.DefaultRequestHeaders.Add("X-Author-User", "viewer-with-ambition");
        client.DefaultRequestHeaders.Add("X-Author-Role", "InfoSecOfficer");

        var resp = await client.PostAsJsonAsync("/suppressions", RuleEverywhere());

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task The_endpoint_no_longer_advertises_header_auth()
    {
        // The OpenAPI summary told callers to send X-Author-User and
        // X-Author-Role. Leaving that in place would keep the pattern alive in
        // every client written from the docs.
        var client = _factory.CreateClient();

        var openapi = await client.GetStringAsync("/openapi/v1.json");

        Assert.DoesNotContain("X-Author-Role", openapi, StringComparison.OrdinalIgnoreCase);
    }
}
