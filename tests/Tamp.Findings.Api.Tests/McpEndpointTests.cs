using System.Net;

namespace Tamp.Findings.Api.Tests;

// The MCP endpoint's door (TFND-12 / F11.2).
//
// These run against the host with an UNREACHABLE database, which is exactly the
// condition worth asserting on an endpoint like this: the interesting question
// is not what it serves, it is what it refuses to serve when it cannot tell
// whether it should be serving at all.
public class McpEndpointTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public McpEndpointTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_endpoint_never_answers_anonymously()
    {
        // Whatever it says, it must not be a 200. An MCP client that got a
        // session without presenting a token would be reading somebody's
        // findings on the strength of knowing a URL.
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/mcp");

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task It_fails_closed_when_it_cannot_tell_whether_it_is_enabled()
    {
        // The database is unreachable in this fixture, so the McpEnabled switch
        // cannot be read. The one outcome that must never happen is the request
        // proceeding — a database outage must not be the condition under which
        // an agent surface opens itself.
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/mcp");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task A_presented_token_does_not_change_that()
    {
        // Auth is checked AFTER the switch, so a valid-looking token cannot
        // talk its way past an endpoint that is not serving.
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("Authorization", "Bearer mcp_anything");

        var response = await client.GetAsync("/mcp");

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task The_branch_covers_every_route_under_it_not_just_the_root()
    {
        // The auth is attached to the PATH BRANCH rather than to each mapped
        // route, because MapMcp registers more than one. A route the SDK adds in
        // a later version must be covered by the same door.
        var client = _factory.CreateClient();

        foreach (var path in new[] { "/mcp", "/mcp/", "/mcp/sse", "/mcp/message" })
        {
            var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        }
    }
}
