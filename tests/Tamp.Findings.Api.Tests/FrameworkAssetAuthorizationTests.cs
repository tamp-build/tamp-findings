using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;

namespace Tamp.Findings.Api.Tests;

// TFND-126. The Blazor framework assets are reachable anonymously; nothing else
// changed.
//
// These are the guard on FrameworkAssetAuthorizationHandler's path predicate.
// Widening it is how an authorization model quietly stops applying, and the
// failure would be invisible — every screen would still render, just to
// everybody.
public class FrameworkAssetAuthorizationTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public FrameworkAssetAuthorizationTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task The_blazor_script_is_served_to_an_anonymous_visitor()
    {
        // Without this there is no circuit, so nothing interactive works —
        // including the sign-in page that would let someone stop being
        // anonymous. A closed loop.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/_framework/blazor.web.js");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsByteArrayAsync();
        Assert.True(body.Length > 10_000, $"script served {body.Length} bytes — an empty 200 is also a failure here");
    }

    [Fact]
    public async Task Rcl_assets_are_served_to_an_anonymous_visitor()
    {
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/_content/Tamp.Findings.Web/app.css");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.True((await resp.Content.ReadAsStringAsync()).Length > 500);
    }

    [Theory]
    [InlineData("/auth/me")]
    [InlineData("/suppressions")]
    public async Task Application_routes_are_still_gated(string path)
    {
        // The half that matters. If the predicate ever widened, these would
        // start returning content and nothing else would notice.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync(path);

        Assert.NotEqual(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Project_screens_send_an_anonymous_visitor_to_sign_in()
    {
        // Redirected now, not answered with a signed-out shell. Rendering the
        // chrome to someone who can see nothing in it makes every panel look
        // empty rather than closed, which is indistinguishable from an
        // instance that simply has no data.
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var resp = await client.GetAsync("/c/brewingcoder/p/tamp/build/179fe8b");

        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);

        // Location comes back absolute, so compare the path rather than the
        // whole string.
        var location = resp.Headers.Location!;
        Assert.Equal("/signin", location.AbsolutePath);

        // The deep link survives, so signing in returns them to the page they
        // asked for rather than the portfolio.
        Assert.Contains(Uri.EscapeDataString("/c/brewingcoder/p/tamp/build/179fe8b"), location.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_sign_in_page_is_reachable_without_a_session()
    {
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync("/signin");

        Assert.Contains("Sign in", body, StringComparison.Ordinal);
        Assert.Contains("Continue with GitHub", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_sign_in_page_explains_what_a_new_account_can_do()
    {
        // A new user lands on read-only access with no role. Saying so on the
        // way in is cheaper than an support conversation about why the buttons
        // are disabled.
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync("/signin");

        Assert.Contains("read access and no role", body, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://evil.example/steal", false)]
    [InlineData("//evil.example/steal", false)]
    [InlineData("/c/brewingcoder/p/tamp/poam", true)]
    public async Task The_return_url_only_ever_forwards_a_local_path(string returnUrl, bool shouldForward)
    {
        // An absolute returnUrl would make this an open redirect: a phisher
        // could send a genuine tamp.findings sign-in link that lands the
        // victim elsewhere immediately after they authenticate.
        var client = _factory.CreateClient();

        var body = await client.GetStringAsync($"/signin?returnUrl={Uri.EscapeDataString(returnUrl)}");

        if (shouldForward)
        {
            Assert.Contains(Uri.EscapeDataString(returnUrl), body, StringComparison.Ordinal);
        }
        else
        {
            Assert.DoesNotContain("evil.example", body, StringComparison.OrdinalIgnoreCase);
        }
    }
}
