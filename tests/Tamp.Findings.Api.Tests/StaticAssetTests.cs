using System.Net;

namespace Tamp.Findings.Api.Tests;

// Regression tests for how the Blazor UI's static assets are served (TFND-61).
//
// These exist because a status-code check is not enough to catch the failure
// that actually happened. MapStaticAssets registers ENDPOINTS, which inherit
// the host's RequireAuthenticatedUser fallback policy; marking them
// AllowAnonymous made every asset return 200 with an EMPTY BODY, including the
// fingerprinted URLs its own Assets[] helper emits. The page rendered, every
// probe returned 200, and the app was completely unstyled.
//
// So every assertion here checks the length, not just the code.
public class StaticAssetTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory _factory;

    public StaticAssetTests(TestApiFactory factory) => _factory = factory;

    [Theory]
    [InlineData("/_content/Tamp.Findings.Web/app.css")]
    [InlineData("/_content/Tamp.Findings.Web/tokens.css")]
    [InlineData("/_content/Tamp.Findings.Web/fonts.css")]
    public async Task Ui_stylesheets_are_served_with_content(string path)
    {
        var client = _factory.CreateClient();

        var resp = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        // The exact number does not matter; "not empty" is the whole point.
        Assert.True(body.Length > 500, $"{path} served {body.Length} bytes — an empty 200 is the bug this test exists for.");
    }

    [Fact]
    public async Task Stylesheets_are_reachable_without_authenticating()
    {
        // The host applies a RequireAuthenticatedUser fallback policy to every
        // endpoint. Assets must sit outside it: the sign-in page has to render
        // and style itself BEFORE the visitor has a session. Serving them
        // through UseStaticFiles middleware — which runs ahead of routing and
        // authorization — is what keeps this true.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/_content/Tamp.Findings.Web/app.css");

        Assert.NotEqual(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Vendored_fonts_are_served_from_this_origin()
    {
        // tamp.findings is self-hosted and generates compliance evidence. A
        // <link> to fonts.googleapis.com would report every page view to a
        // third party and would fail outright in an air-gapped deployment, so
        // the fonts are vendored. If this 404s, someone has removed them and
        // the stylesheet is silently falling back to system-ui.
        var client = _factory.CreateClient();

        var resp = await client.GetAsync("/_content/Tamp.Findings.Web/fonts/Barlow-400-latin.woff2");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var bytes = await resp.Content.ReadAsByteArrayAsync();
        Assert.True(bytes.Length > 1000, $"font served {bytes.Length} bytes");
    }

    [Fact]
    public async Task No_stylesheet_references_an_external_font_cdn()
    {
        // Guards the decision rather than the file: an @import back to Google
        // Fonts would quietly undo the vendoring.
        var client = _factory.CreateClient();

        foreach (var sheet in new[] { "app.css", "tokens.css", "fonts.css" })
        {
            var css = await client.GetStringAsync($"/_content/Tamp.Findings.Web/{sheet}");

            // Comments are stripped first. fonts.css explains in prose WHY the
            // fonts are vendored and names the host it is avoiding; matching on
            // the bare string would fail on the documentation of the very
            // decision this test protects.
            var code = System.Text.RegularExpressions.Regex.Replace(css, @"/\*.*?\*/", "", System.Text.RegularExpressions.RegexOptions.Singleline);

            Assert.DoesNotContain("fonts.googleapis.com", code, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("fonts.gstatic.com", code, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task The_token_stylesheet_carries_no_global_min_width()
    {
        // ADR 0003: the page reflows and the body never scrolls horizontally
        // at 320px. A global min-width would reintroduce the 1180px floor the
        // ADR removed, and it is a one-line change to make by accident.
        var client = _factory.CreateClient();

        var css = await client.GetStringAsync("/_content/Tamp.Findings.Web/tokens.css");

        Assert.DoesNotContain("min-width:", css, StringComparison.OrdinalIgnoreCase);
    }
}
