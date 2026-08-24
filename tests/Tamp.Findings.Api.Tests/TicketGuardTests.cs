using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Tamp.Findings.Api.Authentication;

namespace Tamp.Findings.Api.Tests;

// The last gate before an authentication cookie exists.
//
// A rejected setup token produced a signed-in session. ExternalSignIn refused
// correctly and wrote no user row, but OAuthHandler.CreateTicketAsync ignores
// the result set by OAuthCreatingTicketContext.Fail() — it builds the ticket
// from context.Principal regardless. So the raw OAuth identity became a cookie:
// authenticated, no name, no user behind it. Every [Authorize] page then let it
// through, correctly, because it genuinely was authenticated.
//
// The lesson these tests hold in place is that the check belongs on the
// PRINCIPAL, immediately before sign-in, not on an event whose Fail() may or
// may not be honoured by the handler that raised it.
public class TicketGuardTests
{
    [Fact]
    public async Task A_principal_with_no_user_id_claim_is_never_signed_in()
    {
        // Exactly the shape that got through: authenticated, but nothing from
        // ExternalSignIn. No user row stands behind it.
        var ctx = Context(new ClaimsPrincipal(new ClaimsIdentity("GitHub")));

        await AuthExtensions.HandleTicketReceived(ctx);

        Assert.True(ctx.Result?.Handled, "the ticket must be handled here, before SignInAsync runs");
        Assert.Equal(StatusCodes.Status302Found, ctx.Response.StatusCode);
        Assert.StartsWith("/signin", ctx.Response.Headers.Location.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task An_explicit_refusal_carries_its_reason_to_the_sign_in_page()
    {
        // The reason has to survive, or the reader is told "sign-in did not
        // complete" while holding a token they believe is correct — which is
        // how this cost an afternoon.
        var ctx = Context(Identified(), refused: "setup_token");

        await AuthExtensions.HandleTicketReceived(ctx);

        Assert.True(ctx.Result?.Handled);
        Assert.Equal("/signin?error=setup_token", ctx.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task A_refusal_outranks_a_principal_that_looks_identified()
    {
        // Belt and braces: if a handler ever both resolves a principal and
        // refuses, the refusal wins. Signing someone in because half the
        // pipeline approved is the failure being fixed.
        var ctx = Context(Identified(), refused: "not_approved");

        await AuthExtensions.HandleTicketReceived(ctx);

        Assert.True(ctx.Result?.Handled);
        Assert.Equal("/signin?error=not_approved", ctx.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task A_resolved_principal_passes_through_untouched()
    {
        // The guard must not break sign-in. Leaving Result null is what lets
        // HandleRequestAsync go on to call SignInAsync.
        var ctx = Context(Identified());

        await AuthExtensions.HandleTicketReceived(ctx);

        Assert.Null(ctx.Result);
        Assert.Equal(StatusCodes.Status200OK, ctx.Response.StatusCode);
    }

    /// <summary>A principal as ExternalSignIn builds it — carrying the user id.</summary>
    private static ClaimsPrincipal Identified() =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, "BrewingCoder"),
                new Claim(AuthExtensions.TampUserIdClaim, Guid.NewGuid().ToString()),
            ],
            "GitHub"));

    private static TicketReceivedContext Context(ClaimsPrincipal principal, string? refused = null)
    {
        var properties = new AuthenticationProperties();
        if (refused is not null) properties.Items["tamp.signin.refused"] = refused;

        var scheme = new AuthenticationScheme("GitHub", "GitHub", typeof(OAuthHandler<OAuthOptions>));
        var ticket = new AuthenticationTicket(principal, properties, scheme.Name);

        return new TicketReceivedContext(new DefaultHttpContext(), scheme, new OAuthOptions(), ticket);
    }
}
