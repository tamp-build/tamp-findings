using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// Lets the Blazor framework assets through the authorization gate.
///
/// <para><b>The problem.</b> The host applies a FallbackPolicy of
/// RequireAuthenticatedUser to every endpoint that does not opt out. That is
/// right for the API — it closes the gate on every query route without tagging
/// each one — and wrong for <c>/_framework/blazor.web.js</c>: without the
/// script no circuit boots, so an anonymous visitor cannot render the sign-in
/// page that would let them stop being anonymous. Nothing interactive works
/// before login, which is a closed loop.</para>
///
/// <para><b>Two approaches that do NOT work</b>, recorded so nobody repeats
/// them:</para>
/// <list type="number">
///   <item><c>.AllowAnonymous()</c> on the <c>MapRazorComponents</c> builder.
///   It covers the page and RCL asset endpoints but not the framework script,
///   which is registered separately. Verified: still 401.</item>
///   <item><c>app.UseWhen(path, b =&gt; b.UseAuthorization())</c>. The branch
///   is built before an endpoint has been selected, so AuthorizationMiddleware
///   sees a null endpoint, cannot read AllowAnonymous metadata, and applies
///   the fallback policy to EVERYTHING — every static asset and even /health
///   started returning 401. Adding an explicit <c>UseRouting</c> ahead of it
///   made it worse.</item>
/// </list>
///
/// <para><b>What works.</b> This handler. It is the documented extension point
/// for the last step of the authorization middleware, and crucially it runs
/// AFTER endpoint selection, so the pipeline is otherwise untouched — every
/// other route keeps exactly the authorization it had.</para>
///
/// <para>The path check is deliberately narrow and must stay that way.
/// <c>/_framework</c> is framework-owned: the Blazor script and its
/// boot resources, not application data. Widening this predicate is how an
/// authorization model quietly stops applying, so there are tests asserting
/// that <c>/auth/me</c> and the project screens are still gated.</para>
/// </summary>
public sealed class FrameworkAssetAuthorizationHandler : IAuthorizationMiddlewareResultHandler
{
    private static readonly AuthorizationMiddlewareResultHandler Default = new();

    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (IsStaticFrameworkAsset(context.Request.Path))
        {
            // Serve it regardless of the policy outcome. These are static
            // framework files — the same bytes for every visitor, carrying no
            // tenant data — and withholding them only prevents someone from
            // reaching the sign-in page.
            return next(context);
        }

        return Default.HandleAsync(next, context, policy, authorizeResult);
    }

    /// <summary>
    /// The two framework-owned prefixes, and only those.
    ///
    /// <c>/_framework</c> is the Blazor script and its boot resources;
    /// <c>/_content</c> is Razor Class Library static files — the stylesheet,
    /// the vendored fonts, the icons. Both are the same bytes for every
    /// visitor and carry no tenant data, and the sign-in page needs all of
    /// them before anyone has a session.
    ///
    /// Nothing else belongs here. Every application route, including every
    /// screen and every API endpoint, keeps exactly the authorization it had.
    /// </summary>
    private static bool IsStaticFrameworkAsset(PathString path) =>
        path.StartsWithSegments("/_framework", StringComparison.OrdinalIgnoreCase)
        || path.StartsWithSegments("/_content", StringComparison.OrdinalIgnoreCase);
}
