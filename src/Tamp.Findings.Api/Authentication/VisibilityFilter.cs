using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// Refuses a query for an entity the caller may not see (TFND-133 / F2.3).
///
/// The query endpoints take ids straight off the query string — `clientId`,
/// `projectId`, `componentId`, `componentVersionId` — and until this existed
/// none of them checked whose ids they were. On a multi-client instance any
/// authenticated user could read every tenant's evidence by supplying the id.
///
/// A FILTER rather than a check in each endpoint, for the reason that decides
/// most of this codebase's shape: there are a dozen of these endpoints and
/// there will be more, and the thirteenth is the one that forgets. A filter on
/// the group covers whatever is added to it.
///
/// It answers the "you asked for a specific thing" case. Endpoints that
/// ENUMERATE without an id filter their own results, because there is no id
/// here to check — see the list endpoints.
/// </summary>
public sealed class VisibilityFilter : IEndpointFilter
{
    /// <summary>Where the resolved set is stashed for the endpoint to use.</summary>
    public const string ItemKey = "tamp.visibility";

    private readonly VisibilityScope _scope;
    private readonly FindingsDbContext _db;

    public VisibilityFilter(VisibilityScope scope, FindingsDbContext db)
    {
        _scope = scope;
        _db = db;
    }

    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var http = ctx.HttpContext;
        var ct = http.RequestAborted;

        VisibleSet visible;
        try
        {
            visible = await ResolveAsync(http, ct);
        }
        catch (Exception ex)
        {
            // Could not DETERMINE the boundary — distinct from determining that
            // the caller is outside it, and answered differently. 503 says "ask
            // again"; a 404 here would tell a caller their own project does not
            // exist because the database blinked.
            //
            // Failing closed either way: nothing is served.
            http.RequestServices
                .GetRequiredService<ILoggerFactory>()
                .CreateLogger<VisibilityFilter>()
                .LogError(ex, "Could not resolve the visibility boundary; refusing the request.");

            return Results.Json(
                new { error = "Cannot determine access at the moment." },
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        http.Items[ItemKey] = visible;

        // Sees nothing at all, and named something specific. Answerable without
        // touching the database, which also means it stays answerable when the
        // database is the thing that is unwell.
        if (visible.IsEmpty && NamesAnyId(http)) return NotFound;

        // Every id the request names has to be inside the boundary. Checked
        // narrowest-first only for readability — all of them must pass.
        if (Id(http, "componentVersionId") is { } versionId
            && !await VersionVisibleAsync(visible, versionId, ct))
        {
            return NotFound;
        }

        if (Id(http, "componentId") is { } componentId
            && !await ComponentVisibleAsync(visible, componentId, ct))
        {
            return NotFound;
        }

        if (Id(http, "projectId") is { } projectId
            && !await ProjectVisibleAsync(visible, projectId, ct))
        {
            return NotFound;
        }

        if (Id(http, "clientId") is { } clientId && !visible.CanSeeClient(clientId))
        {
            return NotFound;
        }

        return await next(ctx);
    }

    /// <summary>
    /// 404, never 403.
    ///
    /// A 403 confirms the thing exists, which on a multi-tenant instance tells
    /// one customer that another has a project by that id. Not found is both
    /// safer and true from where the caller stands.
    /// </summary>
    private static IResult NotFound { get; } = Results.NotFound();

    private static bool NamesAnyId(HttpContext http) =>
        Id(http, "clientId") is not null
        || Id(http, "projectId") is not null
        || Id(http, "componentId") is not null
        || Id(http, "componentVersionId") is not null;

    private async Task<VisibleSet> ResolveAsync(HttpContext http, CancellationToken ct)
    {
        if (http.User.Identity?.IsAuthenticated != true) return VisibleSet.Nothing;

        var raw = http.User.FindFirstValue(AuthExtensions.TampUserIdClaim);
        return Guid.TryParse(raw, out var userId)
            ? await _scope.ForAsync(userId, ct)
            : VisibleSet.Nothing;
    }

    /// <summary>
    /// The id under this name, from the route or the query string.
    ///
    /// Both, because the same id appears as a route value on some endpoints and
    /// as a query parameter on others, and a filter that only read one of them
    /// would be a filter with a hole in it shaped like the other.
    /// </summary>
    private static Guid? Id(HttpContext http, string name)
    {
        if (http.Request.RouteValues.TryGetValue(name, out var routed)
            && Guid.TryParse(routed?.ToString(), out var fromRoute))
        {
            return fromRoute;
        }

        return http.Request.Query.TryGetValue(name, out var queried)
               && Guid.TryParse(queried.ToString(), out var fromQuery)
            ? fromQuery
            : null;
    }

    private async Task<bool> ProjectVisibleAsync(VisibleSet visible, Guid projectId, CancellationToken ct)
    {
        if (visible.Unrestricted) return true;

        var clientId = await _db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => (Guid?)p.ClientId)
            .SingleOrDefaultAsync(ct);

        // A project that does not exist is not a visibility question. Let the
        // endpoint answer it, so "no such project" keeps coming from the place
        // that knows.
        if (clientId is not { } client) return true;

        if (visible.CanSeeProject(client, projectId)) return true;

        // Reachable as the container for a component the caller does hold.
        return await _db.Components.AsNoTracking()
            .AnyAsync(c => c.ProjectId == projectId && visible.Components.Contains(c.Id), ct);
    }

    private async Task<bool> ComponentVisibleAsync(VisibleSet visible, Guid componentId, CancellationToken ct)
    {
        if (visible.Unrestricted) return true;

        var row = await _db.Components.AsNoTracking()
            .Where(c => c.Id == componentId)
            .Select(c => new { c.Id, c.ProjectId, c.Project!.ClientId })
            .SingleOrDefaultAsync(ct);

        return row is null || visible.CanSeeComponent(row.ClientId, row.ProjectId, row.Id);
    }

    private async Task<bool> VersionVisibleAsync(VisibleSet visible, Guid versionId, CancellationToken ct)
    {
        if (visible.Unrestricted) return true;

        var row = await _db.ComponentVersions.AsNoTracking()
            .Where(v => v.Id == versionId)
            .Select(v => new { v.ComponentId, v.Component!.ProjectId, v.Component!.Project!.ClientId })
            .SingleOrDefaultAsync(ct);

        return row is null || visible.CanSeeComponent(row.ClientId, row.ProjectId, row.ComponentId);
    }

    /// <summary>
    /// The set the filter resolved, for an endpoint that has to filter its own
    /// results.
    ///
    /// Falls back to <see cref="VisibleSet.Nothing"/> rather than to
    /// "everything" when the filter did not run. An endpoint reached without
    /// the filter attached is a wiring mistake, and the safe reading of a
    /// wiring mistake on a confidentiality control is that the caller sees
    /// nothing.
    /// </summary>
    public static VisibleSet Current(HttpContext http) =>
        http.Items.TryGetValue(ItemKey, out var value) && value is VisibleSet set
            ? set
            : VisibleSet.Nothing;
}
