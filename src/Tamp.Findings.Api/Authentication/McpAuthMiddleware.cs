using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// The door the MCP endpoint is behind (TFND-12 / F11.2).
///
/// Middleware rather than an endpoint filter because <c>MapMcp</c> registers
/// its own routes — including the SSE stream and the POST that rides it — and a
/// filter would have to be attached to each of them, which is one route away
/// from a hole. Middleware on the path branch covers whatever the SDK maps,
/// today and after an upgrade.
///
/// Runs BEFORE the transport, so a bad token never reaches a tool and never
/// opens a stream. The identity it resolves is put on the scoped
/// <see cref="AgentContext"/>, which is the only thing the tools can read it
/// from.
/// </summary>
public sealed class McpAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<McpAuthMiddleware> _log;

    public McpAuthMiddleware(RequestDelegate next, ILogger<McpAuthMiddleware> log)
    {
        _next = next;
        _log = log;
    }

    public async Task InvokeAsync(
        HttpContext context, McpTokenService tokens, AgentContext agent,
        FindingsDbContext db, TimeProvider clock)
    {
        // The instance-level switch, checked per request rather than at startup.
        // An operator turning MCP off is usually doing it because something is
        // wrong right now, and "restart the host for it to take effect" is not
        // an answer at that moment.
        bool? enabled;
        try
        {
            enabled = await db.InstanceSettings.AsNoTracking()
                .Where(s => s.Id == InstanceSettings.SingletonId)
                .Select(s => (bool?)s.McpEnabled)
                .SingleOrDefaultAsync(context.RequestAborted);
        }
        catch (Exception ex)
        {
            // Fail CLOSED. An endpoint whose enablement cannot be determined
            // must not serve — the alternative is that a database outage is the
            // one condition under which an agent surface opens itself.
            _log.LogError(ex, "Could not read whether the MCP endpoint is enabled; refusing the request.");
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        if (enabled is not true)
        {
            // 404, not 403. An instance that does not serve agents should not
            // advertise that it could.
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var header = context.Request.Headers[HeaderNames.Authorization].ToString();
        var wire = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? header["Bearer ".Length..].Trim()
            : null;

        var identity = await tokens.ResolveAsync(wire, clock.GetUtcNow(), context.RequestAborted);

        if (identity is null)
        {
            // WWW-Authenticate so a client knows what to present. The MCP
            // clients that support authorization look for it, and without it a
            // 401 reads as "broken server" rather than "sign in".
            context.Response.Headers.WWWAuthenticate = "Bearer realm=\"tamp.findings\"";
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        agent.Attach(identity);

        // Logged at information: an agent reading a client's findings is a thing
        // an operator should be able to see happening, and the audit trail is
        // for writes.
        _log.LogInformation(
            "MCP request from {Agent} (token {TokenId}) scoped to client {Client}, project {Project}, "
            + "component {Component}.",
            identity.Name, identity.TokenId,
            identity.Scope.ClientId, identity.Scope.ProjectId, identity.Scope.ComponentId);

        await _next(context);
    }
}
