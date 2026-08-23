using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Authentication;

/// <summary>
/// Works out who is authoring a suppression, and where.
///
/// Replaces the <c>X-Author-Role</c> header trust that ADR 0001 flagged and
/// TFND-19 tracked: the endpoint read a role out of a header and believed it,
/// so anyone who could reach it could claim any role by typing it.
/// </summary>
public static class SuppressionAuthorization
{
    /// <summary>
    /// Legacy header path, for the POC ingest tests that predate cookie auth.
    ///
    /// Refused unless BOTH are true: the env var is set, AND no interactive
    /// authentication is configured on the instance. The second condition is
    /// the important one — an operator who sets this on a deployment that has
    /// GitHub OAuth wired up does not get a bypass, they get a 400. A dev
    /// escape hatch that also works in production is not an escape hatch, it is
    /// the vulnerability with a flag in front of it.
    /// </summary>
    public const string LegacyHeaderEnvVar = "TAMP_FINDINGS_ALLOW_HEADER_AUTHOR";

    public readonly record struct ActingUser(
        Principal? Principal,
        User? User,
        ProjectRole RecordedRole,
        ScopeTarget Target,
        string? Error);

    public static async Task<ActingUser> ResolveActorAsync(
        HttpContext http,
        PrincipalResolver principals,
        FindingsDbContext db,
        SuppressionCreateRequest req,
        CancellationToken ct)
    {
        var target = await TargetForAsync(db, req, ct);

        // 1. The supported path: an authenticated cookie.
        var userId = UserIdFrom(http.User);
        if (userId is { } id)
        {
            var principal = await principals.ResolveAsync(id, target, ct);
            if (principal is null) return new(null, null, default, target, null);

            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
            if (user is null) return new(null, null, default, target, null);

            return new(principal, user, RecordedRoleFor(principal), target, null);
        }

        // 2. The legacy path, deliberately hard to reach.
        if (!LegacyHeaderAllowed(http))
        {
            return new(null, null, default, target, null);
        }

        var login = http.Request.Headers["X-Author-User"].ToString();
        var roleStr = http.Request.Headers["X-Author-Role"].ToString();
        if (string.IsNullOrWhiteSpace(login)) return new(null, null, default, target, "X-Author-User header is required");
        if (!Enum.TryParse<ProjectRole>(roleStr, ignoreCase: true, out var claimed))
        {
            return new(null, null, default, target,
                $"X-Author-Role must be one of: {string.Join(", ", Enum.GetNames<ProjectRole>())} (was '{roleStr}')");
        }

        var legacyUser = await db.Users.FirstOrDefaultAsync(u => u.Login == login, ct);
        if (legacyUser is null)
        {
            legacyUser = new User { Login = login, DisplayName = login, IsApproved = true };
            db.Users.Add(legacyUser);
            await db.SaveChangesAsync(ct);
        }

        // Even here the CAPABILITY still comes from the evaluator — the header
        // supplies a claimed role, not a decision. That is what stopped
        // TFND-69's new Auditor role from silently becoming a valid author.
        var legacyPrincipal = Principal.For(legacyUser.Id, legacyUser.Login, legacyUser.IsAdmin, [claimed]);
        return new(legacyPrincipal, legacyUser, claimed, target, null);
    }

    private static bool LegacyHeaderAllowed(HttpContext http)
    {
        if (Environment.GetEnvironmentVariable(LegacyHeaderEnvVar) != "true") return false;

        // If any interactive sign-in is configured, this instance is not a POC
        // and the bypass stays shut regardless of the env var.
        var config = http.RequestServices.GetRequiredService<IConfiguration>();
        var hasOAuth = !string.IsNullOrWhiteSpace(config["GitHub:ClientId"])
                       || !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("GITHUB_CLIENT_ID"));
        return !hasOAuth;
    }

    /// <summary>
    /// The tamp user id on the authenticated cookie, or null.
    ///
    /// Public so the withdraw path can use the same one rather than parsing the
    /// claim a second way — two readings of "who is this" is how they end up
    /// disagreeing.
    /// </summary>
    public static Guid? UserIdFrom(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true) return null;
        var raw = principal.FindFirstValue(AuthExtensions.TampUserIdClaim);
        return Guid.TryParse(raw, out var id) ? id : null;
    }

    /// <summary>
    /// Which role to stamp on the record.
    ///
    /// Suppression.CreatedByRole is an audit field — it records the authority
    /// the author acted under. With additive roles a person may hold several,
    /// so the most senior one that could have authorised the act is recorded.
    /// </summary>
    private static ProjectRole RecordedRoleFor(Principal principal) =>
        principal.Actors.Contains(Actor.InfoSecOfficer) ? ProjectRole.InfoSecOfficer
        : principal.Actors.Contains(Actor.Architect) ? ProjectRole.Architect
        : principal.Actors.Contains(Actor.LeadDev) ? ProjectRole.LeadDev
        // Admin is not a ProjectRole. An admin authoring a suppression is
        // recorded as the closest project authority; the audit log (TFND-73)
        // carries the fact that they were acting as an instance admin.
        : ProjectRole.Architect;

    /// <summary>
    /// Where the suppression applies, for scope resolution.
    ///
    /// RuleEverywhere resolves to INSTANCE scope, which no ProjectRoleAssignment
    /// can reach — so only an instance admin may suppress a rule across the
    /// whole deployment. That is a tightening over the previous behaviour and a
    /// deliberate one: a deployment-wide suppression affects every tenant, and
    /// it should not be reachable from a grant on one project.
    /// </summary>
    private static async Task<ScopeTarget> TargetForAsync(
        FindingsDbContext db, SuppressionCreateRequest req, CancellationToken ct)
    {
        // Switch on the SCOPE, not on whichever fields happen to be populated
        // (TFND-132).
        //
        // The previous version took the first id it found — ComponentId, then
        // FindingId — regardless of scope. That is an escalation, because
        // SuppressionMatcher does not read those fields for the unanchored
        // scopes: a Lead Dev could send RuleEverywhere WITH the component id
        // they hold, pass the check at that component, and store a row that
        // silences the rule for every client on the instance. The field bought
        // the authorization and then constrained nothing.
        //
        // So each scope resolves to the tier its own MATCHING predicate is
        // bounded by, and nothing else on the request can move it.
        return req.Scope switch
        {
            // Anchored to the finding, which is anchored to a component. A
            // ComponentId sent alongside is ignored — otherwise the same trick
            // works one tier down.
            SuppressionScope.SingleFinding =>
                await TargetForFindingAsync(db, req.FindingId, ct),

            // Anchored to the named component, and only that one.
            SuppressionScope.RuleOnComponent =>
                await TargetForComponentAsync(db, req.ComponentId, ct) ?? ScopeTarget.Instance,

            // Bounded by the PROJECT the author named, and by nothing else on
            // the request (TFND-132). ProjectId is what the row is stored with
            // and what the matcher checks, so it is the only field that may
            // decide the authorization — a ComponentId sent alongside buys
            // nothing, which is the escalation this closes.
            //
            // Absent, it is INSTANCE, which no ProjectRoleAssignment reaches.
            // A rule-scoped suppression with no project would silence that rule
            // everywhere, and only an instance admin should be able to ask for
            // that. Validation refuses it before this point; this is the
            // second door on the same room.
            SuppressionScope.RuleOnFile or SuppressionScope.RuleEverywhere =>
                await TargetForProjectAsync(db, req.ProjectId, ct),

            // An unknown scope authorizes at the instance rather than falling
            // through to something permissive. A scope added later that nobody
            // mapped here should be hard to author, not easy.
            _ => ScopeTarget.Instance,
        };
    }

    private static async Task<ScopeTarget> TargetForProjectAsync(
        FindingsDbContext db, Guid? projectId, CancellationToken ct)
    {
        if (projectId is not { } id) return ScopeTarget.Instance;

        var row = await db.Projects.AsNoTracking()
            .Where(p => p.Id == id)
            .Select(p => new { p.Id, p.ClientId })
            .FirstOrDefaultAsync(ct);

        return row is null ? ScopeTarget.Instance : ScopeTarget.Project(row.ClientId, row.Id);
    }

    private static async Task<ScopeTarget> TargetForFindingAsync(
        FindingsDbContext db, Guid? findingId, CancellationToken ct)
    {
        if (findingId is not { } id) return ScopeTarget.Instance;

        var componentId = await (
            from f in db.Findings.AsNoTracking()
            join cv in db.ComponentVersions.AsNoTracking() on f.ComponentVersionId equals cv.Id
            where f.Id == id
            select (Guid?)cv.ComponentId).FirstOrDefaultAsync(ct);

        return await TargetForComponentAsync(db, componentId, ct) ?? ScopeTarget.Instance;
    }

    private static async Task<ScopeTarget?> TargetForComponentAsync(
        FindingsDbContext db, Guid? componentId, CancellationToken ct)
    {
        if (componentId is null) return null;

        var row = await (
            from c in db.Components.AsNoTracking()
            join p in db.Projects.AsNoTracking() on c.ProjectId equals p.Id
            where c.Id == componentId
            select new { c.Id, p.ClientId, ProjectId = p.Id }).FirstOrDefaultAsync(ct);

        return row is null ? null : ScopeTarget.Component(row.ClientId, row.ProjectId, row.Id);
    }
}
