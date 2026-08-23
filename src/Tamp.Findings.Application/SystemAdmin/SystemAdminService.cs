using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.SystemAdmin;

/// <summary>
/// The instance-level panels (TFND-110 … TFND-114).
///
/// Everything here sits OUTSIDE any client or project scope, so every check is
/// against <see cref="ScopeTarget.Instance"/> — where only the instance admin
/// flag grants anything, because every ProjectRoleAssignment is scoped to at
/// least a client.
/// </summary>
public sealed class SystemAdminService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public SystemAdminService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    // ---- Users & RBAC (TFND-110) ------------------------------------------

    public async Task<IReadOnlyList<UserRow>> UsersAsync(CancellationToken ct = default)
    {
        var users = await _db.Users.AsNoTracking()
            .Select(u => new
            {
                u.Id, u.Login, u.DisplayName, u.Email, u.IsApproved, u.IsAdmin,
                u.CreatedAt, u.LastLoginAt,
            })
            .ToArrayAsync(ct);

        var assignments = await _db.ProjectRoleAssignments.AsNoTracking()
            .Select(a => new { a.UserId, a.Role, a.SodConflict })
            .ToArrayAsync(ct);

        return users
            .Select(u =>
            {
                var mine = assignments.Where(a => a.UserId == u.Id).ToArray();
                return new UserRow(
                    u.Id, u.Login, u.DisplayName, u.Email, u.IsApproved, u.IsAdmin,
                    u.CreatedAt, u.LastLoginAt,
                    mine.Length,
                    // A conflict recorded at GRANT TIME, not recomputed. The
                    // point is to show what the granter was told and accepted,
                    // not what today's rules would say.
                    mine.Any(a => a.SodConflict is not null));
            })
            // Pending approvals first: a user waiting for access is the only
            // row on this screen that someone is actively blocked by.
            .OrderBy(u => u.IsApproved)
            .ThenByDescending(u => u.LastLoginAt ?? u.CreatedAt)
            .ToArray();
    }

    public async Task<IReadOnlyList<AssignmentRow>> AssignmentsAsync(
        Guid userId, CancellationToken ct = default)
    {
        var assignments = await _db.ProjectRoleAssignments.AsNoTracking()
            .Where(a => a.UserId == userId)
            .ToArrayAsync(ct);

        var clientIds = assignments.Where(a => a.ClientId is not null).Select(a => a.ClientId!.Value).ToArray();
        var projectIds = assignments.Where(a => a.ProjectId is not null).Select(a => a.ProjectId!.Value).ToArray();

        var clients = await _db.Clients.AsNoTracking()
            .Where(c => clientIds.Contains(c.Id))
            .Select(c => new { c.Id, c.Name })
            .ToArrayAsync(ct);
        var projects = await _db.Projects.AsNoTracking()
            .Where(p => projectIds.Contains(p.Id))
            .Select(p => new { p.Id, p.Name })
            .ToArrayAsync(ct);

        return assignments
            .Select(a => new AssignmentRow(
                a.Id, a.Role,
                a.ComponentId is not null ? "Component"
                    : a.ProjectId is not null ? "Project"
                    : a.ClientId is not null ? "Client" : "Instance",
                a.ProjectId is { } pid ? projects.FirstOrDefault(p => p.Id == pid)?.Name ?? "(removed)"
                    : a.ClientId is { } cid ? clients.FirstOrDefault(c => c.Id == cid)?.Name ?? "(removed)"
                    : "—",
                a.CreatedAt,
                a.SodConflict))
            // Narrowest first, because that is the one that wins: scope
            // resolution takes the narrowest tier with ANY assignment and
            // ignores the wider ones entirely.
            .OrderByDescending(a => a.Tier)
            .ThenBy(a => a.ScopeName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Approve a user who has signed in but has no access yet.
    ///
    /// Approval is separate from role assignment on purpose: an approved user
    /// with no roles is a VIEWER, and that is a real state — read access is
    /// often exactly what someone should have.
    /// </summary>
    public async Task<Result<bool>> ApproveAsync(
        Principal actor, Guid userId, bool approved, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var user = await _db.Users.SingleOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null) return Result<bool>.Invalid("That user no longer exists.");
        if (user.IsApproved == approved) return Result<bool>.Ok(false);

        user.IsApproved = approved;

        _audit.Record(actor, approved ? "user.approved" : "user.suspended", AuditClass.Access,
            ScopeTarget.Instance,
            subjectId: user.Id, subjectKind: nameof(User), detail: user.Login);

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Grant or revoke the instance admin flag.
    ///
    /// Refuses to remove the LAST admin. An instance with nobody who can grant
    /// roles needs database access to recover, and the person who did it is
    /// usually the person who then cannot get back in.
    /// </summary>
    public async Task<Result<bool>> SetAdminAsync(
        Principal actor, Guid userId, bool isAdmin, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var user = await _db.Users.SingleOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null) return Result<bool>.Invalid("That user no longer exists.");
        if (user.IsAdmin == isAdmin) return Result<bool>.Ok(false);

        if (!isAdmin)
        {
            var others = await _db.Users.CountAsync(u => u.IsAdmin && u.Id != userId, ct);
            if (others == 0)
                return Result<bool>.Invalid(
                    "This is the only instance administrator. Removing the flag would leave nobody "
                    + "able to grant roles, and recovering from that needs database access.");
        }

        user.IsAdmin = isAdmin;

        _audit.Record(actor, isAdmin ? "user.admin_granted" : "user.admin_revoked", AuditClass.Access,
            ScopeTarget.Instance,
            subjectId: user.Id, subjectKind: nameof(User), detail: user.Login);

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// Grant a role at a scope.
    ///
    /// Any separation-of-duties conflict the grant introduces is recorded ON
    /// THE ASSIGNMENT, so an assessor can see it was a deliberate choice rather
    /// than an oversight. When the instance switch is on, the advisory becomes
    /// a refusal instead.
    /// </summary>
    public async Task<Result<Guid>> GrantAsync(
        Principal actor, Guid userId, ProjectRole role, ScopeTarget scope,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        if (scope.Depth == 0)
            return Result<Guid>.Invalid(
                "A role has to be granted at a client, project or component. Instance-wide access is "
                + "the admin flag, not a role.");

        var user = await _db.Users.SingleOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null) return Result<Guid>.Invalid("That user no longer exists.");

        var duplicate = await _db.ProjectRoleAssignments.AnyAsync(
            a => a.UserId == userId && a.Role == role
              && a.ClientId == scope.ClientId
              && a.ProjectId == scope.ProjectId
              && a.ComponentId == scope.ComponentId, ct);
        if (duplicate) return Result<Guid>.Invalid("That role is already granted at this scope.");

        // Existing roles at the SAME tier, because that is what scope
        // resolution unions. A role held at a wider tier is ignored entirely
        // once anything is granted at a narrower one, so it cannot conflict.
        var existing = await _db.ProjectRoleAssignments.AsNoTracking()
            .Where(a => a.UserId == userId
                     && a.ClientId == scope.ClientId
                     && a.ProjectId == scope.ProjectId
                     && a.ComponentId == scope.ComponentId)
            .Select(a => a.Role)
            .ToArrayAsync(ct);

        var conflicts = SeparationOfDuties.WouldIntroduce(existing, [role]);

        if (conflicts.Count > 0 && await EnforcesSodAsync(ct))
            return Result<Guid>.Invalid(
                $"Separation of duties is enforced on this instance: {string.Join("; ", conflicts)}");

        var assignment = new ProjectRoleAssignment
        {
            UserId = userId,
            Role = role,
            ClientId = scope.ClientId,
            ProjectId = scope.ProjectId,
            ComponentId = scope.ComponentId,
            GrantedByUserId = actor.UserId,
            SodConflict = conflicts.Count == 0 ? null : string.Join("; ", conflicts),
        };
        _db.ProjectRoleAssignments.Add(assignment);

        _audit.Record(actor, AuditActions.RoleGranted, AuditClass.Access, scope,
            subjectId: user.Id, subjectKind: nameof(User),
            detail: $"{user.Login} granted {role}"
                  + (assignment.SodConflict is null ? "" : $" — SoD: {assignment.SodConflict}"));

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(assignment.Id);
    }

    public async Task<Result<bool>> RevokeAsync(
        Principal actor, Guid assignmentId, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var assignment = await _db.ProjectRoleAssignments
            .SingleOrDefaultAsync(a => a.Id == assignmentId, ct);
        if (assignment is null) return Result<bool>.Ok(false);

        var login = await _db.Users.AsNoTracking()
            .Where(u => u.Id == assignment.UserId)
            .Select(u => u.Login)
            .SingleOrDefaultAsync(ct) ?? "(removed user)";

        _db.ProjectRoleAssignments.Remove(assignment);

        _audit.Record(actor, AuditActions.RoleRevoked, AuditClass.Access,
            new ScopeTarget(assignment.ClientId, assignment.ProjectId, assignment.ComponentId),
            subjectId: assignment.UserId, subjectKind: nameof(User),
            detail: $"{login} lost {assignment.Role}");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    // ---- Scanners & ingest (TFND-112) -------------------------------------

    /// <summary>
    /// Every scanner this build understands, with whether the instance expects
    /// it and when it was last seen.
    ///
    /// The EXPECTED flag is what the brief is really asking for: "a
    /// registered-but-never-seen scanner is what makes 'no scan'
    /// distinguishable from 'clean'". Without it, a scanner that silently
    /// stopped reporting looks exactly like one that was never in the pipeline.
    /// </summary>
    public async Task<IReadOnlyList<ScannerRow>> ScannersAsync(
        DateTimeOffset asOf, CancellationToken ct = default)
    {
        var settings = await SettingsAsync(ct);
        var expected = settings.ExpectedScanners.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var seen = await _db.ScanRunReceipts.AsNoTracking()
            .GroupBy(r => r.Scanner)
            .Select(g => new
            {
                Scanner = g.Key,
                Last = g.Max(r => r.CompletedAt),
                Runs = g.Count(),
            })
            .ToArrayAsync(ct);

        return Enum.GetValues<ScannerKind>()
            .Select(kind =>
            {
                var record = seen.FirstOrDefault(s => s.Scanner == kind);
                var isExpected = expected.Contains(kind.ToString());
                return new ScannerRow(
                    kind,
                    ClassOf(kind),
                    isExpected,
                    record?.Last,
                    record?.Runs ?? 0,
                    // The loud row: this deployment says it should be getting
                    // this scanner and has not, either ever or lately.
                    isExpected && (record is null || (asOf - record.Last).TotalDays > 30));
            })
            .OrderByDescending(s => s.Silent)
            .ThenByDescending(s => s.Expected)
            .ThenBy(s => s.Class, StringComparer.Ordinal)
            .ThenBy(s => s.Kind.ToString(), StringComparer.Ordinal)
            .ToArray();
    }

    public async Task<Result<int>> SetExpectedScannersAsync(
        Principal actor, IReadOnlyList<ScannerKind> expected, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<int>.Denied(decision.Reason!);

        var settings = await MutableSettingsAsync(ct);
        var before = settings.ExpectedScanners.ToHashSet(StringComparer.Ordinal);
        var after = expected.Select(s => s.ToString()).ToHashSet(StringComparer.Ordinal);

        if (before.SetEquals(after)) return Result<int>.Ok(0);

        var added = after.Except(before).ToArray();
        var removed = before.Except(after).ToArray();

        settings.ExpectedScanners = after.OrderBy(s => s, StringComparer.Ordinal).ToList();
        settings.UpdatedAt = DateTimeOffset.UtcNow;

        // Removing an expectation is the one that matters: it stops this
        // instance noticing that a scanner went quiet.
        _audit.Record(actor, "scanners.expected_changed",
            removed.Length > 0 ? AuditClass.Risk : AuditClass.Other,
            ScopeTarget.Instance,
            subjectKind: nameof(InstanceSettings),
            detail: $"expected +[{string.Join(", ", added)}] -[{string.Join(", ", removed)}]");

        await _db.SaveChangesAsync(ct);
        return Result<int>.Ok(added.Length + removed.Length);
    }

    // ---- Instance settings (TFND-113) -------------------------------------

    public async Task<InstanceSettings> SettingsAsync(CancellationToken ct = default) =>
        await _db.InstanceSettings.AsNoTracking()
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId, ct)
        ?? new InstanceSettings();

    public async Task<Result<bool>> SaveSettingsAsync(
        Principal actor, InstanceSettings proposed, CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.AssignRoles);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        if (proposed.InstanceUrl is { Length: > 0 } url
            && !Uri.TryCreate(url, UriKind.Absolute, out _))
            return Result<bool>.Invalid("The instance URL needs to be a full http or https address.");

        if (proposed.SessionLifetimeHours < 1)
            return Result<bool>.Invalid("A session has to last at least an hour.");

        // TFND-23. Enabling checks without credentials would mean an operator
        // watching for check runs that can never appear — and a check that
        // never appears is indistinguishable from one that passed.
        if (proposed.GitHubChecksEnabled
            && (string.IsNullOrWhiteSpace(proposed.GitHubAppId)
                || string.IsNullOrWhiteSpace(proposed.GitHubAppPrivateKeyProtected)))
        {
            return Result<bool>.Invalid(
                "GitHub checks need an App id and a private key before they can be enabled.");
        }

        if (proposed.FindingRetentionDays is < 1 || proposed.BuildRetentionDays is < 1)
            return Result<bool>.Invalid("Retention is measured in whole days, or left blank to keep forever.");

        var settings = await MutableSettingsAsync(ct);
        var sodChanged = settings.EnforceSeparationOfDuties != proposed.EnforceSeparationOfDuties;
        // TFND-12. Opening or closing the agent endpoint changes what can read
        // this instance without a browser, which is an access decision however
        // it is worded on the screen.
        var mcpChanged = settings.McpEnabled != proposed.McpEnabled;

        settings.InstanceUrl = Blank(proposed.InstanceUrl);
        settings.FindingRetentionDays = proposed.FindingRetentionDays;
        settings.BuildRetentionDays = proposed.BuildRetentionDays;
        settings.SessionLifetimeHours = proposed.SessionLifetimeHours;
        settings.SmtpHost = Blank(proposed.SmtpHost);
        settings.SmtpPort = proposed.SmtpPort;
        settings.SmtpFrom = Blank(proposed.SmtpFrom);
        settings.EnforceSeparationOfDuties = proposed.EnforceSeparationOfDuties;
        settings.GitHubAppId = Blank(proposed.GitHubAppId);
        settings.GitHubCheckName = Blank(proposed.GitHubCheckName) ?? "tamp.findings";
        settings.GitHubChecksEnabled = proposed.GitHubChecksEnabled;
        settings.McpEnabled = proposed.McpEnabled;
        // A blank key means "keep what is stored", the same rule the identity
        // provider registry follows: renaming a check should not require
        // re-pasting a private key the operator may no longer have.
        if (!string.IsNullOrWhiteSpace(proposed.GitHubAppPrivateKeyProtected))
            settings.GitHubAppPrivateKeyProtected = proposed.GitHubAppPrivateKeyProtected;

        settings.UpdatedAt = DateTimeOffset.UtcNow;

        // Turning SoD enforcement on or off changes who may hold which roles
        // across every tenant. That is an access decision, not housekeeping.
        _audit.Record(actor, "instance.settings_changed",
            sodChanged || mcpChanged ? AuditClass.Access : AuditClass.Other,
            ScopeTarget.Instance,
            subjectKind: nameof(InstanceSettings),
            detail: Describe(proposed, sodChanged, mcpChanged));

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }

    /// <summary>
    /// What the audit entry says happened.
    ///
    /// The access-class changes are NAMED. "Instance settings updated" against
    /// a change that opened an agent endpoint is technically true and useless
    /// to the person reading the log after an incident.
    /// </summary>
    private static string Describe(InstanceSettings proposed, bool sodChanged, bool mcpChanged)
    {
        var parts = new List<string>();

        if (sodChanged)
            parts.Add($"separation of duties {(proposed.EnforceSeparationOfDuties ? "ENFORCED" : "advisory")}");

        if (mcpChanged)
            parts.Add($"MCP endpoint {(proposed.McpEnabled ? "OPENED" : "CLOSED")}");

        return parts.Count == 0 ? "instance settings updated" : string.Join("; ", parts);
    }

    // ---- Audit log (TFND-114) ---------------------------------------------

    /// <summary>
    /// The audit log, newest first.
    ///
    /// Filtering by CLASS is first-class rather than a search box because "risk
    /// acceptance, role grants and key changes are what an assessor reads
    /// first", and making them findable by typing the right word would mean
    /// knowing the word.
    /// </summary>
    public async Task<IReadOnlyList<AuditRow>> AuditAsync(
        AuditClass? @class = null, int take = 200, CancellationToken ct = default)
    {
        var query = _db.AuditEntries.AsNoTracking();
        if (@class is { } wanted) query = query.Where(a => a.Class == wanted);

        var entries = await query
            .OrderByDescending(a => a.At)
            .Take(Math.Clamp(take, 1, 1000))
            .Select(a => new
            {
                a.Id, a.At, a.ActorLogin, a.ActorRole, a.ActorWasAdmin,
                a.Action, a.Class, a.ClientId, a.ProjectId, a.SubjectKind, a.Detail,
            })
            .ToArrayAsync(ct);

        var clientIds = entries.Where(e => e.ClientId is not null).Select(e => e.ClientId!.Value).Distinct().ToArray();
        var projectIds = entries.Where(e => e.ProjectId is not null).Select(e => e.ProjectId!.Value).Distinct().ToArray();

        var clients = await _db.Clients.AsNoTracking()
            .Where(c => clientIds.Contains(c.Id)).Select(c => new { c.Id, c.Name }).ToArrayAsync(ct);
        var projects = await _db.Projects.AsNoTracking()
            .Where(p => projectIds.Contains(p.Id)).Select(p => new { p.Id, p.Name }).ToArrayAsync(ct);

        return entries
            .Select(e => new AuditRow(
                e.Id, e.At, e.ActorLogin, e.ActorRole, e.ActorWasAdmin, e.Action, e.Class,
                e.ProjectId is { } pid
                    ? projects.FirstOrDefault(p => p.Id == pid)?.Name ?? "(removed project)"
                    : e.ClientId is { } cid
                        ? clients.FirstOrDefault(c => c.Id == cid)?.Name ?? "(removed client)"
                        : "instance",
                e.SubjectKind,
                e.Detail))
            .ToArray();
    }

    // ---- Shared ------------------------------------------------------------

    private async Task<InstanceSettings> MutableSettingsAsync(CancellationToken ct)
    {
        var settings = await _db.InstanceSettings
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId, ct);

        if (settings is null)
        {
            settings = new InstanceSettings();
            _db.InstanceSettings.Add(settings);
        }

        return settings;
    }

    private async Task<bool> EnforcesSodAsync(CancellationToken ct) =>
        await _db.InstanceSettings.AsNoTracking()
            .Where(s => s.Id == InstanceSettings.SingletonId)
            .Select(s => s.EnforceSeparationOfDuties)
            .SingleOrDefaultAsync(ct);

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>
    /// What kind of evidence a scanner produces. Drives the grouping in the
    /// registry, and mirrors the sets the gate evaluator keys off.
    /// </summary>
    public static string ClassOf(ScannerKind kind) =>
        ScannerKinds.Sast.Contains(kind) ? "SAST"
        : ScannerKinds.Dast.Contains(kind) ? "DAST"
        : kind is ScannerKind.Syft or ScannerKind.OsvScanner or ScannerKind.Cosign ? "Supply chain"
        : kind is ScannerKind.TruffleHog ? "Secrets"
        : kind is ScannerKind.Trivy ? "Container / IaC"
        : "Other";
}

public sealed record UserRow(
    Guid Id, string Login, string DisplayName, string? Email,
    bool IsApproved, bool IsAdmin,
    DateTimeOffset CreatedAt, DateTimeOffset? LastLoginAt,
    int AssignmentCount, bool HasSodConflict);

public sealed record AssignmentRow(
    Guid Id, ProjectRole Role, string Tier, string ScopeName,
    DateTimeOffset CreatedAt, string? SodConflict);

public sealed record ScannerRow(
    ScannerKind Kind, string Class, bool Expected,
    DateTimeOffset? LastReceived, int Runs,
    /// <summary>
    /// Expected here and either never seen or not seen in a month. The row that
    /// makes "no scan" distinguishable from "clean".
    /// </summary>
    bool Silent);

public sealed record AuditRow(
    Guid Id, DateTimeOffset At, string ActorLogin, ProjectRole? ActorRole, bool ActorWasAdmin,
    string Action, AuditClass Class, string Scope, string? SubjectKind, string? Detail);
