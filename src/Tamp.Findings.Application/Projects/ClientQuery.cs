using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Projects;

/// <summary>
/// The client tier (TFND-127).
///
/// The Client &gt; Project &gt; Component tree is load-bearing — an ingest that
/// picks the wrong level lands findings somewhere nobody looks — and until this
/// existed the middle tier was a gap between the portfolio and a project rather
/// than a place you could stand.
///
/// It also owns the client-scoped defaults that a project inherits when it sets
/// none of its own, which is the other reason it needs a screen: an inherited
/// policy is invisible from the project it applies to.
/// </summary>
public sealed class ClientQuery
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public ClientQuery(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<ClientDetail?> LoadAsync(string clientSlug, CancellationToken ct = default)
    {
        // Case-insensitive, like every other slug resolution in the product: a
        // URL somebody typed should not 404 on capitalisation.
        var client = await _db.Clients.AsNoTracking()
            .SingleOrDefaultAsync(c => c.Name.ToLower() == clientSlug.ToLower(), ct);
        if (client is null) return null;

        var projects = await _db.Projects.AsNoTracking()
            .Where(p => p.ClientId == client.Id)
            .Select(p => new { p.Id, p.Name, p.RiskPolicyId })
            .ToArrayAsync(ct);

        var projectIds = projects.Select(p => p.Id).ToArray();

        var componentCounts = await _db.Components.AsNoTracking()
            .Where(c => projectIds.Contains(c.ProjectId))
            .GroupBy(c => c.ProjectId)
            .Select(g => new { ProjectId = g.Key, Count = g.Count() })
            .ToArrayAsync(ct);

        var lastBuilds = await _db.ComponentVersions.AsNoTracking()
            .Where(v => projectIds.Contains(v.Component!.ProjectId))
            .GroupBy(v => v.Component!.ProjectId)
            .Select(g => new { ProjectId = g.Key, Last = g.Max(v => v.CreatedAt) })
            .ToArrayAsync(ct);

        var policyIds = projects.Where(p => p.RiskPolicyId is not null)
            .Select(p => p.RiskPolicyId!.Value)
            .Append(client.RiskPolicyId ?? Guid.Empty)
            .Distinct()
            .ToArray();

        var policies = await _db.RiskPolicies.AsNoTracking()
            .Where(p => policyIds.Contains(p.Id))
            .Select(p => new { p.Id, p.Name })
            .ToArrayAsync(ct);

        var clientPolicy = client.RiskPolicyId is { } cpid
            ? policies.FirstOrDefault(p => p.Id == cpid)?.Name
            : null;

        var rows = projects
            .Select(p => new ClientProjectRow(
                p.Id,
                p.Name,
                componentCounts.FirstOrDefault(c => c.ProjectId == p.Id)?.Count ?? 0,
                lastBuilds.FirstOrDefault(b => b.ProjectId == p.Id)?.Last,
                p.RiskPolicyId is { } ppid
                    ? policies.FirstOrDefault(x => x.Id == ppid)?.Name
                    : null,
                // Inherited rather than "none": a project with no policy of its
                // own is not unscored, it is scored by the client's. Rendering
                // that as a blank would send someone looking for a setting that
                // is working as intended.
                p.RiskPolicyId is null))
            // Never-built projects first. A project nobody has ingested to is
            // the one thing on this screen that needs doing.
            .OrderBy(p => p.LastBuild is not null)
            .ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new ClientDetail(
            client.Id, client.Name, client.Description, clientPolicy, client.CreatedAt, rows);
    }

    public async Task<Result<bool>> SaveAsync(
        Principal actor, Guid clientId, string name, string? description, Guid? riskPolicyId,
        CancellationToken ct = default)
    {
        // Client-level settings change the defaults every project under it
        // inherits, so this is the project-creation capability rather than an
        // ordinary edit.
        var decision = _capabilities.Evaluate(actor, Capability.CreateProject);
        if (!decision.Allowed) return Result<bool>.Denied(decision.Reason!);

        var client = await _db.Clients.SingleOrDefaultAsync(c => c.Id == clientId, ct);
        if (client is null) return Result<bool>.Invalid("That client no longer exists.");

        name = name.Trim();
        if (name.Length == 0) return Result<bool>.Invalid("A client needs a name.");

        var clash = await _db.Clients.AnyAsync(
            c => c.Id != clientId && c.Name.ToLower() == name.ToLower(), ct);
        if (clash) return Result<bool>.Invalid($"Another client is already called \"{name}\".");

        if (riskPolicyId is { } policyId
            && !await _db.RiskPolicies.AnyAsync(p => p.Id == policyId, ct))
            return Result<bool>.Invalid("That risk policy no longer exists.");

        var renamed = !string.Equals(client.Name, name, StringComparison.Ordinal);
        var policyChanged = client.RiskPolicyId != riskPolicyId;

        client.Name = name;
        client.Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        client.RiskPolicyId = riskPolicyId;

        // A policy change moves the score of every project under this client
        // that has none of its own — a risk decision. A rename is not, but it
        // DOES break every bookmarked URL, so it is worth the entry either way.
        _audit.Record(actor, "client.updated",
            policyChanged ? AuditClass.Risk : AuditClass.Other,
            ScopeTarget.Client(client.Id),
            subjectId: client.Id, subjectKind: nameof(Client),
            detail: policyChanged
                ? $"{client.Name}: default risk policy changed — every project without its own rescores"
                : renamed
                    ? $"renamed to {client.Name}; existing links to the old name will not resolve"
                    : $"{client.Name} updated");

        await _db.SaveChangesAsync(ct);
        return Result<bool>.Ok(true);
    }
}

public sealed record ClientDetail(
    Guid Id,
    string Name,
    string? Description,
    /// <summary>The client's default policy. Projects with none of their own use it.</summary>
    string? RiskPolicyName,
    DateTimeOffset CreatedAt,
    IReadOnlyList<ClientProjectRow> Projects);

public sealed record ClientProjectRow(
    Guid Id,
    string Name,
    int Components,
    DateTimeOffset? LastBuild,
    string? RiskPolicyName,
    bool InheritsPolicy);
