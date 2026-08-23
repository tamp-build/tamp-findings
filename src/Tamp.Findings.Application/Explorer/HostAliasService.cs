using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// Reading and creating host aliases — the "Merge hosts" affordance the design
/// offers on the DAST duplicate-host callout (TFND-91).
/// </summary>
public sealed class HostAliasService
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public HostAliasService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public async Task<HostAliasMap> ForProjectAsync(Guid projectId, CancellationToken ct = default)
    {
        var rows = await _db.HostAliases.AsNoTracking()
            .Where(a => a.ProjectId == projectId)
            .Select(a => new { a.Alias, a.CanonicalHost })
            .ToArrayAsync(ct);

        return new HostAliasMap(rows.ToDictionary(
            r => r.Alias, r => r.CanonicalHost, StringComparer.OrdinalIgnoreCase));
    }

    public async Task<Result<Guid>> MergeAsync(
        Principal actor, ScopeTarget scope, Guid projectId,
        string alias, string canonicalHost, string reason, CancellationToken ct = default)
    {
        // Same capability as authoring a suppression: both are a person
        // asserting that findings mean something other than what the scanner
        // literally reported.
        var decision = _capabilities.Evaluate(actor, Capability.AuthorSuppression);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        alias = alias.Trim();
        canonicalHost = canonicalHost.Trim();

        if (alias.Length == 0 || canonicalHost.Length == 0)
            return Result<Guid>.Invalid("Both hosts are required.");

        if (string.Equals(alias, canonicalHost, StringComparison.OrdinalIgnoreCase))
            return Result<Guid>.Invalid("A host cannot be an alias of itself.");

        if (string.IsNullOrWhiteSpace(reason))
        {
            // A merge is a judgement about deployment topology that the next
            // reader cannot reconstruct from the hostnames alone.
            return Result<Guid>.Invalid(
                "Say why these are the same application. Someone reading this in a year cannot tell from the names.");
        }

        // Refuse a chain: if the canonical host is itself an alias, the reader
        // would have to follow two hops and the result would depend on
        // resolution order. Point at the end of the chain instead.
        var canonicalIsAlias = await _db.HostAliases
            .AnyAsync(a => a.ProjectId == projectId && a.Alias == canonicalHost, ct);
        if (canonicalIsAlias)
        {
            return Result<Guid>.Invalid(
                $"\"{canonicalHost}\" is already an alias of something else. Merge into the canonical host directly.");
        }

        if (await _db.HostAliases.AnyAsync(a => a.ProjectId == projectId && a.Alias == alias, ct))
            return Result<Guid>.Invalid($"\"{alias}\" is already merged.");

        var entity = new HostAlias
        {
            ProjectId = projectId,
            Alias = alias,
            CanonicalHost = canonicalHost,
            CreatedByUserId = actor.UserId == Guid.Empty ? null : actor.UserId,
            Reason = reason.Trim(),
        };
        _db.HostAliases.Add(entity);

        // Risk class: merging changes which findings group together and
        // therefore what the DAST counts say, which is a risk-posture decision
        // rather than housekeeping.
        _audit.Record(actor, "host.merged", AuditClass.Risk, scope,
            subjectId: entity.Id, subjectKind: nameof(HostAlias),
            detail: $"{alias} → {canonicalHost}: {reason.Trim()}");

        await _db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(entity.Id);
    }
}

/// <summary>
/// Alias → canonical, plus the heuristic that spots hosts worth merging.
/// </summary>
public sealed class HostAliasMap
{
    private readonly IReadOnlyDictionary<string, string> _aliases;

    public HostAliasMap(IReadOnlyDictionary<string, string> aliases) => _aliases = aliases;

    /// <summary>Resolve one hop. Chains are refused at creation, so one is enough.</summary>
    public string Canonical(string host) =>
        _aliases.TryGetValue(host, out var canonical) ? canonical : host;

    /// <summary>
    /// Hosts that look like the same application reached two ways.
    ///
    /// Deliberately a SUGGESTION, never automatic. Whether two addresses are
    /// one deployment is a fact about someone's infrastructure that this
    /// product cannot know — a staging and a production host can share a name
    /// and be genuinely different, and silently merging them would hide real
    /// findings behind a guess.
    /// </summary>
    public IReadOnlyList<DuplicateHostSuspicion> SuspectedDuplicates(IReadOnlyList<string> hosts)
    {
        var suspicions = new List<DuplicateHostSuspicion>();

        for (var i = 0; i < hosts.Count; i++)
        for (var j = i + 1; j < hosts.Count; j++)
        {
            var a = hosts[i];
            var b = hosts[j];
            if (a == "(relative)" || b == "(relative)" || a == "(unknown host)" || b == "(unknown host)") continue;

            var reason = Similarity(a, b);
            if (reason is not null) suspicions.Add(new DuplicateHostSuspicion(a, b, reason));
        }

        return suspicions;
    }

    private static string? Similarity(string a, string b)
    {
        var (hostA, portA) = Split(a);
        var (hostB, portB) = Split(b);

        // Same name, different port: almost always one deployment behind two
        // listeners.
        if (string.Equals(hostA, hostB, StringComparison.OrdinalIgnoreCase) && portA != portB)
            return "same host on different ports";

        // Same leftmost label: app.internal and app.example.com.
        var labelA = hostA.Split('.')[0];
        var labelB = hostB.Split('.')[0];
        if (labelA.Length > 2 && string.Equals(labelA, labelB, StringComparison.OrdinalIgnoreCase))
            return $"both start with \"{labelA}\"";

        // One is localhost and the other is not — a scan run from inside the
        // deployment and one run from outside.
        var localA = IsLocal(hostA);
        var localB = IsLocal(hostB);
        if (localA != localB) return "one address is local and the other is not";

        return null;
    }

    private static bool IsLocal(string host) =>
        host is "localhost" or "127.0.0.1" or "::1" || host.EndsWith(".local", StringComparison.OrdinalIgnoreCase);

    private static (string Host, string? Port) Split(string value)
    {
        var colon = value.LastIndexOf(':');
        return colon > 0 ? (value[..colon], value[(colon + 1)..]) : (value, null);
    }
}

public sealed record DuplicateHostSuspicion(string HostA, string HostB, string Reason);
