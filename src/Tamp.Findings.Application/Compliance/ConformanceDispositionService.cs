using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Compliance;

// The per-finding VEX-accept write-path for ADR-conformance (TFND-191 / ADR 0006 §7):
// an auditable, InfoSec-only accepted deviation recorded AGAINST a conformance Fail — the
// human "we know, and we accept it" that stops the adrConformance gate from blocking on
// that one finding, the same way a VEX statement dispositions a vulnerability. Not a muted
// gate: the finding stays listed; only its block flag clears until the expiry.
public sealed class ConformanceDispositionService(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
{
    public async Task<Result<Guid>> DisposeAsync(
        Principal actor, ScopeTarget scope, Guid projectId, Guid findingId,
        string justification, DateTimeOffset? expiry, CancellationToken ct = default)
    {
        // §7: an accepted deviation is a risk-acceptance decision — InfoSec AcceptRisk,
        // the same capability POA&M risk-acceptance requires (Admin deliberately lacks it).
        var decision = capabilities.Evaluate(actor, Capability.AcceptRisk);
        if (!decision.Allowed) return Result<Guid>.Denied(decision.Reason!);

        if (string.IsNullOrWhiteSpace(justification))
            return Result<Guid>.Invalid("A disposition needs a justification — it is the evidence the deviation was a decision, not an oversight.");
        if (expiry is { } e && e <= DateTimeOffset.UtcNow)
            return Result<Guid>.Invalid("The expiry must be in the future; stale evidence is no evidence.");

        // The finding must belong to the scoped project (join through the build).
        var finding = await db.ConformanceFindings
            .Where(f => f.Id == findingId
                && db.ComponentVersions.Any(v => v.Id == f.ComponentVersionId && v.ProjectId == projectId))
            .FirstOrDefaultAsync(ct);
        if (finding is null) return Result<Guid>.Invalid("That conformance finding no longer exists on this project.");

        finding.Dispositioned = true;
        finding.DispositionJustification = justification.Trim();
        finding.DispositionedByLogin = actor.Login;
        finding.DispositionExpiry = expiry;

        audit.Record(actor, "conformance.dispositioned", AuditClass.Risk, scope,
            subjectId: finding.Id, subjectKind: nameof(Domain.Entities.ConformanceFinding),
            detail: $"{finding.AdrRef}/{finding.RuleId} accepted{(expiry is { } x ? $" until {x:yyyy-MM-dd}" : "")}: {finding.DispositionJustification}");

        await db.SaveChangesAsync(ct);
        return Result<Guid>.Ok(finding.Id);
    }
}
