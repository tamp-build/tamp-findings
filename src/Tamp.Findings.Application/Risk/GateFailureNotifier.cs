using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

/// <summary>
/// Records a notification when a freshly ingested build is blocked by its gates
/// (TFND-122).
///
/// <para>
/// Was an on-demand Elsa workflow (removed, ADR 0005); now an inline emit off the
/// ingest path, which is where the original ran too — a gate verdict changes when
/// a build is ingested, so a timer would either report stale verdicts or hammer
/// the evaluator for nothing.
/// </para>
/// <para>
/// "Notification" here is an audit entry in the risk class, not email: the
/// product has no mail transport, and a durable record the audit-log screen and
/// an assessor both read is the honest form of it. It reports BLOCKING gates,
/// which under four-valued verdicts (ADR 0001) means Fail, Unknown AND Error — a
/// gate that could not be answered is not one that passed, and dropping the
/// Unknowns would be the exact defect the four-valued model exists to remove.
/// </para>
/// </summary>
public sealed class GateFailureNotifier
{
    private readonly FindingsDbContext _db;
    private readonly RiskInputsBuilder _inputs;
    private readonly AuditLog _audit;
    private readonly ScoringPolicyResolver _scoring;

    public GateFailureNotifier(FindingsDbContext db, RiskInputsBuilder inputs, AuditLog audit, ScoringPolicyResolver scoring)
    {
        _db = db;
        _inputs = inputs;
        _audit = audit;
        _scoring = scoring;
    }

    public async Task NotifyIfBlockedAsync(Guid projectId, string commitSha, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(commitSha)) return;

        var project = await _db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .SingleOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return;

        var build = await _db.ComponentVersions.AsNoTracking()
            .Where(v => v.ProjectId == projectId && v.CommitSha == commitSha)
            .Select(v => v.Id)
            .ToListAsync(ct);
        if (build.Count == 0) return;

        var policy = await _scoring.ForProjectAsync(projectId, ct);

        var inputs = await _inputs.BuildAsync(build, policy.Config, projectId, ct);
        var score = RiskScorer.Compute(policy.Config, inputs);
        var evaluation = GateEvaluator.Evaluate(
            project.GatesConfig ?? ProjectGatesDefaults.Empty(),
            inputs, score.Score, prior: null, priorScore: null);

        var blocking = evaluation.Results.Where(r => r.Blocks).ToArray();
        if (blocking.Length == 0) return;

        var shaShort = commitSha[..Math.Min(12, commitSha.Length)];
        var detail = $"{shaShort} is blocked by "
                   + string.Join(", ", blocking.Select(g => $"{g.Key} ({g.Verdict}: {g.Observed})"));

        // On-demand off the ingest path means each scanner for one build triggers
        // this. Record only when the blocking picture is NEW: an identical
        // notification already on the record is noise that teaches people to
        // ignore the signal. A CHANGED blocking set produces a different detail
        // and is worth recording.
        var already = await _db.AuditEntries.AsNoTracking().AnyAsync(
            a => a.Action == "gates.blocking" && a.ProjectId == projectId && a.Detail == detail, ct);
        if (already) return;

        _audit.RecordSystem("gates.blocking", AuditClass.Risk,
            new ScopeTarget(project.ClientId, projectId),
            subjectId: null, subjectKind: "ProjectGates", detail: detail);

        await _db.SaveChangesAsync(ct);
    }
}
