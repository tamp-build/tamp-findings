using Elsa.Extensions;
using Elsa.Scheduling.Activities;
// System.Threading.Timer is in scope through the implicit usings and collides
// with the activity, so the activity gets the unambiguous name here.
using Timer = Elsa.Scheduling.Activities.Timer;
using Elsa.Workflows;
using Elsa.Workflows.Activities;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Workflows.Definitions;

/// <summary>
/// TFND-121. POA&amp;M due-date reminders.
///
/// This is the workflow that most clearly earns the engine. A reminder is
/// neither a row nor a request — it is a thing that has to happen on a schedule
/// whether or not anybody opens the application, and there is no way to express
/// that as state.
///
/// It reminds on items due SOON, not on items already past due. An item that
/// has slipped is already failing the poamPastDue gate and is at the top of the
/// POA&amp;M table in red; another notification about it adds nothing and
/// teaches people that these messages are noise. The window is the last week
/// before the committed date, which is when doing something about it is still
/// possible.
/// </summary>
public sealed class PoamDueReminderWorkflow : WorkflowBase
{
    /// <summary>
    /// Daily. Not hourly: a due date has day resolution, and twenty-four
    /// reminders about the same date is how a channel gets muted.
    /// </summary>
    private static readonly TimeSpan Cadence = TimeSpan.FromDays(1);

    /// <summary>
    /// How far ahead to look. A week is long enough to do something and short
    /// enough that the reminder is about this week's work.
    /// </summary>
    private static readonly TimeSpan Window = TimeSpan.FromDays(7);

    protected override void Build(IWorkflowBuilder builder)
    {
        builder.Root = new Sequence
        {
            Activities =
            {
                new Timer(Cadence),

                new Inline(async context =>
                {
                    var bridge = context.GetRequiredService<WorkflowBridge>();

                    // One instant for the whole sweep, so an item cannot fall
                    // in and out of the window between two rows of the same run.
                    var asOf = DateTimeOffset.UtcNow;
                    var due = await bridge.PoamsDueWithinAsync(Window, asOf, context.CancellationToken);

                    if (due.Count == 0) return;

                    foreach (var item in due)
                    {
                        await bridge.NoteAsync(
                            "poam.due_soon", AuditClass.Risk,
                            new ScopeTarget(null, item.ProjectId, null),
                            subjectId: item.PoamItemId, subjectKind: "PoamItem",
                            detail: $"\"{item.Title}\" is due {item.Due:yyyy-MM-dd} "
                                  + $"({(item.Due - asOf).TotalDays:0} days). Close it, get an AO "
                                  + "extension, or move it to risk-accepted.",
                            context.CancellationToken);
                    }
                }),
            },
        };
    }
}

/// <summary>
/// TFND-122. Gate failure notification.
///
/// Runs on demand rather than on a schedule — a gate verdict changes when a
/// build is ingested, and a timer would either report stale verdicts or hammer
/// the evaluator for no reason.
///
/// It reports BLOCKING gates, which under four-valued verdicts (ADR 0001) means
/// Fail, Unknown AND Error — not just Fail. A gate that could not be answered
/// is not a gate that passed, and a notification that silently dropped the
/// Unknowns would be the exact defect the four-valued model was introduced to
/// remove.
/// </summary>
public sealed class GateFailureNotificationWorkflow : WorkflowBase
{
    public const string ProjectInput = "projectId";
    public const string CommitInput = "commitSha";

    protected override void Build(IWorkflowBuilder builder)
    {
        builder.Root = new Inline(async context =>
        {
            var input = context.WorkflowExecutionContext.Input;

            if (!input.TryGetValue(ProjectInput, out var rawProject)
                || !Guid.TryParse(rawProject?.ToString(), out var projectId))
                return;

            var commitSha = input.TryGetValue(CommitInput, out var rawCommit)
                ? rawCommit?.ToString()
                : null;
            if (string.IsNullOrWhiteSpace(commitSha)) return;

            var bridge = context.GetRequiredService<WorkflowBridge>();
            var blocking = await bridge.BlockingGatesAsync(projectId, commitSha, context.CancellationToken);

            if (blocking.Count == 0) return;

            await bridge.NoteAsync(
                "gates.blocking", AuditClass.Risk,
                new ScopeTarget(null, projectId, null),
                subjectId: null, subjectKind: "ProjectGates",
                detail: $"{commitSha[..Math.Min(12, commitSha.Length)] } is blocked by "
                      + string.Join(", ", blocking.Select(g => $"{g.Key} ({g.Verdict}: {g.Observed})")),
                context.CancellationToken);
        });
    }
}

/// <summary>
/// TFND-118. POA&amp;M completion on a verifying build.
///
/// Also on-demand, for the same reason: it is a question about one specific
/// build, asked when that build arrives.
///
/// It does NOT close the item. It records that a build verifies the
/// remediation and requests the completion approval, because closing a federal
/// record automatically would mean a scanner's silence became somebody's
/// signature. The person still decides; the workflow removes the work of
/// noticing.
/// </summary>
public sealed class PoamVerifyingBuildWorkflow : WorkflowBase
{
    public const string PoamInput = "poamItemId";
    public const string CommitInput = "commitSha";

    protected override void Build(IWorkflowBuilder builder)
    {
        builder.Root = new Inline(async context =>
        {
            var input = context.WorkflowExecutionContext.Input;

            if (!input.TryGetValue(PoamInput, out var rawPoam)
                || !Guid.TryParse(rawPoam?.ToString(), out var poamItemId))
                return;

            var commitSha = input.TryGetValue(CommitInput, out var rawCommit)
                ? rawCommit?.ToString()
                : null;
            if (string.IsNullOrWhiteSpace(commitSha)) return;

            var bridge = context.GetRequiredService<WorkflowBridge>();
            var verification = await bridge.VerifyPoamAsync(poamItemId, commitSha, context.CancellationToken);

            // A failed verification is recorded too. "We looked and it is not
            // fixed yet" is worth having on the record — it is the difference
            // between an item nobody has checked and one that is genuinely
            // still open.
            await bridge.NoteAsync(
                verification.Verified ? "poam.verified" : "poam.not_verified",
                AuditClass.Risk,
                ScopeTarget.Instance,
                subjectId: poamItemId, subjectKind: "PoamItem",
                detail: $"build {commitSha[..Math.Min(12, commitSha.Length)]}: {verification.Reason}",
                context.CancellationToken);
        });
    }
}
