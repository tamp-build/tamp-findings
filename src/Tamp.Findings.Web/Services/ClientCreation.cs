using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;

namespace Tamp.Findings.Web.Services;

/// <summary>
/// Creating a client, as a function rather than as page code (TFND-257).
///
/// The Portfolio page has two entry points for this — the toolbar action and
/// the inline affordance in the New-project dialog's empty state — and they
/// want different things afterwards: one closes its dialog, the other stays put
/// and selects what was just made. The shared part is the orchestration, and
/// keeping it here means both entry points run the SAME orchestration rather
/// than two near-copies in a template.
///
/// Takes the resolved <see cref="Principal"/> rather than <c>CurrentUser</c> so
/// it can be tested with a fabricated actor against the real service, the way
/// HierarchyIntegrationTests already does. A helper that needed an
/// authenticated HTTP context to exercise would be a helper nobody exercises.
/// </summary>
public static class ClientCreation
{
    /// <summary>
    /// May this actor create a client?
    ///
    /// An <see cref="Actor.Admin"/> check rather than a capability one, because
    /// <see cref="HierarchyService.CreateClientAsync"/> asks for exactly that: a
    /// client sits above every project, so nothing narrower can grant the right
    /// to make one. Asking the capability evaluator instead would be answering a
    /// different question and getting a confident wrong answer.
    /// </summary>
    public static bool MayCreate(Principal? actor) =>
        actor?.Actors.Contains(Actor.Admin) == true;

    /// <summary>
    /// Create it, or say why not. The error is the service's own sentence —
    /// name taken, name blank, not an administrator — because those are already
    /// written for a reader and rewording them here would be a second place for
    /// the same message to drift.
    /// </summary>
    public static async Task<(Guid? Id, string? Error)> CreateAsync(
        Principal? actor, HierarchyService hierarchy, string? name, CancellationToken ct = default)
    {
        if (actor is null) return (null, "You are not signed in.");

        var result = await hierarchy.CreateClientAsync(actor, name ?? "", ct);

        return result.Success ? (result.Value, null) : (null, result.Error);
    }
}
