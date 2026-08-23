using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// The capability matrix from the hand-off, as data.
///
/// Roles are ADDITIVE: a user holds any number of them and effective access is
/// the union. That is deliberate — "a three-person team should not be forced
/// into an org chart it doesn't have" — so this table answers per role and the
/// evaluator unions the answers.
///
/// Written as a table rather than a switch so the RBAC screen (TFND-110) can
/// render exactly what the code enforces, rather than a hand-maintained copy
/// that drifts from it.
/// </summary>
public static class CapabilityMatrix
{
    /// <summary>
    /// Grants that hold outright. Conditional cells (the matrix's ◐) are NOT
    /// here — they carry a condition the evaluator has to apply, and a
    /// conditional grant flattened into an unconditional one is a privilege
    /// escalation hiding as a simplification.
    /// </summary>
    private static readonly Dictionary<Actor, Capability[]> Grants = new()
    {
        [Actor.Admin] =
        [
            Capability.ViewEvidence, Capability.ExportAttestation,
            Capability.AuthorSuppression, Capability.AuthorVex, Capability.PublishVex,
            Capability.CreatePoamItem, Capability.CompletePoamItem,
            Capability.EditPolicyWeights, Capability.DuplicatePolicy, Capability.EditGates,
            Capability.CreateProject, Capability.CreateComponent,
            Capability.ManageIngestKey, Capability.EditDisclosurePolicy, Capability.AssignRoles,
            // NOT AcceptRisk. An Authorizing Official decision, not a systems
            // privilege. This absence is load-bearing.
        ],

        [Actor.InfoSecOfficer] =
        [
            Capability.ViewEvidence, Capability.ExportAttestation,
            Capability.AuthorSuppression, Capability.AuthorVex, Capability.PublishVex,
            Capability.CreatePoamItem, Capability.CompletePoamItem, Capability.AcceptRisk,
            Capability.EditPolicyWeights, Capability.DuplicatePolicy, Capability.EditGates,
            Capability.ManageIngestKey, Capability.EditDisclosurePolicy,
            // AssignRoles is conditional — at or below their own scope.
        ],

        [Actor.LeadDev] =
        [
            Capability.ViewEvidence, Capability.ExportAttestation,
            Capability.AuthorSuppression,
            Capability.CreatePoamItem, Capability.CompletePoamItem,
            Capability.CreateComponent, Capability.ManageIngestKey,
            // AuthorVex is conditional — drafts only, InfoSec publishes.
        ],

        [Actor.Architect] =
        [
            Capability.ViewEvidence, Capability.ExportAttestation,
            Capability.AuthorSuppression, Capability.AuthorVex, Capability.PublishVex,
            Capability.CreatePoamItem, Capability.CompletePoamItem,
            Capability.DuplicatePolicy,
            Capability.CreateProject, Capability.CreateComponent,
            // EditPolicyWeights is conditional — may duplicate, not edit in place.
        ],

        [Actor.Auditor] =
        [
            // Reads and exports, authors nothing. Export is the distinguishing
            // capability: it is the auditor's whole job.
            Capability.ViewEvidence, Capability.ExportAttestation,
        ],

        [Actor.Viewer] =
        [
            // Read access and nothing else. Notably NOT ExportAttestation.
            Capability.ViewEvidence,
        ],
    };

    /// <summary>
    /// Conditional grants — the matrix's ◐. The condition is data the caller
    /// must satisfy, not a comment.
    /// </summary>
    private static readonly Dictionary<(Actor, Capability), string> Conditional = new()
    {
        [(Actor.LeadDev, Capability.AuthorVex)] =
            "Lead Dev may draft a VEX statement; publishing it is InfoSec's decision.",
        [(Actor.Architect, Capability.EditPolicyWeights)] =
            "Architect may duplicate a policy but not edit one in place.",
        [(Actor.InfoSecOfficer, Capability.AssignRoles)] =
            "InfoSec may assign roles at or below their own scope.",
    };

    public static bool Grants_(Actor actor, Capability capability) =>
        Grants.TryGetValue(actor, out var caps) && caps.Contains(capability);

    public static bool IsConditional(Actor actor, Capability capability) =>
        Conditional.ContainsKey((actor, capability));

    public static string? ConditionFor(Actor actor, Capability capability) =>
        Conditional.TryGetValue((actor, capability), out var reason) ? reason : null;

    /// <summary>Every actor, for rendering the matrix in the RBAC screen.</summary>
    public static IReadOnlyList<Actor> AllActors { get; } = Enum.GetValues<Actor>();

    /// <summary>Every capability, in matrix order.</summary>
    public static IReadOnlyList<Capability> AllCapabilities { get; } = Enum.GetValues<Capability>();
}

/// <summary>
/// Who is acting, for the purpose of the matrix.
///
/// Wider than <see cref="ProjectRole"/> because two of the rows are not
/// project roles at all: Admin is the instance-level <c>User.IsAdmin</c> flag,
/// and Viewer is the implicit default for someone with read access and no
/// role. The hand-off's matrix has six rows; the enum has six values.
/// </summary>
public enum Actor
{
    /// <summary>Read access, no role. Not persisted — the absence of a grant.</summary>
    Viewer,

    /// <summary>Proposed by the hand-off; added to ProjectRole in TFND-69.</summary>
    Auditor,

    LeadDev,
    Architect,
    InfoSecOfficer,

    /// <summary>Instance-level User.IsAdmin, not a ProjectRole.</summary>
    Admin,
}
