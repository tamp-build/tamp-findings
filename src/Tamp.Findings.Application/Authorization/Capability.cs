namespace Tamp.Findings.Application.Authorization;

/// <summary>
/// What a user may do. One entry per row of the hand-off's capability matrix.
///
/// Capabilities rather than roles are the unit of authorization on purpose: a
/// screen asks "may this person accept risk?", never "is this person an
/// InfoSec Officer?". Roles are how capabilities are granted; they are not
/// what the code checks. That indirection is what lets Auditor be added, or a
/// grant be scoped, without every call site changing.
/// </summary>
public enum Capability
{
    /// <summary>Findings, evidence and the attestation. Everyone with read access.</summary>
    ViewEvidence,

    /// <summary>
    /// Export attestation JSON / PDF. Denied to Viewer, allowed to Auditor —
    /// the hand-off's note is that this is "the auditor's whole job".
    /// </summary>
    ExportAttestation,

    /// <summary>Author rule suppressions. A reason is required.</summary>
    AuthorSuppression,

    /// <summary>
    /// Author a VEX statement. Conditional for Lead Dev: they draft, InfoSec
    /// publishes. The transition itself is a workflow (TFND-120), not a
    /// permission — this only covers authoring.
    /// </summary>
    AuthorVex,

    /// <summary>Publish a VEX statement. InfoSec and above.</summary>
    PublishVex,

    CreatePoamItem,

    /// <summary>Close a POA&amp;M as Completed. Needs a verifying build (TFND-118).</summary>
    CompletePoamItem,

    /// <summary>
    /// Set a POA&amp;M to Risk accepted.
    ///
    /// InfoSec ONLY — and notably NOT Admin. This is an Authorizing Official
    /// decision, not a systems privilege, and the hand-off calls it out
    /// explicitly. Do not "fix" the matrix by granting it to Admin.
    /// </summary>
    AcceptRisk,

    /// <summary>Edit risk policy weights. Architect may duplicate, not edit in place.</summary>
    EditPolicyWeights,

    /// <summary>Duplicate a policy. How an Architect changes weights without editing in place.</summary>
    DuplicatePolicy,

    /// <summary>Edit acceptance gates. Admin and InfoSec only — gates are the release contract.</summary>
    EditGates,

    CreateProject,
    CreateComponent,

    /// <summary>
    /// Set or recycle the project ingest key. Recycling breaks CI until the
    /// pipeline is redeployed, which is why Architect is excluded.
    /// </summary>
    ManageIngestKey,

    /// <summary>Assign roles. Conditional for InfoSec: at or below their own scope.</summary>
    AssignRoles,
}
