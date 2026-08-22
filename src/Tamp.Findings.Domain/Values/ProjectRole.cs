namespace Tamp.Findings.Domain.Values;

// The three named roles allowed to author suppressions, waivers, and acks
// (TFND-3 / F2.4). Plain viewers are not part of this enum — they are the
// implicit default for a user with read access to an entity but no role.
public enum ProjectRole
{
    InfoSecOfficer = 1,
    LeadDev = 2,
    Architect = 3,

    // TFND-69. Reads and exports; authors nothing. Export is the
    // distinguishing capability — it is the auditor's whole job, and it is the
    // only thing separating an Auditor from a Viewer.
    //
    // Stored as an int with no check constraint, so adding this value needed
    // no migration. It DOES widen anything that parses a role from input
    // without then asking the capability evaluator what that role may do —
    // see SuppressionsEndpoints.
    Auditor = 4,
}
