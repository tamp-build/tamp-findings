namespace Tamp.Findings.Domain.Values;

// The three named roles allowed to author suppressions, waivers, and acks
// (TFND-3 / F2.4). Plain viewers are not part of this enum — they are the
// implicit default for a user with read access to an entity but no role.
public enum ProjectRole
{
    InfoSecOfficer = 1,
    LeadDev = 2,
    Architect = 3,
}
