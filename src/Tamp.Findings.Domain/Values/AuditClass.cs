namespace Tamp.Findings.Domain.Values;

// What kind of event this is, which drives the chip colour in the audit log
// and — more importantly — what an assessor filters on first.
//
// The design: "Risk acceptance, role grants and key changes are what an
// assessor reads first." That is why they are classes rather than being flat
// rows with a search box.
public enum AuditClass
{
    // Everything else: exports, ingest key views, settings that carry no
    // security weight on their own.
    Other = 0,

    // Risk posture changed by a human decision: a POA&M risk-accepted, an AO
    // extension, a gate threshold moved, a suppression authored, a policy
    // saved. Rendered in #e2894a.
    Risk = 1,

    // Who can do what changed: role granted or revoked, an ingest key or token
    // rotated, an identity provider enabled. Rendered in the accent.
    Access = 2,
}
