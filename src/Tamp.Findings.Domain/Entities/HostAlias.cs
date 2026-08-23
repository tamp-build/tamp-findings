namespace Tamp.Findings.Domain.Entities;

// One application reached by two addresses (TFND-91).
//
// A dynamic scanner attributes findings to HOW IT CONNECTED, not to the
// application. Scan https://app.internal and https://app.example.com and the
// same deployment appears as two hosts with two sets of findings — problem 7
// on the brief's list, "one app appearing as two hosts".
//
// An alias says "these are the same thing", and the DAST tree collapses them.
//
// FORWARD-ONLY BY DESIGN. Aliasing changes which findings group together, and
// therefore counts — but it does NOT rewrite history: builds already scored and
// attested keep the numbers they were signed with. Re-deriving old scores from
// a mapping created later would make an attestation say something different in
// September than it said in March, which is exactly what ADR 0001 forbids about
// recomputable evidence.
public sealed class HostAlias
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid ProjectId { get; set; }

    // The host as the scanner reported it, e.g. "app.internal:8443".
    public required string Alias { get; set; }

    // The host it should be treated as.
    public required string CanonicalHost { get; set; }

    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    // Why someone decided these were the same application. Required in the UI
    // because a merge is a judgement about deployment topology that the next
    // reader cannot reconstruct from the hostnames alone.
    public string? Reason { get; set; }
}
