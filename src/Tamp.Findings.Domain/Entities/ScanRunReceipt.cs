using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Entities;

// Receipt of "this scanner ran against this component version" — addresses
// the silent-clean problem (TFND-15). Without a receipt, a scanner that
// runs clean is indistinguishable from one that never ran; with one, the
// dashboard can show "scanned · zero findings" instead of falling back to
// the grey "never scanned" affordance.
//
// Replace-on-ingest: one row per (ComponentVersionId, Scanner). Re-ingest
// of the same scanner against the same CV overwrites the prior receipt.
public sealed class ScanRunReceipt
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }
    public ScannerKind Scanner { get; set; }

    public ScanRunStatus Status { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset CompletedAt { get; set; }
    public int FindingsCount { get; set; }

    public string? ToolName { get; set; }       // human label, e.g. "OpenGrep OSS"
    public string? ToolVersion { get; set; }    // e.g. "1.22.0"
    public string? Notes { get; set; }          // free-form, e.g. "1059 rules / 258 applicable, scanned 77 files"

    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
}

public enum ScanRunStatus
{
    Succeeded = 0,
    Failed = 1,
    Skipped = 2,
}
