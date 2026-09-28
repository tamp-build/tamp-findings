namespace Tamp.Findings.Domain.Compliance;

// The CISA ZTMM v2.0 structure (TFND-188 / ADR 0010 §3), stored inline as jsonb on a
// MaturityModelCatalog — the maturity analogue of Control on a ControlCatalog. CISA
// supplies descriptors only; the stage NUMBERS and the scoring math are implementer
// -supplied (the shared scoring contract, ADR 0010 §8). Descriptors are written in
// OWNER language (brief §11) — the stage mapping hides in the model, the question the
// owner answers is concrete.

// One of the 5 ZTMM pillars: Identity, Devices, Networks, Applications & Workloads,
// Data. The 3 cross-cutting capabilities (Visibility & Analytics, Automation &
// Orchestration, Governance) are NOT standalone pillars — they appear as functions
// (CrossCutting = true) folded into each pillar (ADR 0010 §3).
public sealed class ZtPillar
{
    public required string Id { get; set; }       // "identity"
    public required string Name { get; set; }     // "Identity"
    public List<ZtFunctionDef> Functions { get; set; } = [];
}

public sealed class ZtFunctionDef
{
    public required string Id { get; set; }       // "authentication"
    public required string Name { get; set; }     // "Authentication"
    // A cross-cutting capability's function (V&A / Automation / Governance) folded into
    // this pillar. Weighs the same as any other function in the pillar (equal weights).
    public bool CrossCutting { get; set; }
    public List<ZtStageDescriptor> Stages { get; set; } = [];
}

// Stage 1-4 (Traditional / Initial / Advanced / Optimal) — floor is 1, there is NO
// zero (ADR 0010 §2). The descriptor is the owner-language question for this stage.
public sealed class ZtStageDescriptor
{
    public int Stage { get; set; }
    public required string Descriptor { get; set; }
}
