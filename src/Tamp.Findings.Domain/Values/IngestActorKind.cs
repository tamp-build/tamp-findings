namespace Tamp.Findings.Domain.Values;

/// <summary>
/// Who produced an ingest (TFND-165 / ADR 0019 "attributable by construction").
///
/// The wire contract (tamp-ingest-v1 v1.3) carries this PascalCase — the sink's
/// default <c>JsonStringEnumConverter</c> serialises the member names — so an
/// agent-produced build can be told from a human-produced one after the fact.
/// </summary>
public enum IngestActorKind
{
    Agent = 0,
    Human = 1,
}
