using System.Text.Json.Serialization;

namespace Tamp.Findings.Application.Eo;

// The committed, human-reviewed eo-directives corpus (ADR 0011 §6) — the lockfile
// analogue of a governed repo's adr-rules.json, but centralized here because the EO
// registry is instance-wide, not per-repo. Shipped as Content/eo/eo-directives.json and
// hash-seeded on startup. A frontier model (the tamp-EOProvenance tool) produces it
// offline with abstention; a human reviews it before it is trusted; findings ingests
// the reviewed output. Only Reviewed directives ever enter the in-force set.
public sealed class EoCorpus
{
    public string Version { get; set; } = "";
    public List<EoCorpusInstrument> Instruments { get; set; } = [];
    public List<EoCorpusDirective> Directives { get; set; } = [];
    // Amendment-diff input: an instrument that struck prior directives, and when.
    public List<EoCorpusRescission> Rescissions { get; set; } = [];
}

public sealed class EoCorpusInstrument
{
    public required string Identifier { get; set; }   // "EO 14028"
    public required string Title { get; set; }
    public string Type { get; set; } = "ExecutiveOrder"; // InstrumentType name
    public string? Authority { get; set; }
    public DateTimeOffset IssueDate { get; set; }
    public string? Cite { get; set; }
    public string ReviewStatus { get; set; } = "Reviewed";
    public List<EoCorpusRelation> Relations { get; set; } = [];
}

public sealed class EoCorpusRelation
{
    public required string Type { get; set; }         // Amends | Revokes | Supersedes | Implements
    public required string To { get; set; }           // target instrument identifier
    public string? FromSection { get; set; }
    public string? ToSection { get; set; }
}

public sealed class EoCorpusDirective
{
    public required string Ref { get; set; }          // "EO14144§4(e)" — stable, unique
    public required string Instrument { get; set; }   // owning instrument identifier
    public string? Section { get; set; }
    public required string Who { get; set; }
    public required string MustDo { get; set; }
    public string Type { get; set; } = "SelfExecutingDated"; // DirectiveType name
    public string Applicability { get; set; } = "AllSystems";
    public EoCorpusByWhen? ByWhen { get; set; }
    public EoCorpusCrosswalk? Crosswalk { get; set; }
    public string ReviewStatus { get; set; } = "Reviewed";
}

public sealed class EoCorpusByWhen
{
    public string Kind { get; set; } = "Absolute";    // Absolute | Relative | Pending
    public DateTimeOffset? Date { get; set; }         // Absolute
    public int? OffsetDays { get; set; }              // Relative
    public string? Anchor { get; set; }               // SigningDate | PredicateMemoIssue
    public string? AnchorInstrument { get; set; }     // identifier of the predicate instrument
}

public sealed class EoCorpusCrosswalk
{
    public required string Target { get; set; }       // Findings | Ztt
    public required string Ref { get; set; }          // mandate id / gate key / rule id
}

public sealed class EoCorpusRescission
{
    public required string ByInstrument { get; set; } // the amending/revoking instrument identifier
    public DateTimeOffset EffectiveDate { get; set; }
    public List<string> Directives { get; set; } = []; // refs of the struck directives
}
