# Data model, rulesets & ingestion — tamp-ztt + tamp-EOProvenance

* Status: Proposed (design-for-review; no code yet)
* Date: 2026-09-28
* Companion ADRs: [0010](../adr/0010-zero-trust-maturity-and-operational-mandates.md) (ztt), [0011](../adr/0011-executive-order-mandate-provenance-registry.md) (EOProvenance)
* Scope owned here: **data persistence, the model, the rulesets, and the ingestion contracts** for both tools. Scoring-math UI (ztt) and the political dashboard (EOProvenance) are out of scope — they consume this.

Everything lives in the tamp.findings Postgres + minimal-API (one store, real FKs).
Conventions followed throughout (from the existing codebase): `public sealed class`
entities with their own `public Guid Id { get; set; } = Guid.NewGuid();`, no base
class; `DateTimeOffset` timestamps defaulted to `UtcNow`; `required` on non-null
strings; jsonb columns via `HasColumnType("jsonb")` (Npgsql `EnableDynamicJson()` is
already on, so typed POCOs/collections/dictionaries round-trip); sparse-unique
`IsCurrent` indexes for singleton "current" rows; ingest endpoints as
`static MapXxx(this IEndpointRouteBuilder)` with
`.AllowAnonymous().AddEndpointFilter<IngestAuthFilter>()` and `sealed record` DTOs;
every ingest writes an `AuditLog.RecordIngest`. Namespaces: `Domain/Entities`,
`Domain/Compliance` (value/derivation), `Domain/Risk` (policy), `Application/Zt`,
`Application/Eo` (new), `Api/Endpoints`.

---

## Part A — Shared substrate changes (small, additive)

### A1. `PoamItem` gains a source discriminator (ADR 0010 §9)

`PoamItem` today links only `ProjectId` + soft `LinkedFindingIds`. Add, additively:

```csharp
public PoamSource SourceKind { get; set; } = PoamSource.Finding; // default preserves today
public string? SourceRef { get; set; }   // mandate id, ZT function ref, or EO directive id
public string? MandatePackVersion { get; set; } // in-force mandate version at creation (point-in-time)

public enum PoamSource { Finding = 0, OperationalMandate = 1, ZtContradiction = 2, SupplyChainMandate = 3 }
```

`SourceRef` is a free-form key interpreted per `SourceKind` (e.g. `"encrypt-at-rest"`,
`"Identity/Authentication"`, `"EO14028§4(e)"`). No new table; one migration adds three
nullable columns + an index on `(SourceKind, SourceRef)`.

### A2. Close the `PoamDeadlineDays` gap (ADR 0010 §9)

`PolicyLayer.PoamDeadlineDays` (per-severity days) is merged today but never applied
when a POA&M is created. Extend `PoamService.CreateAsync` so that, when
`ScheduledCompletionDate` is null and a resolved deadline exists for the item's
severity, it stamps `CreatedAt + days`. This makes mandate-generated POA&Ms actually
get their dated window (and the existing `poamPastDue` gate then bites on them). Pure
addition; existing callers that pass an explicit date are unaffected.

### A3. `ConformancePayloadDto` + `ConformanceFinding` gain maturity/mandate fields (ADR 0010 §6)

The conformance wire contract (`Application/Compliance/ConformanceIngest.cs`) and the
stored `ConformanceFinding` are the derivation output ztt consumes. Add, additively
(nulls dropped on the wire; a plain 800-53 conformance event carries none of these):

```jsonc
// ConformancePayloadDto additions (camelCase on the wire)
"ztPillar":   "Identity",              // one of the 5 ZTMM pillars
"ztFunction": "Authentication",        // a function within the pillar
"ztStage":    2,                       // 1-4, the stage the ADR/decision represents (emitted at rule-gen)
"mandateId":  "encrypt-in-transit"     // present instead of the zt* trio for a binary mandate rule
```

Stored as four nullable columns on `ConformanceFinding` (`ZtPillar`, `ZtFunction`,
`ZtStage int?`, `MandateId`; strings ≤128, `jsonb` not needed — scalars). A conformance
event is a *maturity* signal when the zt-trio is present, a *mandate* signal when
`mandateId` is present, and a plain control signal when neither is (today's behavior).
`ztStage` is the decision's stage (orthogonal to the verdict/grade), exactly as ADR
0010 §6 requires. No change to the freeze logic — these ride the same frozen record.

> Note: the governed repo's `adr-rules.json` (where a frontier model writes these
> fields) is out of scope here (ADR 0006); we own the **ingest contract** it targets.

---

## Part B — tamp-ztt persistence

### B1. `MaturityModelCatalog` (the ZTMM structure) — parallels `ControlCatalog`

```csharp
public sealed class MaturityModelCatalog {
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }        // "CISA ZTMM"
    public required string Version { get; set; }      // "2.0"
    public required string Source { get; set; }       // "CISA, April 2023"
    public string? ImportedSha { get; set; }
    public bool IsSeeded { get; set; }
    public bool IsCurrent { get; set; }               // sparse-unique: at most one current
    public DateTimeOffset ImportedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<ZtPillar> Pillars { get; set; } = []; // jsonb
}
// jsonb value types
public sealed class ZtPillar   { public required string Id; public required string Name;
                                 public List<ZtFunctionDef> Functions = []; }
public sealed class ZtFunctionDef { public required string Id; public required string Name;
                                    public bool CrossCutting;   // V&A / Automation / Governance folded per-pillar
                                    public List<ZtStageDescriptor> Stages = []; } // owner-language descriptors
public sealed class ZtStageDescriptor { public int Stage; public required string Descriptor; } // 1-4
```

Seeded from a committed `Content/ztmm/ztmm-2.0.json`, refreshed by content hash,
prior versions retained — the OSCAL-catalog lifecycle. Stages carry **owner-language**
descriptors (the interview-as-translation layer, brief §11): the stage mapping hides
in the model, the question the owner sees is concrete.

### B2. `ZtSystem` — the scored unit (ADR 0010 §1)

```csharp
public sealed class ZtSystem {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ClientId { get; set; }              // inherits the client's MaturityModel assignment
    public Guid? ProjectId { get; set; }            // optional: repo-backed consumer system → build/conformance evidence
    public required string Name { get; set; }
    public string? CsamId { get; set; }             // the external CSAM inventory id
    public string? SystemKind { get; set; }         // free-form: "app" | "data-center" | "network" | "cluster" | "db-farm"
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
```

Unique `(ClientId, Name)`; FK `ClientId` cascade, `ProjectId` set-null; index on
`ProjectId`. A `ZtSystem` with no `ProjectId` is an infra system — no derived
evidence, every function floors at 1.

Additive columns on `Client` (ADR 0010 §3, §5):
```csharp
public Guid? MaturityModelId { get; set; }        // ZTMM opt-in, distinct from the singular FrameworkId
public int? ZtAttestationExpiryDays { get; set; }  // per-client attestation cadence (decided 2026-09-28)
public string? ZtAttestationRequirement { get; set; } // per-client: what evidence an attestation must carry
```
The attestation *requirement* (a statement is always mandatory; what else must be
attached) and the *expiry cadence* are **set per client**, not globally. An edge's
`ExpiresAt` is derived as `AttestedAt + Client.ZtAttestationExpiryDays`.

### B3. Enterprise offering registry (ADR 0010 §2, §5)

```csharp
public sealed class EnterpriseOffering {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ClientId { get; set; }              // offerings are ALWAYS client-scoped (decided 2026-09-28)
    public required string ServiceLevelId { get; set; } // admin's free-form id, e.g. "splunk-premium"
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<OfferingFunctionScore> FunctionScores { get; set; } = []; // jsonb
}
public sealed class OfferingFunctionScore { public required string Pillar; public required string Function;
                                            public int Stage; /* 1-4, the cap that flows downhill */ }
```

Scored once; N systems inherit. Tiers/variants of one tool = separate offerings.
Unique `(ClientId, ServiceLevelId)`.

### B4. Inheritance edge + attestation (ADR 0010 §5)

```csharp
public sealed class ZtInheritanceEdge {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SystemId { get; set; }              // → ZtSystem
    public Guid OfferingId { get; set; }            // → EnterpriseOffering
    public required string Pillar { get; set; }
    public required string Function { get; set; }    // the function inherited on this edge
    // attestation: edge-attested requires a Statement (always) + evidence meeting the
    // client's requirement, unexpired; otherwise edge-committed.
    public string? AttesterName { get; set; }
    public string? AttesterLogin { get; set; }
    public string? Statement { get; set; }           // MANDATORY for edge-attested
    public string? EvidenceRef { get; set; }         // uploaded artifact ref / URL / email id
    public DateTimeOffset? AttestedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }    // = AttestedAt + Client.ZtAttestationExpiryDays; stale ⇒ degrades to edge-committed
    public Guid AuthorUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
```

Unique `(SystemId, Pillar, Function)` — one inheritance source per function per system.
Frozen/append-only is *not* required here (an edge is editable state, not evidence),
but each mutation writes an audit entry. Attestation *evidence artifacts* upload
through the existing asset/attachment path.

### B5. Owner picks — the N/A disposition (ADR 0010 §4, brief §5)

```csharp
public sealed class ZtSystemPick {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SystemId { get; set; }
    public required string Pillar { get; set; }
    public required string Function { get; set; }
    public ZtPickKind Kind { get; set; }             // NotApplicable | Committed
    public string? Justification { get; set; }        // required for NotApplicable (role declaration)
    public Guid AuthorUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
public enum ZtPickKind { NotApplicable = 0, Committed = 1 }
```

Unique `(SystemId, Pillar, Function)`. `NotApplicable` removes the function from the
denominator; it is the *correct* home for what a naive questionnaire encodes as a
bogus "option 5 = headless/no-auth" top-of-scale (brief §3, §17-strip).

### B6. Mandate policy pack + results (ADR 0010 §7)

The **mandate definitions** are a policy pack (admin/policy-defined, versioned),
crosswalked from EO directives (ADR 0011 §5). Stored as a versioned pack:

```csharp
public sealed class MandatePack {
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Version { get; set; }      // pin stamped onto every result + POA&M
    public bool IsCurrent { get; set; }               // sparse-unique
    public bool IsSeeded { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public List<MandateDefinition> Mandates { get; set; } = []; // jsonb
}
public sealed class MandateDefinition {
    public required string MandateId;                 // "encrypt-at-rest"
    public required string Title;
    public MandateTool Tool;                          // Findings (supply-chain) | Ztt (operational)
    public string? ApplicabilityRule;                 // e.g. "has-network-surface" → drives where-applicable N/A
    public string? DerivationRuleRef;                 // maps to the conformance rule / gate that proves it
    public Severity PoamSeverity;                     // → shared severity→window table
    public string? SourceDirectiveId;                 // crosswalk back to the EO directive (ADR 0011)
}
public enum MandateTool { Findings = 0, Ztt = 1 }
```

**Mandate results** are stored separately from maturity evidence to keep the two axes
apart (ADR 0010 §7). Rather than a new table, a mandate result is a `ConformanceFinding`
carrying `MandateId` (A3): its four-valued verdict maps `pass`→met, `fail`/contradiction
→POA&M, `unknown`→blocks. This reuses the frozen-evidence + build-attach machinery
whole; the mandate roll-up is a query over `ConformanceFinding` where `MandateId != null`.

### B7. Derivation — pure Domain, no new tables

* `ZtDispositionResolver` (Domain/Compliance) — `Resolve(system, maturityEvidence,
  edges, picks, model, asOf)` → per-function `ZtDisposition` (owned verified/committed/
  contradicted · inherited edge-attested/edge-committed · not-applicable · undetermined→1),
  applying the default rule + N/A guard + attestation-expiry degrade. Mirrors
  `ControlDispositionResolver`.
* `ZtmmScoringContract` (Domain/Risk) — the **single pinned** aggregation. **Pinned
  math (decided 2026-09-28): equal weights — every function weighs equally inside its
  pillar.** So a pillar score is the arithmetic **mean of its function stages**,
  including the cross-cutting functions folded into that pillar (they weigh the same
  as any other function). An inherited function's stage is **min-capped at the
  provider** before it enters the mean; `not-applicable` functions are **excluded from
  the denominator**; `undetermined` counts as its floor of 1. Pure/deterministic like
  `GateEvaluator`. Roll-up walks the graph (systems + offerings + edges); the portfolio
  view uses the same equal-weight principle across systems, with provider-leverage
  ranking layered on top (which provider lifts the most consumers).
* Mandate roll-up is a **count + POA&M list**, computed separately, never averaged in.

### B8. The findings ↔ ztt boundary — findings owns all data; ztt is analysis-only

**Decided 2026-09-28: tamp.findings is the system of record for everything; tamp-ztt
is a stateless analyzer.** ztt holds no store, no UI-of-record. It *consumes the rules
findings serves*, runs its scan/analysis over the repo + ADRs, and *posts results
back* — exactly the tamp-conformance pattern (consume compliance-profile → produce
conformance events). Three surfaces:

| Surface | Direction | Auth | Purpose |
|---|---|---|---|
| **`GET /projects/self/zt-profile`** | findings → ztt | ingest-token (`prj_`) | **serves ztt its rules**: the current ZTMM model (pillars/functions/stage descriptors), the applicable operational **mandate definitions + derivation rules**, and the crosswalk. The ZT analogue of `/projects/self/compliance-profile`. |
| **`POST /ingest/conformance`** | ztt → findings | ingest-token | ztt posts results as conformance events carrying `ztPillar/ztFunction/ztStage` (maturity) or `mandateId` (operational mandate). **No new ingest endpoint** — A3 covers the fields; commit-sha build-attach unchanged. |
| **`POST /zt/systems` (+ registry CRUD)** | human → findings | cookie-authed admin (ADR 0002) | systems, offerings, offering scores, inheritance edges, N/A picks. **Human config, never token ingest** — an edge attestation must be created by a signed-in accountable party (ADR 0010 §5), never an anonymous token. |

So: rules and results both live in findings; ztt scans and reports; the derive-on-read
resolver (B7) combines ztt's posted results with the human-entered picks/edges. The
**supply-chain** mandates are produced by findings itself from build ingest it already
receives; the **operational** mandates + maturity are produced by ztt — but every
definition and every result is stored here. The crosswalk `Target` (Findings | Ztt)
names *which analyzer* produces a result, not which store holds it (all results are
`ConformanceFinding` rows here).

---

## Part C — tamp-EOProvenance persistence

### C1. `Instrument` + `InstrumentRelation` (ADR 0011 §2)

```csharp
public sealed class Instrument {
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Identifier { get; set; }   // "EO 14028", "M-22-09"
    public required string Title { get; set; }
    public InstrumentType Type { get; set; }          // ExecutiveOrder | OmbMemo | Nsm | PresidentialMemo
    public string? IssuingAuthority { get; set; }
    public DateTimeOffset IssueDate { get; set; }
    public string? PublicationCite { get; set; }       // Federal Register cite
    public string? SourceHash { get; set; }            // hash of canonical text (staleness-fails-closed)
    public string? ExtractionModelId { get; set; }
    public ReviewStatus ReviewStatus { get; set; }     // Draft | Reviewed
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
public enum InstrumentType { ExecutiveOrder = 0, OmbMemo = 1, Nsm = 2, PresidentialMemo = 3 }
public enum ReviewStatus { Draft = 0, Reviewed = 1 }

public sealed class InstrumentRelation {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid FromInstrumentId { get; set; }
    public Guid ToInstrumentId { get; set; }
    public InstrumentRelationType Type { get; set; }   // Amends | Revokes | Supersedes | Implements
    public string? FromSection { get; set; }
    public string? ToSection { get; set; }
}
public enum InstrumentRelationType { Amends = 0, Revokes = 1, Supersedes = 2, Implements = 3 }
```

Unique `Identifier`; relation indexes on both endpoints so the authority graph is
walkable in either direction.

### C2. `Directive` + effective-dated status (ADR 0011 §3, §4)

```csharp
public sealed class Directive {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid InstrumentId { get; set; }
    public string? Section { get; set; }
    public required string Who { get; set; }           // agency / role
    public required string MustDo { get; set; }
    public DirectiveType Type { get; set; }            // SelfExecutingDated | Delegation | Aspirational (aspirational never stored - dropped)
    public DirectiveApplicability Applicability { get; set; } // AllSystems | NationalSecuritySystems | WhereApplicable
    // date anchoring
    public ByWhenKind ByWhenKind { get; set; }         // Absolute | Relative | Pending
    public DateTimeOffset? AbsoluteDate { get; set; }
    public int? RelativeOffsetDays { get; set; }
    public AnchorKind? AnchorKind { get; set; }         // SigningDate | PredicateMemoIssue
    public Guid? AnchorInstrumentId { get; set; }
    public DateTimeOffset? ResolvedDate { get; set; }   // computed when the anchor lands
    // provenance
    public string? SourceHash { get; set; }
    public string? ExtractionModelId { get; set; }
    public ReviewStatus ReviewStatus { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
public enum DirectiveType { SelfExecutingDated = 0, Delegation = 1 } // aspirational dropped at extraction
public enum DirectiveApplicability { AllSystems = 0, NationalSecuritySystems = 1, WhereApplicable = 2 }
public enum ByWhenKind { Absolute = 0, Relative = 1, Pending = 2 }
public enum AnchorKind { SigningDate = 0, PredicateMemoIssue = 1 }

// append-only, never mutated/deleted; hooks GuardAuditTrail immutability
public sealed class DirectiveStatusChange {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DirectiveId { get; set; }
    public DirectiveStatus Status { get; set; }         // Active | Rescinded | Superseded
    public DateTimeOffset EffectiveDate { get; set; }
    public Guid? CausedByInstrumentId { get; set; }     // the amending/revoking instrument
    public DateTimeOffset RecordedAt { get; set; } = DateTimeOffset.UtcNow;
}
public enum DirectiveStatus { Active = 0, Rescinded = 1, Superseded = 2 }
```

A directive's status **as of a date** = the latest `DirectiveStatusChange` with
`EffectiveDate <= asOf`. Point-in-time is that one query. Index
`(DirectiveId, EffectiveDate)`.

### C3. Crosswalk (ADR 0011 §5)

```csharp
public sealed class DirectiveCrosswalk {
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DirectiveId { get; set; }
    public MandateTool Target { get; set; }            // Findings | Ztt (partition, reused from B6)
    public required string TargetRef { get; set; }      // mandate id / gate key / conformance rule id
}
```

The partition invariant (no mandate double-scored or dropped) is enforced at
crosswalk write: a `TargetRef` may be claimed by at most one directive per tool.

### C4. The committed `eo-directives` corpus + seeding (ADR 0011 §6)

A committed artifact `Content/eo/eo-directives.json` (the lockfile analogue), seeded on
startup by content hash exactly like `Content/oscal/catalog.json`:

```jsonc
{
  "version": "2026-09-28",
  "instruments": [ { "identifier": "EO 14028", "title": "...", "type": "ExecutiveOrder",
                     "issueDate": "2021-05-12", "cite": "...", "relations": [
                       { "type": "Implements", "to": "M-22-09" } ] } ],
  "directives": [ { "instrument": "M-22-09", "section": "...", "who": "agencies",
                    "mustDo": "encrypt in transit", "type": "SelfExecutingDated",
                    "applicability": "AllSystems",
                    "byWhen": { "kind": "Absolute", "date": "2024-09-30" },
                    "crosswalk": { "target": "Ztt", "ref": "encrypt-in-transit" } } ]
}
```

Startup: hash the file; if changed, run the ingestion pipeline (C5) idempotently.
Source-hash drift without a regenerated corpus fails closed (the instrument's
`ReviewStatus` stays `Draft` and its directives don't go `Active`).

### C5. Ingestion pipeline (ADR 0011 §6) — application services, not a token endpoint

EO ingestion is a **centralized, reviewed** process, not per-repo tool traffic, so it
runs as an application pipeline over the committed corpus (plus an optional
cookie-authed admin `POST /eo/instruments` for manual entry), never through
`IngestAuthFilter`:

1. `EoCorpusSeeder` (startup) — upsert instruments + relations from the corpus.
2. `EoDirectiveExtractor` conceptually = conformance Capability-1 (runs in the
   `tamp-EOProvenance` tool, offline); findings ingests its reviewed output.
3. `EoAmendmentDiffer` — on a new/changed instrument, walk its `Revokes`/`Supersedes`
   relations, write `DirectiveStatusChange(Rescinded, effective = amending issue date)`
   onto affected directives, mark crosswalked checks dormant.
4. `EoDateAnchorResolver` — resolve `Relative` directives whose anchor has landed;
   leave the rest `Pending`.
5. Human review gate — a directive is `Active` only once `ReviewStatus = Reviewed`.

---

## Part D — Migration plan (ordered, one concern each)

Following the repo's one-migration-per-concern pattern (most recent:
`20260928200106_AddComponentProfile`), applied on startup via `db.Database.Migrate()`:

1. `AddPoamSource` — `PoamItem.SourceKind/SourceRef/MandatePackVersion` + index (A1).
2. `AddConformanceMaturityFields` — `ConformanceFinding.ZtPillar/ZtFunction/ZtStage/MandateId` (A3).
3. `AddMaturityModelCatalog` — `MaturityModelCatalog` + `Client.MaturityModelId` (B1, B2).
4. `AddZtSystems` — `ZtSystem` (B2).
5. `AddEnterpriseOfferings` — `EnterpriseOffering` (B3).
6. `AddZtEdgesAndPicks` — `ZtInheritanceEdge`, `ZtSystemPick` (B4, B5).
7. `AddMandatePack` — `MandatePack` (B6).
8. `AddEoInstruments` — `Instrument`, `InstrumentRelation` (C1).
9. `AddEoDirectives` — `Directive`, `DirectiveStatusChange`, `DirectiveCrosswalk` (C2, C3).

Each is additive; none touches existing columns except the three additive `PoamItem`
columns and the four additive `ConformanceFinding` columns. No data backfill needed
(all new nullable/defaulted). Seed content (`Content/ztmm/`, `Content/eo/`) ships and
hash-seeds on startup like `Content/oscal/`.

---

## Part E — Data flow (end to end)

```
governed repo CI ──(conformance events, now carrying ztPillar/ztFunction/ztStage or mandateId)──▶
   POST /ingest/conformance ──▶ ConformanceFinding (frozen, build-attached by commitSha)
                                        │
tamp-EOProvenance tool ──(reviewed eo-directives.json)──▶ Content/eo/ ──startup seed──▶
   Instrument / Directive / StatusChange / Crosswalk ──defines──▶ MandatePack (current)
                                        │
admin (cookie-authed) ──▶ ZtSystem · EnterpriseOffering · OfferingFunctionScore · InheritanceEdge · ZtSystemPick
                                        │
                                        ▼
   ZtDispositionResolver + ZtmmScoringContract  (pure, derive-on-read)
        maturity gauge (stages, floor 1, N/A off denominator, min-cap inheritance)
        mandate results (ConformanceFinding where MandateId != null → pass/fail/unknown)
                                        │
                                        ▼
   fail / contradiction / unproven mandate ──▶ PoamService.CreateAsync
        (SourceKind = OperationalMandate/ZtContradiction, SourceRef, MandatePackVersion,
         ScheduledCompletionDate from PoamDeadlineDays)  ──▶ one shared POA&M model
```

---

## Part F — Open questions (with proposed defaults, for your call)

1. ~~`ZtSystem` vs Project.~~ **RESOLVED: dedicated `ZtSystem` with optional `ProjectId`** (ADR 0010 §1).
2. ~~ZTMM assignment axis.~~ **RESOLVED: `Client.MaturityModelId`, separate from the singular `FrameworkId`.**
3. ~~Scoring-contract weights + fold rule.~~ **RESOLVED (2026-09-28): equal weights —
   every function weighs equally inside its pillar; pillar = mean of function stages
   (cross-cutting folded in at the same weight); min-cap inherited; N/A off the
   denominator; undetermined = 1.** See B7.
4. ~~Offering scope.~~ **RESOLVED: `EnterpriseOffering.ClientId` REQUIRED — offerings are always client-scoped.**
5. ~~Attestation evidence + expiry.~~ **RESOLVED: a statement is always mandatory; the
   evidence requirement and the expiry cadence are set PER CLIENT** (`Client.ZtAttestationRequirement`,
   `Client.ZtAttestationExpiryDays`), not a global default. See B2/B4.
6. ~~Mandate results storage.~~ **RESOLVED: reuse `ConformanceFinding` + `MandateId`** (one frozen-evidence path).
7. ~~EO ingestion surface.~~ **RESOLVED: startup corpus seed + cookie-authed admin entry, no ingest-token endpoint.**
8. ~~Crosswalk partition.~~ **RESOLVED (boundary): findings is the system of record for
   ALL data (all mandate definitions AND all results). ztt is analysis-only — it
   consumes rules from findings (`GET /projects/self/zt-profile`), scans, and posts
   results back (`POST /ingest/conformance`).** The analysis split: findings produces
   supply-chain mandate results from build ingest; ztt produces operational (encryption,
   MFA, IPv6) + maturity results. Still to do: **sync the exact operational-mandate list
   with the `tamp` agent** so nothing is double-scored or dropped (the crosswalk
   `Target` names the analyzer, not the store).
9. ~~Cost apparatus~~ **RESOLVED (2026-09-28): NO cost columns.** The Estimated Cost /
   Type of Funds / Budget Execution / Completion Date apparatus is dropped entirely —
   not added to `PoamItem`.
