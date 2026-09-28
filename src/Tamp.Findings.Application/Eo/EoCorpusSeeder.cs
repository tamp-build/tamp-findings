using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Eo;

// Ingests the committed eo-directives corpus into the registry (ADR 0011 §6). Runs the
// pipeline the brief specifies: upsert instruments + the authority graph, decompose to
// directives, resolve dates (§4 date-anchor), initialize the effective-dated status,
// and apply the amendment-diff (§4/§5). Idempotent — safe to run on every startup:
// entities upsert by natural key, and append-only status changes are only ever ADDED
// when the corresponding dated change is missing (never mutated — that path is guarded
// in FindingsDbContext). Only Reviewed directives enter the in-force set (fail-closed).
public static class EoCorpusSeeder
{
    public static async Task SeedAsync(FindingsDbContext db, EoCorpus corpus, CancellationToken ct = default)
    {
        // ── 1. Instruments (upsert by Identifier) ──
        var existingInstruments = await db.Instruments.ToListAsync(ct);
        var byIdentifier = existingInstruments.ToDictionary(i => i.Identifier, StringComparer.OrdinalIgnoreCase);

        foreach (var ci in corpus.Instruments)
        {
            if (!byIdentifier.TryGetValue(ci.Identifier, out var inst))
            {
                inst = new Instrument { Identifier = ci.Identifier, Title = ci.Title };
                db.Instruments.Add(inst);
                byIdentifier[ci.Identifier] = inst;
            }
            inst.Title = ci.Title;
            inst.Type = ParseEnum(ci.Type, InstrumentType.ExecutiveOrder);
            inst.IssuingAuthority = ci.Authority;
            // Postgres timestamptz stores instants (offset 0); corpus dates parse with a
            // local offset, so normalize to UTC. The instant is preserved.
            inst.IssueDate = ci.IssueDate.ToUniversalTime();
            inst.PublicationCite = ci.Cite;
            inst.ReviewStatus = ParseEnum(ci.ReviewStatus, ReviewStatus.Draft);
        }
        // Persist so instrument ids exist for relations/directives/status FKs.
        await db.SaveChangesAsync(ct);

        // ── 2. Authority graph (upsert relations by From/To/Type) ──
        var existingRelations = await db.InstrumentRelations.ToListAsync(ct);
        foreach (var ci in corpus.Instruments)
        {
            if (!byIdentifier.TryGetValue(ci.Identifier, out var from)) continue;
            foreach (var rel in ci.Relations)
            {
                if (!byIdentifier.TryGetValue(rel.To, out var to)) continue; // target not in corpus yet
                var type = ParseEnum(rel.Type, InstrumentRelationType.Amends);
                var exists = existingRelations.Any(r =>
                    r.FromInstrumentId == from.Id && r.ToInstrumentId == to.Id && r.Type == type);
                if (!exists)
                    db.InstrumentRelations.Add(new InstrumentRelation
                    {
                        FromInstrumentId = from.Id, ToInstrumentId = to.Id, Type = type,
                        FromSection = rel.FromSection, ToSection = rel.ToSection,
                    });
            }
        }

        // ── 3. Directives (upsert by Ref) + date-anchor resolution ──
        var existingDirectives = await db.Directives.ToListAsync(ct);
        var byRef = existingDirectives.ToDictionary(d => d.Ref, StringComparer.OrdinalIgnoreCase);

        foreach (var cd in corpus.Directives)
        {
            if (!byIdentifier.TryGetValue(cd.Instrument, out var owner)) continue; // orphan directive
            if (!byRef.TryGetValue(cd.Ref, out var dir))
            {
                dir = new Directive { Ref = cd.Ref, Who = cd.Who, MustDo = cd.MustDo, InstrumentId = owner.Id };
                db.Directives.Add(dir);
                byRef[cd.Ref] = dir;
            }
            dir.InstrumentId = owner.Id;
            dir.Section = cd.Section;
            dir.Who = cd.Who;
            dir.MustDo = cd.MustDo;
            dir.Type = ParseEnum(cd.Type, DirectiveType.SelfExecutingDated);
            dir.Applicability = ParseEnum(cd.Applicability, DirectiveApplicability.AllSystems);
            dir.ReviewStatus = ParseEnum(cd.ReviewStatus, ReviewStatus.Draft);
            ResolveDates(dir, cd.ByWhen, owner, byIdentifier);
        }
        await db.SaveChangesAsync(ct);

        // ── 4. Crosswalks (upsert by (Target, TargetRef)) ──
        var existingCrosswalks = await db.DirectiveCrosswalks.ToListAsync(ct);
        foreach (var cd in corpus.Directives)
        {
            if (cd.Crosswalk is not { } cx) continue;
            if (!byRef.TryGetValue(cd.Ref, out var dir)) continue;
            var target = ParseEnum(cx.Target, MandateTool.Ztt);
            var exists = existingCrosswalks.Any(c => c.Target == target
                && string.Equals(c.TargetRef, cx.Ref, StringComparison.OrdinalIgnoreCase));
            if (!exists)
                db.DirectiveCrosswalks.Add(new DirectiveCrosswalk
                {
                    DirectiveId = dir.Id, Target = target, TargetRef = cx.Ref,
                });
        }

        // ── 5. Initialize status: a Reviewed directive is Active from its instrument's
        //       issue date (the obligation exists once the instrument issues; the by-when
        //       is a separate deadline). Draft directives stay out of the in-force set.
        var statusChanges = await db.DirectiveStatusChanges.ToListAsync(ct);
        var changesByDirective = statusChanges.GroupBy(s => s.DirectiveId)
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var cd in corpus.Directives)
        {
            if (!byRef.TryGetValue(cd.Ref, out var dir)) continue;
            if (dir.ReviewStatus != ReviewStatus.Reviewed) continue;
            if (!byIdentifier.TryGetValue(cd.Instrument, out var owner)) continue;
            var existing = changesByDirective.GetValueOrDefault(dir.Id) ?? [];
            if (existing.All(s => s.Status != DirectiveStatus.Active))
                db.DirectiveStatusChanges.Add(new DirectiveStatusChange
                {
                    DirectiveId = dir.Id, Status = DirectiveStatus.Active,
                    EffectiveDate = owner.IssueDate, CausedByInstrumentId = owner.Id,
                });
        }

        // ── 6. Amendment-diff: write forward-dated rescissions (§4). Idempotent — only
        //       add a Rescinded change if none exists at that effective date already.
        foreach (var resc in corpus.Rescissions)
        {
            byIdentifier.TryGetValue(resc.ByInstrument, out var cause);
            foreach (var dref in resc.Directives)
            {
                if (!byRef.TryGetValue(dref, out var dir)) continue;
                var existing = changesByDirective.GetValueOrDefault(dir.Id) ?? [];
                var effective = resc.EffectiveDate.ToUniversalTime();
                var already = existing.Any(s => s.Status == DirectiveStatus.Rescinded
                    && s.EffectiveDate == effective);
                if (!already)
                    db.DirectiveStatusChanges.Add(new DirectiveStatusChange
                    {
                        DirectiveId = dir.Id, Status = DirectiveStatus.Rescinded,
                        EffectiveDate = resc.EffectiveDate.ToUniversalTime(), CausedByInstrumentId = cause?.Id,
                    });
            }
        }

        await db.SaveChangesAsync(ct);
    }

    // Date-anchoring (ADR 0011 §4). Absolute → as-is. Relative → anchor date + offset,
    // where the anchor is the owning instrument's signing date or a predicate memo's
    // issue date; if the predicate is not yet in the corpus (not issued), the directive
    // is left Pending with no resolved date.
    private static void ResolveDates(
        Directive dir, EoCorpusByWhen? byWhen, Instrument owner,
        Dictionary<string, Instrument> byIdentifier)
    {
        if (byWhen is null) { dir.ByWhenKind = ByWhenKind.Pending; return; }

        var kind = ParseEnum(byWhen.Kind, ByWhenKind.Pending);
        switch (kind)
        {
            case ByWhenKind.Absolute:
                dir.ByWhenKind = ByWhenKind.Absolute;
                dir.AbsoluteDate = byWhen.Date?.ToUniversalTime();
                dir.ResolvedDate = byWhen.Date?.ToUniversalTime();
                break;

            case ByWhenKind.Relative:
                dir.ByWhenKind = ByWhenKind.Relative;
                dir.RelativeOffsetDays = byWhen.OffsetDays;
                dir.AnchorKind = ParseEnum(byWhen.Anchor, AnchorKind.SigningDate);
                if (dir.AnchorKind == AnchorKind.SigningDate)
                {
                    dir.AnchorInstrumentId = owner.Id;
                    dir.ResolvedDate = owner.IssueDate.AddDays(byWhen.OffsetDays ?? 0);
                }
                else if (byWhen.AnchorInstrument is { } anchorId
                         && byIdentifier.TryGetValue(anchorId, out var anchor))
                {
                    dir.AnchorInstrumentId = anchor.Id;
                    dir.ResolvedDate = anchor.IssueDate.AddDays(byWhen.OffsetDays ?? 0);
                }
                else
                {
                    // Anchor event has not occurred (predicate memo not issued) → Pending.
                    dir.ByWhenKind = ByWhenKind.Pending;
                    dir.ResolvedDate = null;
                }
                break;

            default:
                dir.ByWhenKind = ByWhenKind.Pending;
                dir.ResolvedDate = null;
                break;
        }
    }

    private static TEnum ParseEnum<TEnum>(string? value, TEnum fallback) where TEnum : struct
        => Enum.TryParse<TEnum>(value, ignoreCase: true, out var v) ? v : fallback;
}
