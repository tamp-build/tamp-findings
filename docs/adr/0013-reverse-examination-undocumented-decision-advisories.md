# ADR 0013: Reverse-examination — undocumented-decision advisories as CM-3 evidence

* Status: Proposed
* Date: 2026-09-28
* Deciders: scott
* Tracking: TFND-197
* Companion: [0006](0006-adr-conformance-as-evidence-and-frozen-non-pure-verdicts.md) (conformance verdicts — the forward direction), [0012](0012-findings-as-the-authoritative-conformance-rules-store.md) (the rules store)

## Context and Problem Statement

ADR 0006 established **conformance**: does the code still honour what an ADR *decided*? That
is the forward direction — code checked **against** an ADR. tamp-conformance also has an
**inverse** capability, *reverse-examination*: what architectural decisions did the code make
that **no ADR records**? A new dependency, a new endpoint, a new trust boundary — each is a
decision, and an undocumented one is a change-control gap (NIST SP 800-53 **CM-3**, "the code
changed but the decision record didn't").

tamp (the producer) wanted to run reverse-examination against a governed repo and land the
results in findings as governance evidence. But the conformance ingest (`/ingest/conformance`)
keeps only `conformance.evaluated` events and drops everything else, so reverse-examination's
output — emitted as `diagnostic.emitted` notes — would be silently discarded. We needed a
decision on whether (and how) findings surfaces this new evidence class.

## Decision

Ingest and surface reverse-examination output as a distinct, **advisory-only** evidence type.

1. **Wire (producer → findings).** Reverse-examination rides the canonical BuildEvent stream as
   `diagnostic.emitted` events (SARIF level `note`) whose payload `ruleId` is
   `undocumented-decision:<kind>` (e.g. `undocumented-decision:new-dependency`). Payload carries
   `message` (the decision summary), `location {file, line}`, and `provenance {commitSha}`.
2. **Distinct ingest surface.** A dedicated `POST /ingest/diagnostics` endpoint (cli_/prj_
   Bearer, same auth as conformance) — separate from `/ingest/conformance` so the advisory
   counts never muddy the conformance verdict counts. It is lenient: the producer may fire-hose
   the whole stream; findings keeps only the `undocumented-decision:` notes.
3. **Distinct entity.** `DecisionDiagnostic` — binds to a build by `provenance.commitSha`
   (resolved to a ComponentVersion under the token's project(s), exactly like conformance),
   upserts by `(build, ruleId, location)`, frozen at the commit it was detected against.
   Defaults its `ControlRefs` to `CM-3`.
4. **Advisory, always.** A decision diagnostic carries **no verdict**, **never gates a build**,
   and **never raises a POA&M**. The remedy is "write an ADR" (or, if the decision isn't
   material, nothing — the examiner abstains generously; empty is the common, correct answer).
5. **Surface.** A read-only per-project page (`/c/{}/p/{}/decisions`, under the Evidence nav),
   grouping the latest build's undocumented decisions by kind with file:line + summary. An
   absent report reads "not examined", never "everything is documented".

## Consequences

* **Governance completeness.** Findings now records both directions: code-vs-ADR (conformance,
  gating) and code-with-no-ADR (reverse-examination, advisory). Together they are the CM-3
  change-control story an assessor expects.
* **No gate contamination.** Because it is a separate endpoint, entity, and surface, the
  advisory stream cannot alter a go/no-go verdict or the conformance counts. This is deliberate:
  an undocumented decision is a prompt to govern, not a defect to block on.
* **Producer-independent binding.** The commitSha binding and NDJSON/array sniffing mirror the
  conformance ingest, so any producer emitting the documented shape lands correctly; findings
  owns the transport (the event *shape* is the only shared contract).
* **Future.** If a class of undocumented decision ever needs to gate (e.g. an org policy that a
  new external dependency MUST have an ADR), that is a separate, explicit policy decision layered
  on top — it is not the default, and this ADR does not grant it.
