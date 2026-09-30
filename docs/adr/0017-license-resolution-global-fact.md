# ADR 0017: License resolution — a global fact, kept separate from the project's allow/deny position

* Status: Accepted
* Date: 2026-09-30
* Deciders: scott
* Tracking: TFND-222

## Context and Problem Statement

An SBOM does not always carry a license the classifier can recognise. Legacy NuGet `.nuspec` packages,
for example, declare a `licenseUrl` (a URL) rather than an SPDX expression, so the producer emits a
placeholder like `"Unknown - See URL"`. On tamp-core's own build, 8 of 76 components arrived that way —
every one actually permissive (MIT / Apache-2.0), but all counted as **unknown**.

Unknown licenses are not free: the license score adds `unknownPct × weight`, so an inventory that is
10% unclassifiable carries a standing risk score that no amount of scanning removes. The only way to
clear it is for a human to establish what the license actually is. That raises two questions:

1. **Where does that human judgement live?** A per-project override (like a control disposition, ADR
   0015)? Or something shared?
2. **Is "what license is this package under" the same kind of decision as "is this license acceptable
   to us"?** They feel adjacent, but conflating them would be a category error.

The existing policy stack already answers the *acceptability* question — `LicenseRules` (allow / deny /
deny-unknown) is layered per project and wins over the built-in SPDX tier table (TFND-10 / ADR 0007).
What was missing was a way to establish the *identity* of a license the SBOM failed to carry.

## Decision

**A license resolution is a fact about a package version, not a position about it. Store it once,
globally, keyed by purl — and keep it strictly separate from the project-layered allow/deny policy.**

1. **Identity is global; acceptability stays project-layered.** `System.Memory@4.5.5 IS MIT` is true
   for everyone — it is a property of the artifact, not of any consumer. So a `LicenseResolution`
   (`{Purl, Spdx, Note, ResolvedBy, ResolvedAt}`) is stored **once at the instance level, keyed by
   purl**, and every project that pulls that purl inherits it. Whether MIT (or AGPL) is *acceptable*
   remains a per-project legal position in `LicenseRules`, untouched by this. This is deliberately the
   opposite scoping from control dispositions (ADR 0015), which are per-project because a disposition
   genuinely *is* a per-project position.

2. **The resolution is a human attestation, on the record.** It carries who resolved it and when,
   writes an audit entry (`license.resolved`), and is capability-gated (`EditPolicyWeights`). It is the
   fallback for licenses a producer cannot resolve automatically — not a routine data path.

3. **The scorer and the screen read the same map.** `RiskInputsBuilder` applies the purl→SPDX map
   before `LicensePolicy.Classify`, so a resolved package classifies by its real license and stops
   costing "unknown" points. Because the hub computes the score live (not from a frozen
   ScoreSnapshot), resolving a package updates the score immediately. The license category page shows
   its own working — the score formula with this build's numbers, the policy in force, each license's
   tier, and the still-unknown worklist — all from the same applied map, so the page and the number
   cannot disagree.

4. **Resolution is the downstream safety net, not the fix.** The right place to resolve a well-known
   NuGet `licenseUrl` is the producer, before the SBOM is emitted (filed upstream as
   tamp-build/tamp#98). This mechanism exists for the genuinely-unresolvable remainder and for the
   period before the producer learns to resolve them. When the producer catches up, these rows become
   redundant but stay valid.

## Consequences

* **Resolve once, benefit everywhere.** In a monorepo ecosystem like tamp, the same `System.*` /
  `Microsoft.NETCore.*` packages recur across many projects; a global resolution clears them for all of
  them in one attestation, rather than re-litigating the same fact per project.
* **The fact/position split stays clean.** "What is this license" and "do we accept it" are answered by
  two different stores with two different scopes. An adopter who has signed off AGPL changes their
  policy's allow-list; nobody changes what AGPL *is*.
* **A resolution is auditable and reversible.** Each carries its author and time and an audit entry;
  clearing one reverts the purl to whatever its SBOM carried.
* **Authorization is coarse for now.** The write is gated on `EditPolicyWeights` at the acting
  project's client scope, even though the effect is global. That is acceptable because the resolution
  is an objective fact and is audited, but a dedicated instance-level capability (and a bulk
  resolution ingest endpoint for agents/CI, currently UI-only) are open follow-ups.
* **Same division as the rest of the platform.** The producer reports what it found; findings owns the
  policy and the human judgements layered over it — the same fact/policy split as ADR 0016 (scan cost)
  and the gate model.
