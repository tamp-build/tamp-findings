# ADR 0016: Scan cost — the producer sends tokens, findings owns the dated price

* Status: Accepted
* Date: 2026-09-30
* Deciders: scott
* Tracking: TFND-204

## Context and Problem Statement

Conformance scanning runs LLMs, and an LLM scan costs money — tokens × a per-model price. Teams want
per-project visibility into what their scanning costs. The producer (tamp-conformance) is the only
party that knows the *fact* of a scan: how many tokens it burned, on which model, at what latency. But
the *price* of a token is not a fact the producer should assert — prices change, differ by contract,
and get corrected after the fact. If the producer computed and sent a dollar figure, that number would
be frozen at ingest, wrong the moment a price was corrected, and un-auditable (whose price list?).

There is also a modelling question: is scan cost part of the scan's *evidence* (the SBOM, the
findings, the verdicts), or something else? Folding a dollar cost into the conformance evidence would
conflate two questions an auditor keeps separate — "is the code compliant" and "what did checking it
cost."

## Decision

**Split the fact from the policy. The producer emits the fact (tokens); findings owns the policy (the
dated price) and computes cost at read time.**

1. **Usage is a fact the producer sends.** `POST /ingest/scan-usage` takes, per build,
   `ScanUsageObservation`s — `{adapter, modelId, provider, capability, inputTokens, outputTokens,
   latencyMs, observedAt}`. Replace-on-ingest per build. **No cost is sent.** The producer maps its
   adapters' native usage fields (Anthropic/Bedrock `usage.{input,output}_tokens`, OpenAI-compatible
   `usage.{prompt,completion}_tokens`) onto input/output tokens.

2. **Price is policy findings owns — and it is dated.** A `ModelPrice` table holds per-model USD-per-
   million-token prices, each with an `EffectiveFrom`. A price change is a **new dated row**, never an
   edit in place, so the history a scan was costed against is preserved.

3. **Cost is computed at read time, against the price in effect when the scan ran.** `ScanCostQuery`
   prices each observation with the newest `ModelPrice` whose `EffectiveFrom ≤ observedAt`. So a
   pricing correction (or a newly-added model price) **re-flows through every historical scan's cost
   without re-ingesting** — the producer never has to resend to fix a price.

4. **An unpriced model is surfaced, never silently zero.** A model findings has no price row for is
   reported (`UnpricedModels`) with its cost understated-and-flagged, not hidden as $0 — the same
   "absence is not a clean zero" honesty the gates apply.

5. **Cost is evidence ABOUT the scan, kept separate from the scan's verdicts.** `ScanUsageObservation`
   is its own entity, not a field on the conformance evidence — "what did checking it cost" does not
   live inside "is the code compliant."

## Consequences

* **A price fix is a one-place, retroactive change.** Correct the table (add a dated row) and every
  affected project's historical cost updates on next read — no producer coordination, no re-ingest.
* **The producer stays simple and price-agnostic.** tamp-conformance forwards token counts it already
  has; it never carries a price list or currency logic. This is the same fact/policy division as the
  rest of the platform (the producer reports what it found; findings owns the policy that scores it).
* **Cost visibility is per project today** (the Costs page's "Scan cost" section: tokens + $ by model,
  builds), and can extend to per-build / per-adapter / org roll-ups from the same observations without
  a schema change.
* **Seed prices are approximate and admin-owned.** Findings ships a seed price list so the feature
  works on day one; the numbers are a starting point an operator corrects, exactly like the
  paid-component registry — an upgrade never overwrites a price someone recorded.
* The producer-side emit (a core `cost.observed` / `usage.observed` event feeding this endpoint) is
  scheduled independently; the findings sink does not depend on it to exist.
