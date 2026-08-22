# ADR 0003: Reflow and the 1180px density floor

* Status: Accepted
* Date: 2026-08-22
* Deciders: scott
* Tracking: TFND-57 (under TFND-40)

## Context and Problem Statement

The redesign hand-off sets a hard floor on the application shell:

> The content wrapper has `min-width: 1180px` — this is a dense desktop tool and should scroll
> horizontally rather than collapse.

and lists *"Mobile and narrow-viewport behaviour — this design assumes a 1180px desktop floor"* under
**Not covered**.

Elsewhere the same document states:

> `--color-neutral-500` is the dimmest text token and is used at 9–10px. It measures ~5:1 on the ground;
> do not darken it. **WCAG 2.1 AA is the bar for this product — it ships an accessibility scanner.**

Both cannot hold as written. **WCAG 2.1 SC 1.4.10 Reflow** (Level AA) requires:

> Content can be presented without loss of information or functionality, and without requiring scrolling
> in two dimensions for […] vertical scrolling content at a width equivalent to 320 CSS pixels.

A wrapper with `min-width: 1180px` guarantees two-dimensional scrolling at 320px. As specified, every
screen in the product fails a Level AA success criterion.

This is not a pedantic finding. tamp.findings exists to generate federal compliance evidence, ships an
accessibility scanner (TFND-27, axe-core SARIF for Section 508), and dogfoods its own scanning. A
published AA claim that the product's own scanner would flag on every page is the kind of thing an
assessor notices first, and it undermines the evidence the product sells.

## Decision Drivers

* **The product's credibility is the actual stake.** A compliance tool that fails the standard it
  measures against is a sales problem before it is an engineering problem.
* **Section 508 references WCAG 2.1 Level AA.** For federal customers this is a procurement criterion,
  not an aspiration.
* **The density is real and load-bearing on some screens.** The source viewer, the explorer's two-pane
  tree, and the policy editor's category grid genuinely need width. Collapsing them does destroy their
  usefulness, exactly as the hand-off argues.
* **Most screens are not dense.** Tables and forms — Portfolio, POA&M, VEX, the System panels,
  sign-in — reflow with ordinary responsive technique.
* **The attestation is the deliverable.** It is what an auditor reads, and it is already capped at
  `max-width: 1080px`. It has the weakest possible claim to a 1180px floor.

## Considered Options

1. **Accept the failure; narrow the published claim** to "AA except 1.4.10, documented."
   Cheapest. Leaves the product's own scanner reporting a failure on every page, and weakens the
   conformance statement precisely where it is commercially load-bearing.
2. **Full reflow pass on every screen at 320px.** Maximum conformance. Substantial extra work, and it
   would genuinely damage the explorer and policy editor, whose two-pane density is the design.
3. **Tiered floor** — hold 1180px on the dense screens, reflow the rest. Better, but still concedes
   two pages that do not conform, and picks the boundary by intuition rather than by the standard.
4. **Apply the standard's own exception, surgically.** SC 1.4.10 ends with:

   > **Except for parts of the content which require two-dimensional layout for usage or meaning.**

   The Understanding document names data tables and code as canonical examples. So the *page* reflows;
   the specific *components* that genuinely require two-dimensional layout keep their own horizontal
   scroll, inside their own container.

## Decision

**Adopt option 4. Remove the global `min-width: 1180px`; the page body never scrolls horizontally.
Components that genuinely require two-dimensional layout scroll inside themselves, under the standard's
own exception.**

Concretely:

### 1. The shell reflows

The 238px sidebar collapses to a drawer below the breakpoint; the main column becomes a single column.
Multi-column rows on the project hub (`minmax(620px,1.55fr) / minmax(320px,1fr)`) stack. This is a
handful of media queries against grid definitions that already use `minmax()`, not a redesign.

The body must never scroll horizontally at 320px. That is the test.

### 2. Named components claim the exception

Only these, and each scrolls inside its own `overflow-x: auto` container rather than pushing the page:

| Component | Why it qualifies |
|---|---|
| Source viewer (SAST spine, coverage spine) | Source code is meaningful only with its original line breaks; rewrapping changes what the reader is looking at. Canonical example in the Understanding document. |
| Explorer two-pane grid | Tree plus detail is a two-dimensional relationship. Below the breakpoint it becomes a master–detail *navigation* — tree, then detail as its own view — which is reflow, not a floor. |
| Wide data tables (Portfolio, POA&M, build history, audit log, SBOM advisories) | Data tables are the other canonical example. Each scrolls within its own container. |
| Policy category grid | Weight, effective max and sub-weights are a matrix; the relationship between columns *is* the information. |
| Request/response panels (DAST spine) | Side-by-side comparison is the evidence. Stacks below the breakpoint. |

Everything not on this list reflows. The list does not grow without amending this ADR.

### 3. The attestation reflows unconditionally

It is the deliverable, it is what an auditor reads, and it prints. No exception is claimed for it. Its
practice rows are a label/status/evidence stack, not a matrix, and they collapse cleanly.

### 4. The conformance claim becomes true rather than narrowed

The product claims **WCAG 2.1 Level AA**, without carve-outs, and the axe-core dogfood run (TFND-27) is
expected to pass on every screen. Where the exception is claimed, it is recorded here and in the
component, so a reviewer can see it was a deliberate reading of the standard rather than an oversight.

### 5. This is an acceptance criterion, not a later pass

Every screen ticket in TFND-40 closes only when it has been checked at 320px. It joins pseudo-locale
verification (TFND-67) as a standing gate on screen work — both are cheap per screen and expensive as a
retrofit.

## Consequences

**Positive**

* The AA claim is honest, and the product's own scanner agrees with it.
* Density survives exactly where it is load-bearing, which is what the hand-off was actually protecting.
* Reflow is designed in per screen rather than retrofitted across eight screens later.
* Removing a global `min-width` is easier than adding one back would have been.

**Negative / accepted costs**

* **Real added work**, spread thinly: a breakpoint and a stacking rule per screen, plus a 320px check in
  every screen ticket's acceptance. This is the honest cost of the decision and it is not zero.
* **The hand-off is contradicted on a stated point.** `min-width: 1180px` is explicit, and this ADR
  overrides it. The design owner should be told rather than discovering it in a review.
* Master–detail navigation on the explorer below the breakpoint is genuinely new behaviour that the
  prototype does not show, so it needs a design answer (TFND-86).

**Neutral**

* Nothing here promises a *good* mobile experience. It promises conformance and no loss of function.
  This remains a desktop tool; the 1180px design intent is unchanged above the breakpoint.

## Notes

* SC 1.4.10 is about reflow at 320px CSS pixels, which is equivalent to 1280px at 400% zoom. The
  realistic user is not on a phone — it is a low-vision user at high browser zoom on a desktop. That
  framing makes the exception list easier to judge: *would this still make sense magnified four times?*
* The 9–10px uppercase labels are a separate question and are **not** a 1.4.10 issue. WCAG sets no
  minimum text size; the hand-off's ~5:1 contrast measurement on `--color-neutral-500` satisfies SC
  1.4.3. Left as designed.
* **axe-core cannot verify this decision.** The a11y scan is already wired (`build/Build.cs`,
  `SecurityScanAxeCore`, emitting SARIF via `axe-sarif-converter`), but SC 1.4.10 is not
  automatically detectable — reflow requires rendering at a viewport and judging loss of information.
  So no scanner config changes here, and no rule is being suppressed: the dogfood run is simply silent
  on this criterion. That silence is precisely why the 320px check is written into every screen
  ticket's acceptance rather than delegated to CI. If the check is not performed by a human or a
  scripted viewport test, it is not performed at all.
* TFND-61 (token stylesheet and primitive kit) is the first ticket that consumes this decision, which is
  why TFND-57 was made a hard dependency of it.
