# Design addendum — gate verdict marks

Ticket: TFND-75 (under TFND-40) · Date: 2026-08-22

Extends `docs/redesign/README.md` §2 "Project hub" and §1 "Portfolio". The hand-off predates the
four-valued verdict and specifies only two gate marks; this fills the gap. **Where this document and the
hand-off disagree about gate rendering, this document wins.**

## Why the hand-off needs extending

The hand-off draws the gate rail as an 18px square mark that is either an accent-bordered `✓` or a solid
`#dd5f5f` `✕`, with a sub-line reading *"3 of 10 enabled gates failing on this build"*.

TFND-74 gave `GateResult` four verdicts — `Pass | Fail | Unknown | Error` — because a project that had
never been scanned passed every severity gate. The design has no mark for the other two.

Left unaddressed, the project hub would render its scan-receipt cards saying *"a missing scanner is not
a clean scanner"* directly beneath a gate rail reading **PASS** for the very scanner that never ran.
That is the ADR 0001 bug, drawn in high fidelity.

## The marks

No new colours. All four come from the semantic palette already in the system, and each pairs a glyph,
a written tag and a colour so that **colour is never the sole signal** — the hand-off's own rule, and
the reason the attestation survives a black-and-white printer.

| Verdict | Glyph | Tag | Colour | Mark treatment |
|---|:--:|---|---|---|
| Pass | `✓` | `PASS` | `--color-accent` | 1px accent border, no fill |
| Fail | `✕` | `FAIL` | `#dd5f5f` | solid fill, `#12181e` glyph |
| Unknown | `?` | `UNKNOWN` | `#d4bb4a` | **1px dashed** border, 14% tint fill |
| Error | `!` | `ERROR` | `#e2894a` | solid fill, `#12181e` glyph |

Three choices worth stating:

**`#d4bb4a` for Unknown.** Already carries "medium severity · skipped · idle" in the palette — the
family of *nothing conclusive happened here*. It is the same yellow the Tests spine uses for a skipped
case, and a skipped test and an unrun scanner are the same idea: absence of a result, not a good result.

**Dashed, not solid.** The scan-receipt cards already draw a never-ran class with a dashed border. Reusing
dashed for Unknown makes one visual idea — *dashed means nothing happened here* — readable across both
rows of the hub without the reader learning a second convention.

**`?` not `—`.** An em dash is what a disabled gate shows, and disabled and unanswered are opposite
statements: one says *we chose not to ask*, the other says *we asked and got no answer*. A question mark
is legible at 18px and reads correctly in monochrome.

## The sub-line counts three things

Derived, never hard-coded — this line contradicting a computed value is the original "9 gates enabled"
bug.

```
3 of 10 enabled gates failing · 2 unanswered
```

Rules:

- Drop a clause at zero. No `· 0 unanswered`.
- With no failures and no unknowns: `all 10 enabled gates passing`.
- `Error` is rare and operator-facing; fold it into the unanswered clause as
  `· 1 could not be evaluated` rather than giving it a fourth clause.
- The denominator is `GateEvaluation.Enabled`, **never** `Passed + Failed` — that arithmetic silently
  drops every Unknown.

## The ship verdict gains a third state

The hand-off gives the hub two: `✕ BLOCKED` solid `#dd5f5f`, or `✓ CLEAR TO SHIP` outlined `#4fb783`.
Portfolio already has three (`BLOCKED` / `CLEAR` / `NO SCAN`), so the hub is the inconsistent one.

| Condition | Verdict chip |
|---|---|
| any `Fail` | `✕ BLOCKED` — solid `#dd5f5f`, `#12181e` text |
| no `Fail`, any `Unknown` or `Error` | `? NOT ASSESSED` — outlined `#d4bb4a`, dashed border |
| all enabled gates `Pass` | `✓ CLEAR TO SHIP` — outlined `#4fb783` |

`NOT ASSESSED` blocks exactly as `BLOCKED` does — `GateEvaluation.ClearToShip` is false for both. It is
worded differently because the remedy is different: *"your pipeline is not running the scanner"* rather
than *"go fix the finding"*. Collapsing them would put the reader on a hunt for findings that do not
exist.

Maps to `Portfolio`'s existing `NO SCAN` chip, so a reader moving between the two screens sees the same
three outcomes.

## The failure action link

The hand-off gives failures *"an accent action link to the thing that failed"*. An Unknown gate has no
finding to link to, so it links to the **scan receipt** for the missing class instead — the card in row
3 that explains what did not run. Error links nowhere and shows its reason inline.

## Attestation

Same three states, same glyphs. The attestation's count tiles already use `✓ ◐ ✕ ○` so the tally
survives monochrome; gate lines follow the marks above.

An unanswered gate **must not** print as passed. That is the specific mechanism by which a compliance
attestation becomes false, and it is why `SsdfGateLine` carries the verdict rather than a boolean.

## Already implemented

- `GateVerdict` and the derived counts (`Enabled`, `Passed`, `Failed`, `Unknown`, `Errored`,
  `Blocking`, `ClearToShip`) — TFND-74, merged.
- The React SPA renders three states with amber for unanswered — interim, retires with TFND-128.

## Consumers

- **TFND-61** — the token stylesheet carries the four mark treatments as primitives.
- **TFND-79** — the hub's gate rail. Blocked on this document; now unblocked.
- **TFND-84** — Portfolio's ship chip, which already had three states and now matches the hub.
- **TFND-100** — attestation gate lines.
