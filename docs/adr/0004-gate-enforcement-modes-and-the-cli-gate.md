# ADR 0004: Gate enforcement modes and the fail-closed CLI gate

* Status: Accepted
* Date: 2026-09-26
* Deciders: scott
* Tracking: TFND-142 (Gating hardening: fail-closed enforcement + CLI gate)

## Context and Problem Statement

ADR 0001 gave us a sound rule engine: a four-valued verdict (`Pass | Fail | Unknown | Error`)
where every non-Pass state blocks, and "never scanned = Unknown" so a skipped scanner cannot
wear a green badge. That model is correct and is not in question here.

The problem is **delivery**, not evaluation. A 2026-09-26 code-verified review of the gating
surface found that the verdict is, in practice, **advisory almost everywhere**:

* The dashboard, the `build-evaluation` endpoint and the attestation only *display* the verdict.
  `GET /projects/{id}/build-evaluation` always returns `200` with the body — there is no
  CI-consumable exit status.
* The **only** thing that can actually block is the GitHub check-run
  (`GitHubCheckPublisher`), and it is opt-in, off by default, its block lives in GitHub
  branch-protection (external config), its delivery is best-effort (dropped on outage or
  queue-full — a dropped check looks identical to a passing one to GitHub), and it evaluates
  with `prior: null`, so the delta gates (`riskScoreRegression`, `coverageRegression`) are dead
  on that path.

Two consumers now need more than advice, on different clocks:

* **Engine contractor (near term)** — internal dev-efficiency tooling in a controlled ITAR
  enclave. Needs hard, local, air-gapped, fail-closed gates now. Does **not** need cryptographic
  provenance yet.
* **Strata (long term)** — GovRAMP-bound. Needs verified provenance and real signatures. Runs on
  its own clock.

The question this ADR answers: **how do we turn gating into a hard guarantee for the contractor
without hobbling the open-source default, and without touching the engine core?**

The provenance half (verifying inbound attestations, real outbound signatures, identity-bound
ingest) is **scoped, not decided here** — it is Strata's track and must not eat the contractor
runway. See the long-term slices under TFND-142 and TFND-159.

## Decision Drivers

* **Do not hobble the community.** A fresh open-source install must never block anyone. Hard
  enforcement is something an operator opts into, not a default they fight.
* **Fail closed when it counts.** In an enclave, a misconfigured or unreachable gate that passes
  silently is worse than no gate — it manufactures false confidence on a release decision.
* **Air-gap native.** The contractor's CI has no internet. Enforcement cannot depend on GitHub,
  a SaaS, or any external call.
* **Do not touch the engine.** The four-valued model (ADR 0001) is correct. Build around it.
* **Enabling a gate and enforcing on it are different questions.** Conflating them forces a team
  to choose between "no signal" and "hard block on day one," which kills adoption.
* **Agents are first-class consumers.** A remediation agent needs structured, machine-readable
  reasons to fix-and-retry, not a wall of log text.

## Invariants

These hold for every change on this track. If a design choice breaks one, the choice is wrong.

1. **Default is advisory.** A fresh install never blocks anyone. The community runs it loose; the
   contractor flips it strict.
2. **Enforcing mode fails closed.** Anything that is not a definitive Pass returns non-zero — Fail,
   Unknown, Error, *and* "could not reach a verdict." A missing result is a block, never a pass.
3. **Gates stay opt-in per gate.** Enforcement mode is a separate axis from which gates are enabled.
4. **Evidence stays optional.** SSDF / VEX / POA&M generation is a nice-to-have a community user can
   ignore. Enforcement does not drag the evidence surface along.
5. **The engine core is not touched.** Build around the four-valued verdict, not into it.

## Decision

### 1. Two enforcement modes on one strictness axis

`advisory < enforcing`. There is no third `off` mode — "off" is simply not enabling gates or not
invoking the gate.

* **`advisory`** (default): evaluate, report, never fail the build. The CLI gate exits 0 regardless
  of verdict; the dashboard and check-run still go red. This is the OSS-safe default and the honest
  preview state.
* **`enforcing`**: a blocking verdict — or an unreachable/no-verdict situation — returns non-zero.

Mode is stored on `InstanceSettings.enforcement { mode, locked }` (ships `advisory` / `false`) and,
per-project, on `Project.GatesConfig.enforcementMode` (optional; omitted = inherit). It resolves
along the existing risk-policy chain: **Project → Client → Instance default**, most-specific wins —
with one exception.

### 2. The locked floor (the platform lever)

The instance default carries an optional `locked` flag.

* **Unlocked** (OSS default): most-specific-wins; a project may set advisory or enforcing freely.
* **Locked**: the instance mode becomes a **floor**, not merely a default. Effective mode =
  the stricter of (instance floor, project setting). A project may match or exceed the floor; it
  cannot weaken it.

The contractor's platform team sets instance = `enforcing` + `locked`; no project can then quietly
downgrade to advisory, and the guarantee holds fleet-wide. OSS leaves it unlocked and advisory, and
nobody is hobbled.

### 3. A build-invocable CLI gate is the keystone

Working name `tamp findings gate` (or a Tamp build target `FindingsGate`; a tamp-CLI/TAM split may
follow, design owned in TFND). It runs **after ingest, against the build just posted** — the same
stable identifier (commit SHA + component-version / flavor) is passed to both ingest and gate — and
talks **only to the in-enclave findings instance**. It:

* resolves the effective enforcement mode (§1–2) from the instance;
* **evaluates WITH the prior canonical build** for the `(Component, Flavor)` tuple, so delta gates
  actually fire (it does **not** copy the publisher's `prior: null` shortcut);
* **polls** the posted build's verdict with a timeout, because ingest triggers evaluation
  out-of-band;
* applies the fail-closed decision table:

  | Situation | `advisory` exit | `enforcing` exit |
  |---|---|---|
  | Pass / ClearToShip | 0 | 0 |
  | Fail (≥1 blocking Fail gate) | 0 | 10 |
  | Unknown (enabled gate never ran) | 0 | 11 |
  | Error (evaluation error verdict) | 0 | 12 |
  | Unreachable / no verdict / timeout / auth fail / no build record | 0 | 20 |

  Advisory never fails the build (it still prints every warning loudly). Enforcing fails on anything
  that is not a definitive Pass; the unreachable row is the whole point and is non-negotiable.
  Distinct non-zero codes are for diagnostics — CI only needs "non-zero fails the step," but the code
  lets a human or agent tell "scanner didn't run" from "server was down."

* emits `--json` (machine-readable per-gate reasons, file/finding refs, remedy class — the
  agent-consumable surface), a human per-gate breakdown with an explicit "would block / blocks" line
  even in advisory, and `--explain` / dry-run that prints the breakdown and always exits 0.

### 4. Keep the GitHub check-run; fix its bug

The CLI gate and the check-run are independent surfaces over the same verdict: the CLI gate is
primary for hard / air-gapped enforcement, the check-run stays for shops that want PR-level UX. The
publisher's `prior: null` evaluation is fixed so the two surfaces agree on delta gates.

### 5. Gate-integrity fixes that hard mode depends on

Hard enforcement is only as trustworthy as its inputs, and these guard against an honest mistake or
an over-eager agent — no malicious actor required:

* Empty-batch auto-close must require a corroborating scan-run receipt; a missing/never-ran receipt
  resolves Unknown (blocks). The `Ran*` machinery already exists.
* The Admin-only, unaudited HTTP-API write paths (`PATCH /gates`, VEX/POA&M) route through the
  audited, capability-gated Application services — the same ones the UI uses. This closes a hole
  where an Admin can set POA&M `RiskAccepted` directly, bypassing the InfoSec-only `AcceptRisk`
  capability, and it completes the single-authorization-boundary intent of ADR 0002.
* The VisibilityScope zero-assignment bootstrap posture (every approved user sees everything until
  the first role grant exists) is closed, pending confirmation.

## Consequences

**Positive**

* Gating becomes a real guarantee where an operator asks for one, and stays friendly everywhere else.
  The advisory→enforcing split gives a clean rollout: enable gates in advisory, watch what *would*
  block for a sprint, then flip to enforcing once the noise is gone.
* The enclave gets local, air-gapped, fail-closed enforcement independent of GitHub.
* Agents get a structured verdict to remediate against.
* The engine core (ADR 0001) is untouched; this is all delivery and configuration around it.

**Negative / accepted costs**

* A second enforcement surface (CLI gate) alongside the check-run — accepted, because they serve
  different shops and share one verdict source.
* Two config axes (enabled-per-gate × enforcement mode) are more to explain; the adoption path in the
  UI is the mitigation, and the separation is the feature, not an accident.

**Neutral**

* The provenance track (verified inbound attestation, real outbound signatures, identity-bound ingest,
  a first-class trust tier) is deliberately out of scope here and sequenced on Strata's clock. The
  shared seams — per-ingest audit and the config-authority cleanup — are done once and serve both.

## Notes

* This ADR decides *how gating is enforced and delivered*; ADR 0001 decides *what a rule is and how it
  evaluates*. They compose — see the forward reference added to ADR 0001.
* The HTTP-API side-door reroute (§5) is the concrete completion of ADR 0002's "one authorization
  boundary" for the write paths that predated it.
* Provenance verification remains unbuilt: TFND-29 shipped Cosign only as a `ScannerKind`, not in-app
  DSSE verification. Real verification is tracked in TFND-159 (long term).
