# ADR 0008: An ingest-token compliance-profile read

* Status: Proposed
* Date: 2026-09-28
* Deciders: scott
* Tracking: TFND-177 (compliance-profile read endpoint for tamp-conformance)

## Context and Problem Statement

The ADR-conformance producer (`tamp-conformance`, ADR 0006) runs in CI in the governed
repo. To tag its verdicts with the right control vocabulary — which 800-53 controls a rule
maps to, under which framework — it needs to know the **project's compliance profile**: the
framework the project is held to, that framework's applicable controls, the effective policy
templates, and the enforcement posture.

The producer already holds one credential for this project: the **ingest token** the evidence
flows through. The question this ADR answers: **how does the producer read the project's
compliance profile using that same token, without opening a new unaudited surface or a
cross-tenant read?**

Reading it through the ingest token is the point — it ties the framework used for extraction
to the exact project the evidence posts to, so the vocabulary cannot drift from the project by
construction.

## Decision

Add a read-only endpoint **`GET /projects/self/compliance-profile`**, authenticated by the
existing ingest token (the same `cli_`/`prj_` scheme as `/ingest/*` and the CLI gate at
`/projects/{id}/gate`), returning **only the token project's profile**.

1. **It reuses the ingest-auth boundary, not a new one.** The endpoint copies `GateEndpoints`:
   `.AllowAnonymous().AddEndpointFilter<IngestAuthFilter>()`, resolves the project from the
   token, and reads through the audited Application query — it is not a raw HTTP side-door of
   the kind ADR 0004 §5 closed. The read is written to the audit log, attributed to the token's
   minting user where known.

2. **`self` requires a project-scoped token.** `self` is unambiguous only for a `prj_` token; a
   `cli_` token spans many projects, so it has no single `self` and is refused as **not-found**
   (never 403) — the same not-found-not-forbidden discipline the rest of the ingest surface uses
   so a token never confirms which projects exist under a client. (A `/projects/{id}/…` variant
   for client tokens can be added later if needed.)

3. **The payload is derived, never a new source of truth.** The **applicable controls are
   computed** from the assigned framework's baseline against the current catalog's membership
   flags (ADR 0007 / v3 §6) — a Moderate framework's controls are the catalog controls in the
   Moderate baseline — so they cannot drift from the catalog. The policy templates and
   enforcement come straight from the three-layer policy resolver and `EnforcementResolver`. The
   response is **versioned in the body** (`schemaVersion 1.0`) because a cross-repo consumer
   codes against it.

4. **It exposes nothing else.** No findings, no evidence, no secrets, no other project, and no
   mutation. A project with neither a framework nor an inherited policy template has **no profile
   configured** and returns 404, not an empty 200.

## Consequences

* The ingest token gains a single, narrow, audited **read** — its own project's compliance
  profile — where before it was write-only. The blast radius of a leaked token is unchanged in
  kind (still one project) and only slightly wider in scope (it can now read that project's
  framework/controls, which are not secret).
* The conformance producer tags evidence with the project's real control vocabulary using one
  credential, so the framework and the evidence cannot disagree about which project they are for.
* The applicable-control set is only as complete as the seeded catalog until a full OSCAL 1.2
  profile is imported; the computed-from-baseline approach means it grows automatically when the
  catalog does, with no change here.
