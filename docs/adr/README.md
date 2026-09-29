# Architecture Decision Records

This folder will collect ADRs for tamp.findings. ADR 0018 (the tamp emission
contract) is owned upstream by [tamp-build/tamp](https://github.com/tamp-build/tamp);
we consume it here.

Numbering starts at 0001 for tamp.findings-local decisions.

## Records

| # | Title | Status |
|---|---|---|
| [0001](0001-rule-evaluation-predicates-and-workflows.md) | Rule evaluation — four-valued verdicts, predicates by default, Elsa for complexity | Accepted |
| [0002](0002-blazor-hosting-and-the-authorization-boundary.md) | Blazor hosting, the application layer, and one authorization boundary | Accepted |
| [0003](0003-reflow-and-the-1180px-density-floor.md) | Reflow and the 1180px density floor | Accepted |
| [0004](0004-gate-enforcement-modes-and-the-cli-gate.md) | Gate enforcement modes and the fail-closed CLI gate | Accepted |
| [0005](0005-removing-elsa-scheduled-work-as-hosted-workers.md) | Removing Elsa — scheduled work as hosted workers | Accepted |
| [0006](0006-adr-conformance-as-evidence-and-frozen-non-pure-verdicts.md) | ADR-conformance as an evidence source, and freezing non-pure verdicts at the snapshot | Accepted |
| [0007](0007-three-layer-harden-only-policy.md) | Three-layer harden-only policy (template → client → project) | Accepted |
| [0008](0008-ingest-token-compliance-profile-read.md) | An ingest-token compliance-profile read | Proposed |
| [0009](0009-control-disposition-and-the-no-unmapped-meta-gate.md) | Control disposition and the no-unmapped meta-gate | Proposed |
| [0010](0010-zero-trust-maturity-and-operational-mandates.md) | Zero Trust maturity + operational mandates in tamp.findings | Proposed |
| [0011](0011-executive-order-mandate-provenance-registry.md) | Executive-order mandate provenance registry | Proposed |
| [0012](0012-findings-as-the-authoritative-conformance-rules-store.md) | Findings as the authoritative conformance-rules store (amends 0006 §3) | Proposed |
| [0013](0013-reverse-examination-undocumented-decision-advisories.md) | Reverse-examination — undocumented-decision advisories as CM-3 evidence | Proposed |
| [0014](0014-raw-report-ingestion-and-server-side-parsing.md) | Raw report ingestion — the sink parses, and the raw report is the evidence of record | Accepted |
| [0015](0015-project-authored-control-dispositions.md) | Project-authored control dispositions; archetype as the default (amends 0009) | Accepted |
