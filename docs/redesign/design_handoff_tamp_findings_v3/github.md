repo: tamp-build/tamp-findings
branch: main

## Last sync

date: 2026-09-28T12:13:23Z

### Updated in this project

- Read docs/adr 0001–0005 to ground the ADR-conformance evidence source in real rules and quotes.
- ADR conformance added to the Evidence card, sidebar and evidence screen (four-valued verdicts, dispositions, advisory).
- Attestation evidence screens (provenance, disclosure policy, VEX) and six collected-evidence screens.

## Sync history

- 2026-09-28T02:15:05Z — scorer + ingest inventory; portfolio, dashboard, category detail pages.

- 2026-08-22T18:49:33Z — CRUD, ingest key, unified explorer, dark palette.
- 2026-08-22T16:34:45Z — first read: IA, risk policy, gates, POA&M model, SSDF attestation builder.

## Screen map

| Screen | Built from |
| --- | --- |
| Sidebar IA / scope switcher | web/src/App.tsx, web/src/components/DrillBreadcrumb.tsx |
| Portfolio | src/Tamp.Findings.Application/Projects/PortfolioQuery.cs |
| Project dashboard | src/Tamp.Findings.Application/Projects/ProjectHubQuery.cs, live /c/BrewingCoder/p/tamp-findings/build/latest |
| Category detail pages | src/Tamp.Findings.Application/Risk/RiskInputsBuilder.cs, src/Tamp.Findings.Application/Risk/LicensePolicy.cs |
| Findings + severity treatment | web/src/views/FindingsView.tsx, web/src/components/SeverityBadge.tsx |
| POA&M | src/Tamp.Findings.Domain/Entities/PoamItem.cs, web/src/components/PoamItemsPanel.tsx |
| Attestation | src/Tamp.Findings.Application/Attestation/SsdfAttestationBuilder.cs |
| Policy &amp; gates | web/src/components/RiskPolicyEditor.tsx, src/Tamp.Findings.Domain/Risk/RiskPolicyDefaults.cs |
| Roles &amp; access | src/Tamp.Findings.Domain/Values/ProjectRole.cs, src/Tamp.Findings.Domain/Entities/ProjectRoleAssignment.cs |
| Ingest keys | src/Tamp.Findings.Domain/Entities/IngestToken.cs |
| ADR conformance | docs/adr/0001–0005 (rules and quotes) |
| Receipts / missing scanners | tamp-ingest-v1: src/Tamp.Ingest.V1/ScannerKind.cs, ScanRunsIngest.cs |
