repo: tamp-build/tamp-findings
branch: main

## Last sync

date: 2026-08-22T18:49:33Z

### Updated in this project

- Read ProjectRole / ProjectRoleAssignment to ground the proposed RBAC matrix in the real three-role enum and its client/project/component tiers.
- Added CRUD for projects, components, risk policies and POA&M items, plus a recyclable project ingest key.
- Unified explorer (SAST, DAST, SBOM, coverage, tests) replaced the four separate two-pane screens.
- Dark editor palette; score, gates and attestation all read from one computed source.

## Sync history

- 2026-08-22T16:34:45Z — first read: IA, risk policy, gates, POA&M model, SSDF attestation builder.

## Screen map

| Screen | Built from |
| --- | --- |
| Sidebar IA / scope switcher | web/src/App.tsx, web/src/components/DrillBreadcrumb.tsx |
| Project hub (score + gates) | web/src/views/ProjectPageView.tsx, src/Tamp.Findings.Domain/Risk/RiskPolicyDefaults.cs, src/Tamp.Findings.Domain/Risk/ProjectGatesConfig.cs |
| Findings + severity treatment | web/src/views/FindingsView.tsx, web/src/components/SeverityBadge.tsx |
| POA&M | src/Tamp.Findings.Domain/Entities/PoamItem.cs, web/src/components/PoamItemsPanel.tsx |
| Attestation | web/src/views/AttestationView.tsx, src/Tamp.Findings.Api/Endpoints/SsdfAttestationEndpoints.cs |
| Policy &amp; gates | web/src/components/RiskPolicyEditor.tsx, src/Tamp.Findings.Domain/Risk/RiskPolicyDefaults.cs |
| Roles &amp; access | src/Tamp.Findings.Domain/Values/ProjectRole.cs, src/Tamp.Findings.Domain/Entities/ProjectRoleAssignment.cs |
| Ingest keys | src/Tamp.Findings.Domain/Entities/IngestToken.cs |
