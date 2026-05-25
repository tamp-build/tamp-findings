// Tiny fetch wrapper. Goes through the Vite dev-proxy mapping /api → :5080
// (see vite.config.ts). In prod the SPA is served from the same origin as
// the API, so the same /api path works without a proxy.

export const API_BASE = '/api'

export type ScannerKind =
  | 'Unknown' | 'OpenGrep' | 'TruffleHog' | 'CodeQL' | 'Trivy'
  | 'Checkov' | 'Tfsec' | 'Kics' | 'Zap' | 'Spectral' | 'Oasdiff'
  | 'Cosign' | 'NetArchTest' | 'DependencyCruiser' | 'Stryker' | 'Coverlet'
  | 'OsvScanner' | 'Roslyn' | 'Syft' | 'Grype' | 'ReSharper' | 'ESLint'
  | 'AxeCore'

export type Severity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical'
export type FindingStatus = 'Open' | 'Fixed' | 'Suppressed' | 'Accepted'

export type SeverityCounts = {
  info: number
  low: number
  medium: number
  high: number
  critical: number
  total: number
}

export type FindingListItem = {
  id: string
  scanner: ScannerKind
  ruleId: string
  severity: Severity
  title: string
  filePath: string | null
  line: number | null
  status: FindingStatus
  firstSeen: string
  lastSeen: string
  componentVersionId: string
  versionString: string
  componentId: string
  componentName: string
  projectId: string
  projectName: string
  clientId: string
  clientName: string
}

export type FindingsListResponse = {
  totalCount: number
  skip: number
  take: number
  counts: SeverityCounts
  items: FindingListItem[]
}

export type FindingsListFilters = {
  clientId?: string
  projectId?: string
  componentId?: string
  componentVersionId?: string
  severities?: Severity[]
  scanners?: ScannerKind[]
  statuses?: FindingStatus[]
  search?: string
  skip?: number
  take?: number
}

// ----- SBOM components ----------------------------------------------------

export type SbomComponentListItem = {
  id: string
  purl: string
  name: string
  version: string
  kind: string | null
  ecosystem: 'nuget' | 'npm' | 'other' | string
  license: string | null
  latestVersion: string | null
  latestReleasedAt: string | null
  vulnerabilityCount: number
  componentVersionId: string
  versionString: string
  componentId: string
  componentName: string
  projectId: string
  projectName: string
  clientId: string
  clientName: string
}

export type EcosystemCounts = { nuget: number; npm: number; other: number; total: number }

export type SbomComponentsListResponse = {
  totalCount: number
  skip: number
  take: number
  counts: EcosystemCounts
  totalVulnerabilities: number
  items: SbomComponentListItem[]
}

export type SbomHealthStatus = 'vulnerable' | 'outdated' | 'current'

export type SbomComponentsFilters = {
  componentVersionId?: string
  ecosystem?: string
  status?: SbomHealthStatus
  license?: string
  search?: string
  latest?: boolean
  skip?: number
  take?: number
}

export async function fetchSbomComponents(filters: SbomComponentsFilters = {}): Promise<SbomComponentsListResponse> {
  const params = new URLSearchParams()
  if (filters.componentVersionId) params.set('componentVersionId', filters.componentVersionId)
  if (filters.ecosystem) params.set('ecosystem', filters.ecosystem)
  if (filters.status) params.set('status', filters.status)
  if (filters.license) params.set('license', filters.license)
  if (filters.search) params.set('search', filters.search)
  if (filters.latest === false) params.set('latest', 'false')
  if (filters.skip != null) params.set('skip', String(filters.skip))
  if (filters.take != null) params.set('take', String(filters.take))
  const r = await fetch(`${API_BASE}/sbom-components?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /sbom-components failed: ${r.status}`)
  return r.json()
}

export type VulnerabilityDetail = {
  id: string
  advisoryId: string
  severity: string
  title: string | null
  description: string | null
  fixedInVersion: string | null
  referenceUrl: string | null
  source: string
}

export type SbomComponentDetail = {
  id: string
  purl: string
  name: string
  version: string
  kind: string | null
  ecosystem: string
  license: string | null
  componentVersionId: string
  versionString: string
  vulnerabilities: VulnerabilityDetail[]
  dependsOnPurls: string[]
  dependentPurls: string[]
}

export async function fetchSbomComponent(id: string): Promise<SbomComponentDetail> {
  const r = await fetch(`${API_BASE}/sbom-components/${id}`)
  if (!r.ok) throw new Error(`GET /sbom-components/${id} failed: ${r.status}`)
  return r.json()
}

// ----- Hierarchy lookups + aggregates ------------------------------------

export type ClientListItem = { id: string; name: string; projectCount: number; riskPolicyId: string | null }
export type ProjectListItem = { id: string; name: string; clientId: string; clientName: string; componentCount: number }
export type ComponentListItem = { id: string; name: string; kind: string | null; projectId: string; projectName: string; clientId: string; clientName: string; versionCount: number }

export async function fetchClients(): Promise<ClientListItem[]> {
  const r = await fetch(`${API_BASE}/clients`)
  if (!r.ok) throw new Error(`GET /clients failed: ${r.status}`)
  return r.json()
}

export async function fetchProjects(clientId?: string): Promise<ProjectListItem[]> {
  const qs = clientId ? `?clientId=${clientId}` : ''
  const r = await fetch(`${API_BASE}/projects${qs}`)
  if (!r.ok) throw new Error(`GET /projects failed: ${r.status}`)
  return r.json()
}

export async function fetchComponents(projectId?: string): Promise<ComponentListItem[]> {
  const qs = projectId ? `?projectId=${projectId}` : ''
  const r = await fetch(`${API_BASE}/components${qs}`)
  if (!r.ok) throw new Error(`GET /components failed: ${r.status}`)
  return r.json()
}

export type AggregateScope = {
  clientName: string | null
  projectName: string | null
  componentName: string | null
  label: string
  level: 'All' | 'Client' | 'Project' | 'Component'
}

export type ScannerDetail = {
  scanner: string
  open: SeverityCounts
  closed: number
  suppressed: number
  accepted: number
}

export type ScanRunStatus = 'Succeeded' | 'Failed' | 'Skipped'

export type ScanRunSummary = {
  scanner: ScannerKind
  status: ScanRunStatus
  completedAt: string
  findingsCount: number
  toolName: string | null
  toolVersion: string | null
}

export type FindingRuleSummary = {
  ruleId: string
  count: number
  severity: Severity
  scanner: ScannerKind
}

export type AggregatesResponse = {
  scope: AggregateScope
  findings: {
    counts: SeverityCounts
    byScanner: Record<string, number>
    byStatus: Record<string, number>
    byScannerDetail: ScannerDetail[]
    byRule: FindingRuleSummary[]
  }
  sbom: {
    componentsCount: number
    vulnerabilitiesCount: number
    byEcosystem: Record<string, number>
    health: SbomHealthCounts
  }
  secrets: {
    health: SecretsHealthCounts
  }
  licenses: {
    tiers: LicenseTierCounts
    byLicense: Record<string, number>
  }
  iac: {
    counts: SeverityCounts
    scanned: boolean
  }
  coverage: {
    measured: boolean
    sequenceCoverage: number | null
    branchCoverage: number | null
    coveredSequences: number
    totalSequences: number
    modules: CoverageModuleSummary[]
  }
  // TFND-15: per-scanner receipts so the dashboard can tell "ran clean"
  // from "never ran". Empty array means no scanners have reported.
  scanRuns: ScanRunSummary[]
  // Risk Assessment Policy score. null when the scope has no ingest
  // evidence — SPA renders "not yet scored" instead of a misleading 0%.
  risk: RiskScore | null
}

export type RiskBand = 'green' | 'yellow' | 'orange' | 'red'

export type RiskBreakdown = {
  key: string
  enabled: boolean
  max: number
  subScore: number
  contribution: number
}

export type RiskScore = {
  score: number          // 0..100, rounded to 1dp
  band: RiskBand
  policyId: string
  policyName: string
  schemaVersion: number
  breakdown: RiskBreakdown[]
}

export type CoverageModuleSummary = {
  name: string
  sequenceCoverage: number
  coveredSequences: number
  totalSequences: number
}

export type SbomHealthCounts = {
  current: number     // green
  outdated: number    // yellow
  vulnerable: number  // red
  // TFND-22: sub-count of outdated where LatestReleasedAt > 180 days ago.
  stale: number
}

export type SecretsHealthCounts = {
  verified: number    // red — TruffleHog confirmed live credential
  unverified: number  // yellow — pattern match only
}

export type LicenseTierCounts = {
  permissive: number       // lightest green
  weakCopyleft: number
  strongCopyleft: number
  denied: number           // red — release-blocking by default
  unknown: number          // grey
}

export type AggregatesFilters = {
  clientId?: string
  projectId?: string
  componentId?: string
}

// ----- Coverage detail (per-module / per-class) --------------------------

export type CoverageTreeClass = {
  id: string
  fullName: string
  sourceFileRelativePath: string
  sequenceCoverage: number
  coveredSequences: number
  totalSequences: number
}

export type CoverageTreeModule = {
  name: string
  sequenceCoverage: number
  branchCoverage: number
  coveredSequences: number
  totalSequences: number
  classes: CoverageTreeClass[]
}

export type CoverageTreeResponse = {
  measured: boolean
  sequenceCoverage: number | null
  branchCoverage: number | null
  coveredSequences: number
  totalSequences: number
  modules: CoverageTreeModule[]
}

export type CoverageClassDetail = {
  id: string
  moduleName: string
  fullName: string
  sourceFileRelativePath: string
  sequenceCoverage: number
  branchCoverage: number
  coveredSequences: number
  totalSequences: number
  coveredBranches: number
  totalBranches: number
  visitedLines: number[]
  unvisitedLines: number[]
  sourceText: string
}

export async function fetchCoverageTree(filters: AggregatesFilters = {}): Promise<CoverageTreeResponse> {
  const params = new URLSearchParams()
  if (filters.clientId) params.set('clientId', filters.clientId)
  if (filters.projectId) params.set('projectId', filters.projectId)
  if (filters.componentId) params.set('componentId', filters.componentId)
  const r = await fetch(`${API_BASE}/coverage/tree?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /coverage/tree failed: ${r.status}`)
  return r.json()
}

// ----- Findings tree (file-based detail view) -----------------------------

export type FindingsTreeFile = {
  relativePath: string
  counts: SeverityCounts
  maxSeverity: Severity
}

export type FindingsTreeModule = {
  name: string
  counts: SeverityCounts
  files: FindingsTreeFile[]
}

export type FindingsTreeResponse = {
  totalCount: number
  counts: SeverityCounts
  modules: FindingsTreeModule[]
  noPathCount: number
}

export type FindingsFileItem = {
  id: string
  scanner: ScannerKind
  ruleId: string
  severity: Severity
  title: string
  description: string | null
  line: number | null
}

export type FindingsFileResponse = {
  relativePath: string
  sourceAvailable: boolean
  sourceText: string
  findings: FindingsFileItem[]
}

export type FindingsTreeFilters = AggregatesFilters & { ruleId?: string }

export async function fetchFindingsTree(filters: FindingsTreeFilters = {}): Promise<FindingsTreeResponse> {
  const params = new URLSearchParams()
  if (filters.clientId) params.set('clientId', filters.clientId)
  if (filters.projectId) params.set('projectId', filters.projectId)
  if (filters.componentId) params.set('componentId', filters.componentId)
  if (filters.ruleId) params.set('ruleId', filters.ruleId)
  const r = await fetch(`${API_BASE}/findings/tree?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /findings/tree failed: ${r.status}`)
  return r.json()
}

export async function fetchFindingsFile(path: string, ruleId?: string): Promise<FindingsFileResponse> {
  const params = new URLSearchParams({ path })
  if (ruleId) params.set('ruleId', ruleId)
  const r = await fetch(`${API_BASE}/findings/file?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /findings/file failed: ${r.status}`)
  return r.json()
}

// ----- Test results (TRX) --------------------------------------------------

export type TestOutcome = 'Passed' | 'Failed' | 'Skipped' | 'Inconclusive'

export type TestTreeSuite = {
  id: string
  className: string
  totalCount: number
  passedCount: number
  failedCount: number
  skippedCount: number
}

export type TestTreeAssembly = {
  name: string
  totalCount: number
  passedCount: number
  failedCount: number
  skippedCount: number
  suites: TestTreeSuite[]
}

export type TestResultsTreeResponse = {
  measured: boolean
  totalCount: number
  passedCount: number
  failedCount: number
  skippedCount: number
  inconclusiveCount: number
  durationMs: number
  completedAt: string | null
  assemblies: TestTreeAssembly[]
}

export type TestCaseDetail = {
  name: string
  outcome: TestOutcome
  durationMs: number
  errorMessage: string | null
  errorStackTrace: string | null
}

export type TestSuiteDetail = {
  id: string
  assemblyName: string
  className: string
  totalCount: number
  passedCount: number
  failedCount: number
  skippedCount: number
  durationMs: number
  cases: TestCaseDetail[]
}

export async function fetchTestResultsTree(filters: AggregatesFilters = {}): Promise<TestResultsTreeResponse> {
  const params = new URLSearchParams()
  if (filters.clientId) params.set('clientId', filters.clientId)
  if (filters.projectId) params.set('projectId', filters.projectId)
  if (filters.componentId) params.set('componentId', filters.componentId)
  const r = await fetch(`${API_BASE}/test-results/tree?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /test-results/tree failed: ${r.status}`)
  return r.json()
}

export async function fetchTestSuite(id: string): Promise<TestSuiteDetail> {
  const r = await fetch(`${API_BASE}/test-results/suite/${id}`)
  if (!r.ok) throw new Error(`GET /test-results/suite/${id} failed: ${r.status}`)
  return r.json()
}

export async function fetchCoverageClass(id: string): Promise<CoverageClassDetail> {
  const r = await fetch(`${API_BASE}/coverage/class/${id}`)
  if (!r.ok) throw new Error(`GET /coverage/class/${id} failed: ${r.status}`)
  return r.json()
}

export async function fetchAggregates(filters: AggregatesFilters = {}): Promise<AggregatesResponse> {
  const params = new URLSearchParams()
  if (filters.clientId) params.set('clientId', filters.clientId)
  if (filters.projectId) params.set('projectId', filters.projectId)
  if (filters.componentId) params.set('componentId', filters.componentId)
  const r = await fetch(`${API_BASE}/aggregates?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /aggregates failed: ${r.status}`)
  return r.json()
}

// ----- Findings -----------------------------------------------------------

export async function fetchFindings(filters: FindingsListFilters = {}): Promise<FindingsListResponse> {
  const params = new URLSearchParams()
  if (filters.clientId) params.set('clientId', filters.clientId)
  if (filters.projectId) params.set('projectId', filters.projectId)
  if (filters.componentId) params.set('componentId', filters.componentId)
  if (filters.componentVersionId) params.set('componentVersionId', filters.componentVersionId)
  if (filters.severities?.length) params.set('severity', filters.severities.join(','))
  if (filters.scanners?.length) params.set('scanner', filters.scanners.join(','))
  if (filters.statuses?.length) params.set('status', filters.statuses.join(','))
  if (filters.search) params.set('search', filters.search)
  if (filters.skip != null) params.set('skip', String(filters.skip))
  if (filters.take != null) params.set('take', String(filters.take))

  const r = await fetch(`${API_BASE}/findings?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /findings failed: ${r.status}`)
  return r.json()
}

// ----- Ingest tokens ------------------------------------------------------

export type IngestTokenListItem = {
  id: string
  name: string
  scope: 'Client' | 'Project'
  prefix: 'cli_' | 'prj_'
  clientId: string | null
  projectId: string | null
  createdAt: string
  lastUsedAt: string | null
  revokedAt: string | null
}

export type MintedIngestToken = {
  id: string
  name: string
  // Plaintext exposed once at mint time — store immediately, never retrievable.
  token: string
  createdAt: string
}

export async function fetchClientTokens(clientId: string): Promise<IngestTokenListItem[]> {
  const r = await fetch(`${API_BASE}/clients/${clientId}/tokens`)
  if (!r.ok) throw new Error(`GET /clients/${clientId}/tokens failed: ${r.status}`)
  return r.json()
}

export async function mintClientToken(clientId: string, name: string): Promise<MintedIngestToken> {
  const r = await fetch(`${API_BASE}/clients/${clientId}/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
  if (!r.ok) throw new Error(`POST /clients/${clientId}/tokens failed: ${r.status}`)
  return r.json()
}

export async function revokeIngestToken(tokenId: string): Promise<void> {
  const r = await fetch(`${API_BASE}/tokens/${tokenId}`, { method: 'DELETE' })
  if (!r.ok && r.status !== 404) throw new Error(`DELETE /tokens/${tokenId} failed: ${r.status}`)
}

// ----- Risk policies ------------------------------------------------------

export type RiskPolicySummary = {
  id: string
  name: string
  description: string | null
  isDefault: boolean
  isSeeded: boolean
  createdAt: string
  updatedAt: string
}

export type RiskPolicyConfig = {
  schemaVersion: number
  bands: { greenMax: number; yellowMax: number; orangeMax: number }
  categories: Record<string, { enabled: boolean; max: number; weights: Record<string, number> }>
  // Per-scanner severity ceilings. When set, findings from that scanner
  // are downgraded to at most the ceiling severity BEFORE scoring.
  // Default = empty (no overrides; every finding scores at its
  // ingested severity).
  scannerOverrides: Record<string, { severityCeiling: Severity | null }>
}

export type RiskPolicyFull = RiskPolicySummary & { config: RiskPolicyConfig }

export async function fetchRiskPolicies(): Promise<RiskPolicySummary[]> {
  const r = await fetch(`${API_BASE}/risk-policies`)
  if (!r.ok) throw new Error(`GET /risk-policies failed: ${r.status}`)
  return r.json()
}

export async function fetchRiskPolicy(id: string): Promise<RiskPolicyFull> {
  const r = await fetch(`${API_BASE}/risk-policies/${id}`)
  if (!r.ok) throw new Error(`GET /risk-policies/${id} failed: ${r.status}`)
  return r.json()
}

export async function updateRiskPolicy(id: string, patch: { name?: string; description?: string | null; config?: RiskPolicyConfig }): Promise<RiskPolicyFull> {
  const r = await fetch(`${API_BASE}/risk-policies/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  if (!r.ok) throw new Error(`PATCH /risk-policies/${id} failed: ${r.status}`)
  return r.json()
}

export async function cloneRiskPolicy(id: string, name: string): Promise<RiskPolicyFull> {
  const r = await fetch(`${API_BASE}/risk-policies/${id}/clone`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
  if (!r.ok) throw new Error(`POST /risk-policies/${id}/clone failed: ${r.status}`)
  return r.json()
}

export async function deleteRiskPolicy(id: string): Promise<void> {
  const r = await fetch(`${API_BASE}/risk-policies/${id}`, { method: 'DELETE' })
  if (!r.ok && r.status !== 404) throw new Error(`DELETE /risk-policies/${id} failed: ${r.status}`)
}

export async function setDefaultRiskPolicy(id: string): Promise<void> {
  const r = await fetch(`${API_BASE}/risk-policies/${id}/set-default`, { method: 'POST' })
  if (!r.ok) throw new Error(`POST /risk-policies/${id}/set-default failed: ${r.status}`)
}

export async function assignClientPolicy(clientId: string, policyId: string | null): Promise<void> {
  const r = await fetch(`${API_BASE}/clients/${clientId}/policy`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policyId }),
  })
  if (!r.ok) throw new Error(`PATCH /clients/${clientId}/policy failed: ${r.status}`)
}

export async function assignProjectPolicy(projectId: string, policyId: string | null): Promise<void> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/policy`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policyId }),
  })
  if (!r.ok) throw new Error(`PATCH /projects/${projectId}/policy failed: ${r.status}`)
}

// ----- Project policy + gates --------------------------------------------

export type ProjectGatesConfig = {
  schemaVersion: number
  gates: Record<string, { enabled: boolean; threshold?: number | null }>
}

export type ProjectPolicyAndGatesView = {
  assignedPolicyId: string | null
  effectivePolicyId: string
  effectivePolicyName: string
  effectiveFromProject: boolean
  effectiveFromClient: boolean
  gates: ProjectGatesConfig
}

export async function fetchProjectPolicyAndGates(projectId: string): Promise<ProjectPolicyAndGatesView> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/policy-and-gates`)
  if (!r.ok) throw new Error(`GET /projects/${projectId}/policy-and-gates failed: ${r.status}`)
  return r.json()
}

// "Override" / disconnect-from-inherited — clones the current effective
// policy and assigns the clone to the project so the admin can tune it
// without touching the inherited (shared) policy.
export async function forkProjectPolicy(projectId: string): Promise<RiskPolicyFull> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/policy/fork`, { method: 'POST' })
  if (!r.ok) throw new Error(`POST /projects/${projectId}/policy/fork failed: ${r.status}`)
  return r.json()
}

export async function updateProjectGates(projectId: string, gates: ProjectGatesConfig): Promise<void> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/gates`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ gates }),
  })
  if (!r.ok) throw new Error(`PATCH /projects/${projectId}/gates failed: ${r.status}`)
}

// ----- Project scan receipts (per-build) ----------------------------------

export type ScanReceiptRow = {
  scanner: ScannerKind
  status: 'Succeeded' | 'Failed' | 'Skipped'
  startedAt: string | null
  completedAt: string | null
  findingsCount: number
  toolName: string | null
  toolVersion: string | null
}

export type BuildReceipt = {
  componentVersionId: string
  componentId: string
  componentName: string
  flavorName: string | null
  versionString: string
  commitSha: string | null
  branchName: string | null
  buildId: string | null
  createdAt: string
  receipts: ScanReceiptRow[]
}

// ----- VEX statements -----------------------------------------------------

// CycloneDX-VEX 1.5 status vocabulary. Mirrors the backend enum order.
export type VexStatementStatus =
  | 'UnderInvestigation'
  | 'Affected'
  | 'NotAffected'
  | 'Fixed'

export type VexJustification =
  | 'None'
  | 'ComponentNotPresent'
  | 'VulnerableCodeNotPresent'
  | 'VulnerableCodeNotInExecutePath'
  | 'VulnerableCodeCannotBeControlledByAdversary'
  | 'InlineMitigationsAlreadyExist'

export type VexStatement = {
  id: string
  projectId: string
  purl: string
  componentVersion: string | null
  advisoryId: string
  status: VexStatementStatus
  justification: VexJustification | null
  impactStatement: string | null
  responseReferenceUrl: string | null
  authorUserId: string
  createdAt: string
  updatedAt: string
  retiredAt: string | null
}

export type CreateVexStatementRequest = {
  purl: string
  componentVersion?: string | null
  advisoryId: string
  status: VexStatementStatus
  justification?: VexJustification | null
  impactStatement?: string | null
  responseReferenceUrl?: string | null
}

export type UpdateVexStatementRequest = {
  status?: VexStatementStatus
  justification?: VexJustification | null
  impactStatement?: string | null
  responseReferenceUrl?: string | null
}

export async function fetchVexStatements(
  projectId: string,
  includeRetired = false,
): Promise<VexStatement[]> {
  const qs = includeRetired ? '?includeRetired=true' : ''
  const r = await fetch(`${API_BASE}/projects/${projectId}/vex-statements${qs}`)
  if (!r.ok) throw new Error(`GET /projects/${projectId}/vex-statements failed: ${r.status}`)
  return r.json()
}

export async function createVexStatement(projectId: string, req: CreateVexStatementRequest): Promise<VexStatement> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/vex-statements`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
  if (!r.ok) throw new Error(`POST /projects/${projectId}/vex-statements failed: ${r.status}`)
  return r.json()
}

export async function updateVexStatement(id: string, patch: UpdateVexStatementRequest): Promise<VexStatement> {
  const r = await fetch(`${API_BASE}/vex-statements/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  if (!r.ok) throw new Error(`PATCH /vex-statements/${id} failed: ${r.status}`)
  return r.json()
}

export async function retireVexStatement(id: string): Promise<void> {
  const r = await fetch(`${API_BASE}/vex-statements/${id}`, { method: 'DELETE' })
  if (!r.ok && r.status !== 404) throw new Error(`DELETE /vex-statements/${id} failed: ${r.status}`)
}

// ----- POA&M items --------------------------------------------------------

// NIST SP 800-53 CA-5 / FedRAMP continuous monitoring lifecycle.
// Open / InProgress = live; Completed / RiskAccepted / Cancelled = terminal.
export type PoamStatus =
  | 'Open'
  | 'InProgress'
  | 'Completed'
  | 'RiskAccepted'
  | 'Cancelled'

export type PoamItem = {
  id: string
  projectId: string
  title: string
  weaknessDescription: string
  mitigationPlan: string | null
  resourcesRequired: string | null
  severity: Severity
  status: PoamStatus
  scheduledCompletionDate: string | null
  actualCompletionDate: string | null
  linkedFindingIds: string[]
  referenceUrl: string | null
  authorUserId: string
  createdAt: string
  updatedAt: string
  closedAt: string | null
  isPastDue: boolean
}

export type CreatePoamItemRequest = {
  title: string
  weaknessDescription: string
  mitigationPlan?: string | null
  resourcesRequired?: string | null
  severity: Severity
  status?: PoamStatus
  scheduledCompletionDate?: string | null
  linkedFindingIds?: string[]
  referenceUrl?: string | null
}

export type UpdatePoamItemRequest = {
  title?: string
  weaknessDescription?: string
  mitigationPlan?: string | null
  resourcesRequired?: string | null
  severity?: Severity
  status?: PoamStatus
  scheduledCompletionDate?: string | null
  linkedFindingIds?: string[]
  referenceUrl?: string | null
}

export type PoamListFilters = {
  includeClosed?: boolean
  pastDueOnly?: boolean
  status?: PoamStatus
}

export async function fetchPoamItems(projectId: string, filters: PoamListFilters = {}): Promise<PoamItem[]> {
  const params = new URLSearchParams()
  if (filters.includeClosed) params.set('includeClosed', 'true')
  if (filters.pastDueOnly) params.set('pastDueOnly', 'true')
  if (filters.status) params.set('status', filters.status)
  const qs = params.toString() ? `?${params.toString()}` : ''
  const r = await fetch(`${API_BASE}/projects/${projectId}/poam-items${qs}`)
  if (!r.ok) throw new Error(`GET /projects/${projectId}/poam-items failed: ${r.status}`)
  return r.json()
}

export async function createPoamItem(projectId: string, req: CreatePoamItemRequest): Promise<PoamItem> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/poam-items`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
  if (!r.ok) throw new Error(`POST /projects/${projectId}/poam-items failed: ${r.status}`)
  return r.json()
}

export async function updatePoamItem(id: string, patch: UpdatePoamItemRequest): Promise<PoamItem> {
  const r = await fetch(`${API_BASE}/poam-items/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  if (!r.ok) throw new Error(`PATCH /poam-items/${id} failed: ${r.status}`)
  return r.json()
}

export async function cancelPoamItem(id: string): Promise<void> {
  const r = await fetch(`${API_BASE}/poam-items/${id}`, { method: 'DELETE' })
  if (!r.ok && r.status !== 404) throw new Error(`DELETE /poam-items/${id} failed: ${r.status}`)
}

// ----- VDP (Vulnerability Disclosure Policy) ------------------------------

export type ProjectVdp = {
  projectId: string
  vdpPolicyUrl: string | null
  vdpContactEmail: string | null
  vdpReportingFormUrl: string | null
}

export async function fetchProjectVdp(projectId: string): Promise<ProjectVdp> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/vdp`)
  if (!r.ok) throw new Error(`GET /projects/${projectId}/vdp failed: ${r.status}`)
  return r.json()
}

export async function updateProjectVdp(projectId: string, patch: Omit<ProjectVdp, 'projectId'>): Promise<ProjectVdp> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/vdp`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(patch),
  })
  if (!r.ok) throw new Error(`PUT /projects/${projectId}/vdp failed: ${r.status}`)
  return r.json()
}

// ----- SSDF attestation ---------------------------------------------------

// TFND-31: CISA SSDF (NIST SP 800-218) attestation surface. The
// backend assembles a doc with per-practice evidence drawn from
// ingest data; the SPA renders + supports JSON export for the
// FedRAMP package.
export type SsdfPracticeStatus = 'Yes' | 'No' | 'Partial' | 'Manual'

export type SsdfPractice = {
  id: string
  family: 'PO' | 'PS' | 'PW' | 'RV' | string
  label: string
  intent: string
  status: SsdfPracticeStatus
  evidence: string
}

export type SsdfGateLine = {
  key: string
  passed: boolean
  observed: string
}

export type SsdfAttestation = {
  generated: string
  project: { id: string; name: string; clientName: string }
  build: { commitSha: string | null; versionString: string; latestCreatedAt: string } | null
  risk: { score: number; band: string; policyName: string } | null
  gates: {
    enabled: number
    passed: number
    failed: number
    results: SsdfGateLine[]
  } | null
  practices: SsdfPractice[]
  summary: {
    yes: number
    partial: number
    no: number
    manual: number
    headline: string
  }
}

export async function fetchSsdfAttestation(projectId: string): Promise<SsdfAttestation> {
  const r = await fetch(`${API_BASE}/projects/${projectId}/ssdf-attestation`)
  if (!r.ok) throw new Error(`GET /projects/${projectId}/ssdf-attestation failed: ${r.status}`)
  return r.json()
}

// ----- Project scan receipts (per-build) ----------------------------------

export async function fetchProjectScanReceipts(
  projectId: string,
  opts: { take?: number; includeNonCanonical?: boolean } = {},
): Promise<{ builds: BuildReceipt[] }> {
  const params = new URLSearchParams()
  params.set('take', String(opts.take ?? 25))
  if (opts.includeNonCanonical) params.set('includeNonCanonical', 'true')
  const r = await fetch(`${API_BASE}/projects/${projectId}/scan-receipts?${params.toString()}`)
  if (!r.ok) throw new Error(`GET /projects/${projectId}/scan-receipts failed: ${r.status}`)
  return r.json()
}
