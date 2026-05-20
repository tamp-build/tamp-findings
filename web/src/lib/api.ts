// Tiny fetch wrapper. Goes through the Vite dev-proxy mapping /api → :5080
// (see vite.config.ts). In prod the SPA is served from the same origin as
// the API, so the same /api path works without a proxy.

export const API_BASE = '/api'

export type ScannerKind =
  | 'Unknown' | 'OpenGrep' | 'TruffleHog' | 'CodeQL' | 'Trivy'
  | 'Checkov' | 'Tfsec' | 'Kics' | 'Zap' | 'Spectral' | 'Oasdiff'
  | 'Cosign' | 'NetArchTest' | 'DependencyCruiser' | 'Stryker' | 'Coverlet'
  | 'OsvScanner' | 'Roslyn' | 'Syft' | 'Grype' | 'ReSharper'

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

export type ClientListItem = { id: string; name: string; projectCount: number }
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
