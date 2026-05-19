// Tiny fetch wrapper. Goes through the Vite dev-proxy mapping /api → :5080
// (see vite.config.ts). In prod the SPA is served from the same origin as
// the API, so the same /api path works without a proxy.

export const API_BASE = '/api'

export type ScannerKind =
  | 'Unknown' | 'OpenGrep' | 'TruffleHog' | 'CodeQL' | 'Trivy'
  | 'Checkov' | 'Tfsec' | 'Kics' | 'Zap' | 'Spectral' | 'Oasdiff'
  | 'Cosign' | 'NetArchTest' | 'DependencyCruiser' | 'Stryker' | 'Coverlet'
  | 'OsvScanner' | 'Roslyn' | 'Syft' | 'Grype'

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

export type SbomComponentsFilters = {
  componentVersionId?: string
  ecosystem?: string
  search?: string
  latest?: boolean
  skip?: number
  take?: number
}

export async function fetchSbomComponents(filters: SbomComponentsFilters = {}): Promise<SbomComponentsListResponse> {
  const params = new URLSearchParams()
  if (filters.componentVersionId) params.set('componentVersionId', filters.componentVersionId)
  if (filters.ecosystem) params.set('ecosystem', filters.ecosystem)
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
