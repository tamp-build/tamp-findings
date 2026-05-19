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

export type AggregatesResponse = {
  scope: AggregateScope
  findings: {
    counts: SeverityCounts
    byScanner: Record<string, number>
    byStatus: Record<string, number>
    byScannerDetail: ScannerDetail[]
  }
  sbom: {
    componentsCount: number
    vulnerabilitiesCount: number
    byEcosystem: Record<string, number>
  }
}

export type AggregatesFilters = {
  clientId?: string
  projectId?: string
  componentId?: string
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
