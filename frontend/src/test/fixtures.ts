import type { Package, Stats } from '@/stores/packages'

export const STATS: Stats = {
  registry: '',
  total_packages: 4,
  total_size: 5368709120,
  max_cache_size: 10737418240,
  total_downloads: 120,
  scanned_packages: 3,
  vulnerable_packages: 2,
  blocked_packages: 1,
  bypassed_packages: 1,
}

export const REGISTRIES = {
  npm: { count: 2, size: 2147483648, downloads: 80 },
  pypi: { count: 1, size: 1073741824, downloads: 30 },
  go: { count: 1, size: 2147483648, downloads: 10 },
}

export const PACKAGES: Package[] = [
  {
    id: 'npm-1',
    registry: 'npm',
    name: 'left-pad',
    version: '1.3.0',
    size: 2048,
    cached_at: '2026-01-03T10:00:00Z',
    last_accessed: '2026-01-03T10:00:00Z',
    download_count: 40,
    vulnerabilities: {
      scanned: true,
      status: 'vulnerable',
      counts: { critical: 1, high: 2, moderate: 0, low: 1 },
      total: 4,
      scannedAt: '2026-01-03T10:05:00Z',
      isBlocked: true,
      verdict: 'held',
      reason: 'Package has 1 CRITICAL vulnerabilities (threshold: 0)',
    },
  },
  {
    id: 'npm-2',
    registry: 'npm',
    name: 'left-pad',
    version: '1.2.0',
    size: 1024,
    cached_at: '2026-01-02T10:00:00Z',
    last_accessed: '2026-01-02T10:00:00Z',
    download_count: 40,
    vulnerabilities: {
      scanned: true,
      status: 'vulnerable',
      counts: { critical: 0, high: 0, moderate: 3, low: 0 },
      total: 3,
      scannedAt: '2026-01-02T10:05:00Z',
      isBlocked: false,
      verdict: 'cleared',
    },
  },
  {
    id: 'pypi-1',
    registry: 'pypi',
    name: 'requests',
    version: '2.31.0',
    size: 4096,
    cached_at: '2026-01-01T10:00:00Z',
    last_accessed: '2026-01-01T10:00:00Z',
    download_count: 30,
    vulnerabilities: {
      scanned: true,
      status: 'vulnerable',
      counts: { critical: 1, high: 0, moderate: 0, low: 0 },
      total: 1,
      scannedAt: '2026-01-01T10:05:00Z',
      isBlocked: false,
      verdict: 'bypassed',
      bypass: {
        id: 'bypass-1',
        type: 'package',
        target: 'pypi/requests@2.31.0',
        reason: 'Vendored fix',
        created_by: 'a.khan',
        created_at: '2026-01-01T00:00:00Z',
        expires_at: '2099-01-01T00:00:00Z',
      },
    },
  },
  {
    id: 'go-1',
    registry: 'go',
    name: 'github.com/example/module',
    version: 'v0.4.1',
    size: 512,
    cached_at: '2026-01-04T10:00:00Z',
    last_accessed: '2026-01-04T10:00:00Z',
    download_count: 10,
    vulnerabilities: { scanned: false, status: 'not_scanned', isBlocked: false, verdict: 'pending' },
  },
]

export const TIMESERIES = {
  period: '1day',
  registry: '',
  data_points: [
    { timestamp: '2026-01-04T08:00:00Z', value: 3 },
    { timestamp: '2026-01-04T09:00:00Z', value: 7 },
    { timestamp: '2026-01-04T10:00:00Z', value: 5 },
  ],
}

export const VULNERABILITY_REPORT = {
  decision: {
    verdict: 'held',
    blocked: true,
    reason: 'Package has 1 CRITICAL vulnerabilities (threshold: 0)',
    bypass: null,
  },
  scanners: [
    { name: 'trivy', findings: 2, severity_counts: { critical: 1, high: 0, moderate: 0, low: 1 } },
    { name: 'osv', findings: 3, severity_counts: { critical: 1, high: 1, moderate: 0, low: 1 } },
  ],
  scanned: true,
  scanner: 'trivy+osv',
  scanned_at: '2026-01-03T10:05:00Z',
  status: 'vulnerable',
  vulnerability_count: 3,
  bypassed_count: 1,
  severity_counts: { critical: 1, high: 1, moderate: 0, low: 1 },
  vulnerabilities: [
    {
      id: 'CVE-2026-0001',
      severity: 'LOW',
      title: 'Low severity sample',
      description: 'A **low** severity sample description.',
      references: ['https://example.com/advisory/1'],
      fixed_in: '1.3.1',
      detected_by: ['trivy', 'osv'],
      bypassed: false,
    },
    {
      id: 'CVE-2026-0002',
      severity: 'CRITICAL',
      title: 'Critical severity sample',
      description: 'A critical severity sample description.',
      references: [],
      fixed_in: '',
      bypassed: true,
      bypass: {
        id: 'bypass-1',
        reason: 'No fix available',
        created_by: 'admin@example.com',
        expires_at: '2026-02-01T00:00:00Z',
      },
    },
    {
      id: 'CVE-2026-0003',
      severity: 'HIGH',
      title: '',
      description: 'A high severity sample description.',
      references: [],
      fixed_in: '2.0.0',
      bypassed: false,
    },
  ],
}

export const BYPASSES = [
  {
    id: 'bypass-1',
    type: 'cve',
    target: 'CVE-2026-0002',
    reason: 'No fix available',
    created_by: 'admin@example.com',
    created_at: '2026-01-01T00:00:00Z',
    expires_at: '2099-01-01T00:00:00Z',
    applies_to: 'npm/left-pad@1.3.0',
    notify_on_expiry: true,
    active: true,
  },
  {
    id: 'bypass-2',
    type: 'package',
    target: 'npm/left-pad',
    reason: 'Pinned until the next release',
    created_by: 'admin@example.com',
    created_at: '2025-01-01T00:00:00Z',
    expires_at: '2025-02-01T00:00:00Z',
    notify_on_expiry: false,
    active: false,
  },
]

function trendDay(offset: number): string {
  return new Date(Date.UTC(2026, 0, 4 + offset)).toISOString().slice(0, 10)
}

export const TREND = {
  period: '30day',
  from: trendDay(-2),
  to: trendDay(0),
  vulnerability_history_start: trendDay(-1),
  points: [
    { date: trendDay(-2), total_packages: 3, total_size: 3072, vulnerable_packages: null, critical: null, high: null, moderate: null, low: null, blocked: null },
    { date: trendDay(-1), total_packages: 4, total_size: 7168, vulnerable_packages: 1, critical: 0, high: 1, moderate: 0, low: 0, blocked: null },
    { date: trendDay(0), total_packages: 4, total_size: 7168, vulnerable_packages: 2, critical: 1, high: 1, moderate: 0, low: 0, blocked: 1 },
  ],
}

export const SYSTEM = {
  version: 'v1.8.0',
  security: {
    enabled: true,
    fail_closed: true,
    scan_on_download: true,
    block_on_severity: 'none',
    block_thresholds: { critical: 0, high: -1, moderate: -1, low: -1 },
    scan_wait_timeout: 30,
    scanners: [
      { name: 'trivy', enabled: true, healthy: true, version: '0.58.1' },
      { name: 'grype', enabled: true, healthy: false, version: '' },
      { name: 'osv', enabled: true, healthy: true, version: '' },
      { name: 'govulncheck', enabled: false, healthy: null, version: '' },
    ],
    rescan: { interval: 86400, active_window: 2592000, concurrency: 2, on_access: false },
  },
  upstreams: { go: 'https://proxy.golang.org', npm: 'https://registry.npmjs.org', pypi: 'https://pypi.org' },
  cache: { max_size: 10737418240, idle_ttl: 2592000, default_ttl: 86400 },
  prewarming: { enabled: true, interval: 3600, top_packages: 100 },
}

export const TOP_PACKAGES = {
  packages: [
    { Registry: 'npm', Name: 'left-pad', Downloads: 40, RecentDownloads: 12, Trend: 0.4 },
    { Registry: 'go', Name: 'github.com/example/module/@v/v0.4.1.zip', Downloads: 10, RecentDownloads: 4, Trend: 0 },
  ],
  total: 2,
}

export const PACKAGE_ANALYTICS = {
  package: {
    Registry: 'npm',
    Name: 'left-pad',
    TotalDownloads: 40,
    UniqueVersions: 2,
    BytesServed: 81920,
    FirstSeen: '2026-01-01T10:00:00Z',
    LastDownload: '2026-01-03T10:00:00Z',
  },
}
