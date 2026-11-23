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
    vulnerabilities: { scanned: true, status: 'clean', total: 0, scannedAt: '2026-01-01T10:05:00Z' },
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
    vulnerabilities: { scanned: false, status: 'not_scanned' },
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
