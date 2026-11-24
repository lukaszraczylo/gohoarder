<template>
  <div class="flex flex-col gap-6">
    <PageHeader
      :title="showOnlyBlocked ? 'Blocked packages' : 'Vulnerable packages'"
      :description="
        showOnlyBlocked
          ? 'Packages blocked from download because they exceed the vulnerability thresholds.'
          : 'Packages with known security vulnerabilities, sorted by risk.'
      "
    >
      <template #back>
        <Button variant="ghost" size="sm" :icon-start="faArrowLeft" @click="goBack">Back to stats</Button>
      </template>
    </PageHeader>

    <LoadingState v-if="loading" variant="card" label="Loading vulnerable packages..." />

    <ErrorState
      v-else-if="error"
      variant="card"
      title="Could not load vulnerable packages"
      :message="error"
      @retry="fetchVulnerablePackages"
    />

    <Card v-else-if="vulnerablePackages.length === 0">
      <CardContent>
        <EmptyState
          tone="success"
          :icon="faCircleCheck"
          :title="showOnlyBlocked ? 'No blocked packages' : 'No vulnerable packages'"
          description="Every cached package is clean."
        />
      </CardContent>
    </Card>

    <template v-else>
      <SeveritySummary
        v-model="selectedSeverities"
        selectable
        :counts="totalCounts"
        :package-counts="packageCounts"
        label="Vulnerabilities by severity. Select a severity to filter the packages."
      />

      <div v-if="hasFilter" class="flex flex-wrap items-center justify-between gap-3" data-testid="filter-bar">
        <p class="text-sm text-muted-foreground" role="status">Showing packages with {{ filterSummary }} vulnerabilities.</p>
        <Button variant="outline" size="sm" @click="clearFilters">Clear filters</Button>
      </div>

      <Card v-if="sortedVulnerablePackages.length === 0">
        <CardContent>
          <EmptyState
            :icon="faCircleCheck"
            title="No packages match the filter"
            :description="`No ${showOnlyBlocked ? 'blocked' : 'vulnerable'} package has a ${filterSummary} vulnerability.`"
          >
            <template #action>
              <Button variant="outline" @click="clearFilters">Clear filters</Button>
            </template>
          </EmptyState>
        </CardContent>
      </Card>

      <Card v-else>
        <CardHeader>
          <CardTitle as="h2">
            {{ showOnlyBlocked ? 'Blocked' : 'Vulnerable' }} packages ({{ sortedVulnerablePackages.length }})
          </CardTitle>
          <CardDescription>
            {{ groupedPackages.length }} unique package{{ groupedPackages.length !== 1 ? 's' : '' }}, most critical first
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="multiple" class="w-full">
            <AccordionItem
              v-for="group in groupedPackages"
              :key="`${group.registry}:${group.name}`"
              :value="`${group.registry}:${group.name}`"
            >
              <AccordionTrigger :heading-level="3">
                <span class="flex w-full min-w-0 items-center justify-between gap-4">
                  <span class="min-w-0 text-start">
                    <span class="block break-words font-semibold">{{ group.name }}</span>
                    <span class="block text-sm text-muted-foreground">
                      {{ group.versions.length }} vulnerable version{{ group.versions.length > 1 ? 's' : '' }}
                    </span>
                  </span>
                  <span class="flex shrink-0 items-center gap-4">
                    <Badge variant="outline">{{ group.registry }}</Badge>
                    <span class="whitespace-nowrap text-end tabular-nums">
                      <span class="block text-sm font-medium">{{ formatBytes(group.totalSize) }}</span>
                      <span class="block text-xs text-muted-foreground">{{ formatNumber(group.totalDownloads) }} downloads</span>
                    </span>
                  </span>
                </span>
              </AccordionTrigger>
              <AccordionContent>
                <DataTable
                  :label="`Vulnerable versions of ${group.name}`"
                  layout="cards"
                  row-clickable
                  :columns="versionColumns"
                  :rows="group.versions"
                  @row-click="navigateToPackage"
                >
                  <template #cell-vulnerabilities="{ row }">
                    <VulnerabilityBadge
                      v-if="row.vulnerabilities"
                      :scanned="row.vulnerabilities.scanned"
                      :status="row.vulnerabilities.status"
                      :counts="row.vulnerabilities.counts"
                      :total="row.vulnerabilities.total"
                      :scannedAt="row.vulnerabilities.scannedAt"
                      :isBlocked="row.vulnerabilities.isBlocked"
                      @click="navigateToPackage(row)"
                    />
                  </template>
                </DataTable>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { usePackageStore, type Package, type VulnerabilityCounts } from '../stores/packages'
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataTable,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  type DataTableColumn,
} from '@perfect-design/ui'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import SeveritySummary from './SeveritySummary.vue'
import { formatBytes, formatDate, formatNumber, displayVersion, withVersionPrefix } from '@/lib/format'
import { faArrowLeft, faCircleCheck } from '@/lib/icons'
import { NO_VULNERABILITIES, SEVERITY_LEVELS, formatSeverityName, type SeverityLevel } from '@/lib/severity'

const store = usePackageStore()
const router = useRouter()
const route = useRoute()

const SEVERITY_QUERY = 'severity'

/** Reads `?severity=critical,high`: known levels only, in severity order, each once. */
function parseSeverityQuery(raw: unknown): SeverityLevel[] {
  const text = Array.isArray(raw) ? raw.join(',') : typeof raw === 'string' ? raw : ''
  const wanted = text.split(',').map((part) => part.trim().toLowerCase())
  return SEVERITY_LEVELS.filter((level) => wanted.includes(level))
}

// The URL is the source of truth, so a reload or a shared link restores the filter.
const selectedSeverities = computed<SeverityLevel[]>({
  get: () => parseSeverityQuery(route.query[SEVERITY_QUERY]),
  set: (levels) => {
    const { [SEVERITY_QUERY]: _previous, ...rest } = route.query
    void router.replace({ query: levels.length > 0 ? { ...rest, [SEVERITY_QUERY]: levels.join(',') } : rest })
  },
})
const hasFilter = computed(() => selectedSeverities.value.length > 0)
const filterSummary = computed(() =>
  selectedSeverities.value.map((level) => formatSeverityName(level).toLowerCase()).join(' or '),
)

function clearFilters() {
  selectedSeverities.value = []
}

const loading = ref(false)
const error = ref<string | null>(null)
const vulnerablePackages = ref<Package[]>([])

// Check if we should filter to show only blocked packages
const showOnlyBlocked = computed(() => route.path === '/blocked-packages')

onMounted(async () => {
  await fetchVulnerablePackages()
})

async function fetchVulnerablePackages() {
  loading.value = true
  error.value = null

  try {
    // The server drops clean packages; the toggles below narrow the rest without another request.
    await store.fetchPackages({ severity: SEVERITY_LEVELS })
    // The store records a failed request in store.error and resolves; surface it instead of an empty list.
    if (store.error) {
      error.value = store.error
      return
    }
    vulnerablePackages.value = store.packages.filter(pkg => {
      const isVulnerable = pkg.vulnerabilities?.status === 'vulnerable'
      if (showOnlyBlocked.value) {
        return isVulnerable && pkg.vulnerabilities?.isBlocked === true
      }
      return isVulnerable
    })
  } catch (err: any) {
    console.error('Failed to load vulnerable packages:', err)
    error.value = err.message || 'Failed to load vulnerable packages'
  } finally {
    loading.value = false
  }
}

// A package passes when it has at least one vulnerability of any selected severity.
const filteredPackages = computed(() => {
  if (!hasFilter.value) return vulnerablePackages.value
  return vulnerablePackages.value.filter((pkg) =>
    selectedSeverities.value.some((level) => (pkg.vulnerabilities?.counts?.[level] ?? 0) > 0),
  )
})

// Sort packages by risk: Critical count DESC, High count DESC, Moderate count DESC, Low count DESC
const sortedVulnerablePackages = computed(() => {
  return [...filteredPackages.value].sort((a, b) => {
    const aVulns = a.vulnerabilities?.counts || { critical: 0, high: 0, moderate: 0, low: 0 }
    const bVulns = b.vulnerabilities?.counts || { critical: 0, high: 0, moderate: 0, low: 0 }

    // Compare critical count (descending)
    if (aVulns.critical !== bVulns.critical) {
      return bVulns.critical - aVulns.critical
    }

    // Compare high count (descending)
    if (aVulns.high !== bVulns.high) {
      return bVulns.high - aVulns.high
    }

    // Compare moderate count (descending)
    if (aVulns.moderate !== bVulns.moderate) {
      return bVulns.moderate - aVulns.moderate
    }

    // Compare low count (descending)
    return bVulns.low - aVulns.low
  })
})

// Group packages by name and registry, with versions sorted by risk
const groupedPackages = computed(() => {
  const groups = new Map<string, {
    registry: string
    name: string
    versions: Package[]
    totalSize: number
    totalDownloads: number
  }>()

  sortedVulnerablePackages.value.forEach((pkg) => {
    const key = `${pkg.registry}:${pkg.name}`
    if (!groups.has(key)) {
      groups.set(key, {
        registry: pkg.registry,
        name: pkg.name,
        versions: [],
        totalSize: 0,
        totalDownloads: 0,
      })
    }
    const group = groups.get(key)!
    group.versions.push(pkg)
    group.totalSize += pkg.size || 0
    group.totalDownloads += pkg.download_count || 0
  })

  return Array.from(groups.values())
})

// Packages holding at least one vulnerability of each severity, before any filter.
const packageCounts = computed<VulnerabilityCounts>(() => {
  const counts = { ...NO_VULNERABILITIES }
  for (const pkg of vulnerablePackages.value) {
    for (const level of SEVERITY_LEVELS) {
      if ((pkg.vulnerabilities?.counts?.[level] ?? 0) > 0) counts[level]++
    }
  }
  return counts
})

// Calculate total counts across all packages, before any filter
const totalCounts = computed(() =>
  vulnerablePackages.value.reduce(
    (sum, pkg) => {
      const counts = pkg.vulnerabilities?.counts ?? NO_VULNERABILITIES
      return {
        critical: sum.critical + counts.critical,
        high: sum.high + counts.high,
        moderate: sum.moderate + counts.moderate,
        low: sum.low + counts.low,
      }
    },
    { ...NO_VULNERABILITIES },
  ),
)

const versionColumns: DataTableColumn<Package>[] = [
  { key: 'version', header: 'Version', rowHeader: true, accessor: (pkg) => withVersionPrefix(displayVersion(pkg)) },
  { key: 'download_count', header: 'Downloads', numeric: true, accessor: (pkg) => formatNumber(pkg.download_count) },
  { key: 'size', header: 'Size', numeric: true, accessor: (pkg) => formatBytes(pkg.size) },
  { key: 'cached_at', header: 'Cached', accessor: (pkg) => formatDate(pkg.cached_at) },
  { key: 'vulnerabilities', header: 'Vulnerabilities', accessor: () => '' },
]

function navigateToPackage(pkg: Package) {
  router.push(`/package/${pkg.registry}/${pkg.name}/${pkg.version}`)
}

function goBack() {
  router.push('/stats')
}
</script>
