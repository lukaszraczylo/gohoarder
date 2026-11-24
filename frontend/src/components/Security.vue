<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Security" description="Packages the scanners found something in, and what the policy did about each.">
      <template #actions>
        <Button variant="outline" :icon-start="faRotateRight" @click="load">Refresh</Button>
      </template>
    </PageHeader>

    <LoadingState v-if="loading && packages.length === 0" variant="table" label="Loading security findings..." />

    <ErrorState v-else-if="error" variant="card" title="Could not load security findings" :message="error" @retry="load" />

    <template v-else>
      <SeveritySummary
        v-if="everyBucketed.length > 0"
        v-model="selectedSeverities"
        selectable
        label="Findings by severity. Select a severity to filter the packages."
        :counts="severityTotals"
        :package-counts="severityPackages"
      />

      <div v-if="hasFilter" class="flex flex-wrap items-center justify-between gap-3" data-testid="filter-bar">
        <p class="m-0 text-sm text-muted-foreground" role="status">Showing packages with {{ filterSummary }} vulnerabilities.</p>
        <Button variant="outline" size="sm" @click="selectedSeverities = []">Clear filters</Button>
      </div>

      <Tabs v-model="tab">
        <TabsList aria-label="Security sections">
          <TabsTrigger v-for="t in TAB_DEFS" :key="t.value" :value="t.value">{{ t.label }} ({{ buckets[t.value].length }})</TabsTrigger>
        </TabsList>

        <TabsContent v-for="t in TAB_DEFS" :key="t.value" :value="t.value" class="pt-4">
          <Card>
            <CardHeader>
              <CardTitle as="h2">{{ t.label }}</CardTitle>
              <CardDescription>{{ t.description }}</CardDescription>
            </CardHeader>
            <CardContent>
              <EmptyState
                v-if="rowsFor(t.value).length === 0"
                :icon="faCircleCheck"
                :title="hasFilter ? 'No packages match the filter' : t.empty"
                :description="hasFilter ? `No package here has a ${filterSummary} vulnerability.` : undefined"
              >
                <template v-if="hasFilter" #action>
                  <Button variant="outline" @click="selectedSeverities = []">Clear filters</Button>
                </template>
              </EmptyState>
              <DataTable
                v-else
                :label="t.label"
                layout="cards"
                density="compact"
                row-clickable
                :page-size="PAGE_SIZE"
                :columns="columnsFor(t.value)"
                :rows="rowsFor(t.value)"
                @row-click="open"
              >
                <template #cell-name="{ row }">
                  <RouterLink :to="packageRoute(row)" class="break-words font-medium text-foreground underline-offset-4 hover:underline">
                    {{ row.name }}
                  </RouterLink>
                </template>
                <template #cell-registry="{ row }"><Badge variant="outline">{{ row.registry }}</Badge></template>
                <template #cell-findings="{ row }">
                  <VulnerabilityBadge
                    v-if="row.vulnerabilities"
                    :scanned="row.vulnerabilities.scanned"
                    :status="row.vulnerabilities.status"
                    :counts="row.vulnerabilities.counts"
                    :total="row.vulnerabilities.total"
                    @click="open(row)"
                  />
                </template>
                <template #cell-bypass="{ row }">
                  <span v-if="row.vulnerabilities?.bypass" class="block text-sm">
                    {{ row.vulnerabilities.bypass.created_by }}
                    <span class="block text-xs text-muted-foreground">
                      expires <RelativeTime :datetime="row.vulnerabilities.bypass.expires_at" />
                    </span>
                  </span>
                </template>
                <template #cell-scanned="{ row }">
                  <RelativeTime v-if="row.vulnerabilities?.scannedAt" :datetime="row.vulnerabilities.scannedAt" />
                </template>
              </DataTable>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import {
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
  RelativeTime,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  type DataTableColumn,
} from '@perfect-design/ui'
import SeveritySummary from './SeveritySummary.vue'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import { usePackageStore, type Package, type VulnerabilityCounts } from '../stores/packages'
import { displayVersion, withVersionPrefix } from '@/lib/format'
import { packageRoute } from '@/lib/packages'
import { faCircleCheck, faRotateRight } from '@/lib/icons'
import { NO_VULNERABILITIES, SEVERITY_LEVELS, formatSeverityName, type SeverityLevel } from '@/lib/severity'
import { verdictOf } from '@/lib/verdict'

type TabName = 'held' | 'allowed' | 'bypassed'

const TAB_DEFS: ReadonlyArray<{ value: TabName; label: string; description: string; empty: string }> = [
  { value: 'held', label: 'Held', description: 'At or over the block policy. Clients get a 403 until the package is fixed or bypassed.', empty: 'Nothing is held' },
  { value: 'allowed', label: 'Vulnerable but allowed', description: 'Findings exist, but none reach the block policy. Clients are served these.', empty: 'No package carries findings under the policy' },
  { value: 'bypassed', label: 'Bypassed', description: 'An admin bypass lets these through despite their findings.', empty: 'No bypass is in effect' },
]

const PAGE_SIZE = 25
const SEVERITY_QUERY = 'severity'

const store = usePackageStore()
const route = useRoute()
const router = useRouter()
const { packages, loading, error } = storeToRefs(store)

const tab = ref<TabName>(TAB_DEFS.find((t) => t.value === route.query.tab)?.value ?? 'held')
watch(tab, (value) => void router.replace({ query: { ...route.query, tab: value } }))

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
// With nothing to filter the tiles are hidden, so a leftover ?severity= must not claim a filter is on.
const hasFilter = computed(() => selectedSeverities.value.length > 0 && everyBucketed.value.length > 0)
const filterSummary = computed(() => selectedSeverities.value.map((level) => formatSeverityName(level).toLowerCase()).join(' or '))

/** Packages with findings, by what the policy did. A package with no findings is not a security matter. */
const buckets = computed<Record<TabName, Package[]>>(() => {
  const out: Record<TabName, Package[]> = { held: [], allowed: [], bypassed: [] }
  for (const pkg of packages.value) {
    const verdict = verdictOf(pkg)
    if (verdict === 'held') out.held.push(pkg)
    else if (verdict === 'bypassed') out.bypassed.push(pkg)
    else if (verdict === 'cleared' && (pkg.vulnerabilities?.total ?? 0) > 0) out.allowed.push(pkg)
  }
  return out
})

function risk(pkg: Package): number[] {
  const c = pkg.vulnerabilities?.counts ?? NO_VULNERABILITIES
  return [c.critical, c.high, c.moderate, c.low]
}

// Worst first: more critical, then high, then moderate, then low.
function byRisk(a: Package, b: Package): number {
  const [ra, rb] = [risk(a), risk(b)]
  for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return rb[i] - ra[i]
  return 0
}

function passesFilter(pkg: Package): boolean {
  if (!hasFilter.value) return true
  return selectedSeverities.value.some((level) => (pkg.vulnerabilities?.counts?.[level] ?? 0) > 0)
}

function rowsFor(name: TabName): Package[] {
  return buckets.value[name].filter(passesFilter).sort(byRisk)
}

const everyBucketed = computed(() => [...buckets.value.held, ...buckets.value.allowed, ...buckets.value.bypassed])

const severityTotals = computed<VulnerabilityCounts>(() => {
  const totals = { ...NO_VULNERABILITIES }
  for (const pkg of everyBucketed.value) for (const level of SEVERITY_LEVELS) totals[level] += pkg.vulnerabilities?.counts?.[level] ?? 0
  return totals
})

const severityPackages = computed<VulnerabilityCounts>(() => {
  const totals = { ...NO_VULNERABILITIES }
  for (const pkg of everyBucketed.value) for (const level of SEVERITY_LEVELS) if ((pkg.vulnerabilities?.counts?.[level] ?? 0) > 0) totals[level]++
  return totals
})

const BASE_COLUMNS: DataTableColumn<Package>[] = [
  { key: 'name', header: 'Package', sortable: true, rowHeader: true },
  { key: 'version', header: 'Version', accessor: (p) => withVersionPrefix(displayVersion(p)) },
  { key: 'registry', header: 'Registry' },
  { key: 'findings', header: 'Findings', accessor: (p) => p.vulnerabilities?.total ?? 0 },
]
const SCANNED: DataTableColumn<Package> = { key: 'scanned', header: 'Last scanned', accessor: (p) => Date.parse(p.vulnerabilities?.scannedAt ?? '') || 0 }

function columnsFor(name: TabName): DataTableColumn<Package>[] {
  if (name === 'held') return [...BASE_COLUMNS, { key: 'reason', header: 'Why', accessor: (p) => p.vulnerabilities?.reason ?? '' }, SCANNED]
  if (name === 'bypassed') return [...BASE_COLUMNS, { key: 'bypass', header: 'Bypass', accessor: (p) => p.vulnerabilities?.bypass?.created_by ?? '' }, SCANNED]
  return [...BASE_COLUMNS, SCANNED]
}

function open(pkg: Package) {
  void router.push(packageRoute(pkg))
}

async function load() {
  // Unfiltered: a package held because its scan failed has no findings, and the severity filter would drop it.
  await store.fetchPackages()
}

onMounted(load)
</script>
