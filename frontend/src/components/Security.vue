<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Security" description="Packages the scanners found something in, and what the policy did about each.">
      <template #actions>
        <Button variant="outline" :icon-start="faRotateRight" @click="load">Refresh</Button>
      </template>
    </PageHeader>

    <LoadingState v-if="loading && !loaded" variant="table" label="Loading security findings..." />

    <ErrorState v-else-if="error" variant="card" title="Could not load security findings" :message="error" @retry="load" />

    <template v-else>
      <SeveritySummary
        v-if="anyFindings"
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
          <TabsTrigger v-for="t in TAB_DEFS" :key="t.value" :value="t.value">{{ t.label }} ({{ tabCount(t.value) }})</TabsTrigger>
        </TabsList>

        <TabsContent v-for="t in TAB_DEFS" :key="t.value" :value="t.value" class="pt-4">
          <Card>
            <CardHeader>
              <CardTitle as="h2">{{ t.label }}</CardTitle>
              <CardDescription>{{ t.description }}</CardDescription>
            </CardHeader>
            <CardContent>
              <EmptyState
                v-if="total === 0"
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
                v-model:sort="sort"
                :label="t.label"
                layout="cards"
                density="compact"
                row-clickable
                :loading="loading"
                :columns="columnsFor(t.value)"
                :rows="rows"
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
              <Pagination
                v-if="total > PAGE_SIZE"
                v-model:page="page"
                class="mt-4"
                :total="total"
                :page-size="PAGE_SIZE"
                aria-label="Security pages"
              />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
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
  Pagination,
  RelativeTime,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  type DataTableColumn,
  type SortState,
} from '@perfect-design/ui'
import SeveritySummary from './SeveritySummary.vue'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import type { Package, VulnerabilityCounts } from '../stores/packages'
import { displayVersion, withVersionPrefix } from '@/lib/format'
import { packageRoute } from '@/lib/packages'
import { usePackageRows, type RowQuery, type RowSort } from '@/lib/packageRows'
import { humanReason } from '@/lib/reason'
import { faCircleCheck, faRotateRight } from '@/lib/icons'
import { SEVERITY_LEVELS, formatSeverityName, type SeverityLevel } from '@/lib/severity'

type TabName = 'held' | 'allowed' | 'bypassed'

const TAB_DEFS: ReadonlyArray<{ value: TabName; label: string; description: string; empty: string }> = [
  { value: 'held', label: 'Held', description: 'At or over the block policy. Clients get a 403 until the package is fixed or bypassed.', empty: 'Nothing is held' },
  { value: 'allowed', label: 'Vulnerable but allowed', description: 'Findings exist, but none reach the block policy. Clients are served these.', empty: 'No package carries findings under the policy' },
  { value: 'bypassed', label: 'Bypassed', description: 'An admin bypass lets these through despite their findings.', empty: 'No bypass is in effect' },
]

const PAGE_SIZE = 25
const SEVERITY_QUERY = 'severity'

const route = useRoute()
const router = useRouter()
const { rows, total, counts, loading, error, load: loadRows } = usePackageRows()

const loaded = ref(false)
const page = ref(1)
const sort = ref<SortState | null>(null)

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

const anyFindings = computed(() => counts.value.verdicts.held + counts.value.vulnerable_allowed + counts.value.verdicts.bypassed > 0)
// With nothing to filter the tiles are hidden, so a leftover ?severity= must not claim a filter is on.
const hasFilter = computed(() => selectedSeverities.value.length > 0 && anyFindings.value)
const filterSummary = computed(() => selectedSeverities.value.map((level) => formatSeverityName(level).toLowerCase()).join(' or '))

function tabCount(name: TabName): number {
  if (name === 'held') return counts.value.verdicts.held
  if (name === 'bypassed') return counts.value.verdicts.bypassed
  return counts.value.vulnerable_allowed
}

const severityTotals = computed<VulnerabilityCounts>(() => ({ ...counts.value.severity_findings }))
const severityPackages = computed<VulnerabilityCounts>(() => ({ ...counts.value.severity_packages }))

const SORT_KEYS: Record<string, RowSort> = { name: 'name', version: 'version', registry: 'registry', scanned: 'last_scanned' }

// "Vulnerable but allowed" is the cleared packages that have findings, so it always filters by severity.
const rowQuery = computed<RowQuery>(() => {
  const severity = selectedSeverities.value.length > 0 ? selectedSeverities.value : tab.value === 'allowed' ? SEVERITY_LEVELS : []
  return {
    verdict: tab.value === 'allowed' ? 'cleared' : tab.value,
    severity,
    // Worst first unless the operator picked a column.
    sort: sort.value ? SORT_KEYS[sort.value.key] : 'risk',
    order: sort.value ? (sort.value.direction === 'desc' ? 'desc' : 'asc') : 'desc',
    page: page.value,
    pageSize: PAGE_SIZE,
  }
})

watch([tab, selectedSeverities, sort], () => (page.value = 1))

const BASE_COLUMNS: DataTableColumn<Package>[] = [
  { key: 'name', header: 'Package', sortable: true, rowHeader: true },
  { key: 'version', header: 'Version', sortable: true, accessor: (p) => withVersionPrefix(displayVersion(p)) },
  { key: 'registry', header: 'Registry', sortable: true },
  { key: 'findings', header: 'Findings', accessor: (p) => p.vulnerabilities?.total ?? 0 },
]
const SCANNED: DataTableColumn<Package> = { key: 'scanned', header: 'Last scanned', sortable: true, accessor: (p) => Date.parse(p.vulnerabilities?.scannedAt ?? '') || 0 }

function columnsFor(name: TabName): DataTableColumn<Package>[] {
  if (name === 'held') return [...BASE_COLUMNS, { key: 'reason', header: 'Why', accessor: (p) => humanReason(p.vulnerabilities?.reason) }, SCANNED]
  if (name === 'bypassed') return [...BASE_COLUMNS, { key: 'bypass', header: 'Bypass', accessor: (p) => p.vulnerabilities?.bypass?.created_by ?? '' }, SCANNED]
  return [...BASE_COLUMNS, SCANNED]
}

function open(pkg: Package) {
  void router.push(packageRoute(pkg))
}

async function load() {
  await loadRows(rowQuery.value)
  loaded.value = true
}

watch(rowQuery, load)
onMounted(load)
</script>
