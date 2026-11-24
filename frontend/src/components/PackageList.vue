<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Packages" description="Everything the proxy has cached and the verdict each package received.">
      <template #actions>
        <Button variant="outline" :icon-start="faRotateRight" @click="load()">Refresh</Button>
      </template>
    </PageHeader>

    <div class="flex flex-col gap-3">
      <SearchInput v-model="query" aria-label="Search packages" placeholder="Search by name or version..." class="w-full sm:max-w-md" />
      <FilterBar v-model="filterItems" :fields="filterFields" variant="compact" />
    </div>

    <LoadingState v-if="loading && packages.length === 0" variant="table" label="Loading packages..." />

    <ErrorState v-else-if="error" variant="card" title="Could not load packages" :message="error" @retry="load()" />

    <Card v-else>
      <CardContent>
        <EmptyState
          v-if="packages.length === 0"
          :icon="faBoxOpen"
          title="No packages cached yet"
          description="Packages will appear here once they are downloaded through the proxy."
        />
        <EmptyState
          v-else-if="rows.length === 0"
          :icon="faMagnifyingGlass"
          title="No packages match"
          description="Change the search text or remove a filter."
        />
        <template v-else>
          <p class="m-0 mb-3 text-sm text-muted-foreground" data-testid="package-count">
            {{ rows.length }} of {{ plural(packages.length, 'package version') }}
          </p>
          <DataTable
            v-model:sort="sort"
            v-model:page="page"
            label="Cached packages"
            layout="cards"
            density="compact"
            row-clickable
            :page-size="PAGE_SIZE"
            :columns="columns"
            :rows="rows"
            @row-click="(row: Package) => (selected = row)"
          >
            <template #cell-name="{ row }">
              <RouterLink :to="packageRoute(row)" class="break-words font-medium text-foreground underline-offset-4 hover:underline">
                {{ row.name }}
              </RouterLink>
            </template>
            <template #cell-registry="{ row }"><Badge variant="outline">{{ row.registry }}</Badge></template>
            <template #cell-size="{ row }">{{ formatBytes(row.size) }}</template>
            <template #cell-download_count="{ row }">{{ formatNumber(row.download_count) }}</template>
            <template #cell-last_accessed="{ row }"><RelativeTime :datetime="row.last_accessed" /></template>
            <template #cell-verdict="{ row }"><VerdictBadge :verdict="verdictOf(row)" /></template>
            <template #cell-scanned="{ row }">
              <RelativeTime v-if="row.vulnerabilities?.scannedAt" :datetime="row.vulnerabilities.scannedAt" />
              <span v-else class="text-muted-foreground">Never</span>
            </template>
          </DataTable>
        </template>
      </CardContent>
    </Card>

    <PackageQuickView :pkg="selected" @close="selected = null" @delete="confirmDelete" />

    <ConfirmDialog
      v-model:open="showDeleteModal"
      title="Remove package version?"
      :description="`Remove ${packageToDelete?.name}@${packageToDelete?.version} from the cache? Clients can fetch it again from upstream.`"
      confirm-label="Remove version"
      tone="danger"
      destructive
      @confirm="deletePackage"
    />
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
  ConfirmDialog,
  DataTable,
  EmptyState,
  ErrorState,
  FilterBar,
  LoadingState,
  PageHeader,
  RelativeTime,
  SearchInput,
  useToastStore,
  type DataTableColumn,
  type FilterField,
  type FilterItem,
  type SortState,
} from '@perfect-design/ui'
import PackageQuickView from './parts/PackageQuickView.vue'
import VerdictBadge from './parts/VerdictBadge.vue'
import { usePackageStore, type Package } from '../stores/packages'
import { plural } from '@/lib/reason'
import { displayVersion, formatBytes, formatNumber, withVersionPrefix } from '@/lib/format'
import { filterPackages, packageRoute } from '@/lib/packages'
import { faBoxOpen, faMagnifyingGlass, faRotateRight } from '@/lib/icons'
import { VERDICT_OPTIONS, VERDICT_RANK, verdictOf, type Verdict } from '@/lib/verdict'

const props = defineProps<{ registry?: string }>()

const PAGE_SIZE = 25
const KNOWN_REGISTRIES = ['npm', 'go', 'pypi']

const store = usePackageStore()
const toasts = useToastStore()
const route = useRoute()
const router = useRouter()
const { packages, loading, error } = storeToRefs(store)

const selected = ref<Package | null>(null)
const showDeleteModal = ref(false)
const packageToDelete = ref<Package | null>(null)
const sort = ref<SortState | null>(null)
const page = ref(1)

function queryText(key: string): string {
  const raw = route.query[key]
  return typeof raw === 'string' ? raw : ''
}

const query = ref(queryText('q'))

let nextFilterId = 0
function filterItem(field: string, value: string): FilterItem {
  return { id: `f${nextFilterId++}`, field, operator: 'eq', value }
}

// The path segment is the pre-redesign way to pick a registry, so it still seeds the filter.
const filterItems = ref<FilterItem[]>(
  [
    ...[props.registry || queryText('registry')].filter(Boolean).map((r) => filterItem('registry', r)),
    ...[queryText('verdict')].filter(Boolean).map((v) => filterItem('verdict', v)),
  ],
)

const registryOptions = computed(() => {
  const seen = new Set([...KNOWN_REGISTRIES, ...packages.value.map((p) => p.registry)])
  return [...seen].map((value) => ({ value, label: value }))
})

const filterFields = computed<FilterField[]>(() => [
  { id: 'registry', label: 'Registry', type: 'select', options: registryOptions.value, operators: ['eq'] },
  { id: 'verdict', label: 'Verdict', type: 'select', options: VERDICT_OPTIONS, operators: ['eq'] },
])

function valuesOf(field: string): string[] {
  return filterItems.value.filter((f) => f.field === field).map((f) => String(f.value))
}

const rows = computed(() =>
  filterPackages(packages.value, {
    query: query.value,
    registries: valuesOf('registry'),
    verdicts: valuesOf('verdict') as Verdict[],
  }),
)

// The URL mirrors the filters so a reload or a shared link restores the view.
watch([query, filterItems], () => {
  page.value = 1
  const { q: _q, registry: _r, verdict: _v, ...rest } = route.query
  const next: Record<string, string> = {}
  if (query.value.trim()) next.q = query.value.trim()
  const [registry] = valuesOf('registry')
  const [verdict] = valuesOf('verdict')
  if (registry) next.registry = registry
  if (verdict) next.verdict = verdict
  void router.replace({ path: '/packages', query: { ...rest, ...next } })
})

const columns: DataTableColumn<Package>[] = [
  { key: 'name', header: 'Package', sortable: true, rowHeader: true },
  { key: 'version', header: 'Version', sortable: true, accessor: (p) => withVersionPrefix(displayVersion(p)) },
  { key: 'registry', header: 'Registry', sortable: true },
  { key: 'size', header: 'Size', sortable: true, numeric: true },
  { key: 'download_count', header: 'Downloads', sortable: true, numeric: true },
  { key: 'last_accessed', header: 'Last accessed', sortable: true, accessor: (p) => Date.parse(p.last_accessed) || 0 },
  { key: 'verdict', header: 'Verdict', sortable: true, accessor: (p) => VERDICT_RANK[verdictOf(p)] },
  { key: 'scanned', header: 'Last scanned', sortable: true, accessor: (p) => Date.parse(p.vulnerabilities?.scannedAt ?? '') || 0 },
]

async function load() {
  await store.fetchPackages()
}

onMounted(load)

function confirmDelete(pkg: Package) {
  packageToDelete.value = pkg
  showDeleteModal.value = true
}

async function deletePackage() {
  const target = packageToDelete.value
  if (!target) return
  await store.deletePackage(target.registry, target.name, target.version)
  showDeleteModal.value = false
  packageToDelete.value = null
  selected.value = null
  const label = `${target.name}@${target.version}`
  if (store.error) {
    toasts.error('Could not remove package', `${label}: ${store.error}`)
    // The toast reports it; the list loaded fine, so it must not be replaced by a load error.
    store.error = null
  } else {
    toasts.success('Package removed', label)
    await load()
  }
}
</script>
