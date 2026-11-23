<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Packages" description="Everything the proxy has cached, grouped by package.">
      <template #actions>
        <Button variant="outline" :icon-start="faRotateRight" @click="load()">Refresh</Button>
      </template>
    </PageHeader>

    <div class="flex flex-col gap-4 sm:flex-row sm:items-center">
      <SegmentedControl
        :model-value="selectedRegistry"
        :options="REGISTRY_OPTIONS"
        aria-label="Filter by registry"
        @update:model-value="changeRegistryFilter"
      />
      <SearchInput v-model="searchTerm" aria-label="Search packages" placeholder="Search packages..." class="w-full sm:ms-auto sm:w-64" />
    </div>

    <LoadingState v-if="loading" variant="table" label="Loading packages..." />

    <ErrorState
      v-else-if="error"
      variant="card"
      title="Could not load packages"
      :message="error"
      @retry="load()"
    />

    <Card v-else>
      <CardContent>
        <EmptyState
          v-if="totalGroups === 0 && !filtersActive"
          :icon="faBoxOpen"
          title="No packages cached yet"
          description="Packages will appear here once they are downloaded through the proxy."
        />
        <EmptyState
          v-else-if="groups.length === 0"
          :icon="faMagnifyingGlass"
          title="No packages match"
          description="Change the registry filter or the search text."
        />
        <Accordion v-else type="multiple" class="w-full">
          <AccordionItem
            v-for="group in groups"
            :key="`${group.registry}:${group.name}`"
            :value="`${group.registry}:${group.name}`"
          >
            <AccordionTrigger :heading-level="2">
              <!-- Stacked below sm: a side-by-side row leaves the name ~90px at 320px and breaks scoped names mid-word. -->
              <span class="flex w-full min-w-0 flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                <span class="w-full min-w-0 text-start sm:w-auto">
                  <span class="block break-words font-semibold">{{ group.name }}</span>
                  <span class="block text-sm text-muted-foreground">
                    {{ group.versions.length }} version{{ group.versions.length > 1 ? 's' : '' }}
                  </span>
                </span>
                <span class="flex shrink-0 items-center gap-4">
                  <Badge variant="outline">{{ group.registry }}</Badge>
                  <span class="text-end tabular-nums">
                    <span class="block text-sm font-medium">{{ formatBytes(group.totalSize) }}</span>
                    <span class="block text-xs text-muted-foreground">{{ formatNumber(group.totalDownloads) }} downloads</span>
                  </span>
                </span>
              </span>
            </AccordionTrigger>
            <AccordionContent>
              <Table :label="`Versions of ${group.name}`" layout="cards">
                <TableHeader>
                  <TableRow>
                    <TableHead>Version</TableHead>
                    <TableHead align="right">Downloads</TableHead>
                    <TableHead align="right">Size</TableHead>
                    <TableHead>Cached</TableHead>
                    <TableHead>Vulnerabilities</TableHead>
                    <TableHead align="right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow v-for="version in group.versions" :key="version.id">
                    <TableCell label="Version" class="font-medium">{{ withVersionPrefix(displayVersion(version)) }}</TableCell>
                    <TableCell label="Downloads" numeric>{{ formatNumber(version.download_count) }}</TableCell>
                    <TableCell label="Size" numeric>{{ formatBytes(version.size) }}</TableCell>
                    <TableCell label="Cached">{{ formatDate(version.cached_at) }}</TableCell>
                    <TableCell label="Vulnerabilities">
                      <VulnerabilityBadge
                        v-if="version.vulnerabilities"
                        :scanned="version.vulnerabilities.scanned"
                        :status="version.vulnerabilities.status"
                        :counts="version.vulnerabilities.counts"
                        :total="version.vulnerabilities.total"
                        :scannedAt="version.vulnerabilities.scannedAt"
                        :isBlocked="version.vulnerabilities.isBlocked"
                        @click="showVulnerabilityDetails(group.registry, group.name, version.version)"
                      />
                    </TableCell>
                    <TableCell label="Actions" align="right">
                      <IconButton
                        :icon="faTrash"
                        :label="`Delete ${group.name} ${version.version}`"
                        @click="confirmDelete(version)"
                      />
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </AccordionContent>
          </AccordionItem>
        </Accordion>

        <div v-if="totalPages > 1" class="mt-6 flex flex-col gap-3 border-t pt-4 sm:flex-row sm:items-center sm:justify-between">
          <p class="m-0 text-sm text-muted-foreground">
            Page {{ currentPage }} of {{ totalPages }} ({{ totalGroups }} total packages)
          </p>
          <Pagination
            :page="currentPage"
            :total="totalGroups"
            :page-size="PAGE_SIZE"
            :show-edges="false"
            @update:page="changePage"
          />
        </div>
      </CardContent>
    </Card>

    <ConfirmDialog
      v-model:open="showDeleteModal"
      title="Delete package version?"
      :description="`Delete ${packageToDelete?.name}@${packageToDelete?.version}? This action cannot be undone.`"
      confirm-label="Delete version"
      tone="danger"
      destructive
      @confirm="deletePackage"
    />
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, computed, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRoute, useRouter } from 'vue-router'
import { usePackageStore, type Package } from '../stores/packages'
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
  Badge,
  Button,
  Card,
  CardContent,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  IconButton,
  LoadingState,
  PageHeader,
  Pagination,
  SearchInput,
  SegmentedControl,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  useToastStore,
} from '@perfect-design/ui'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import { formatBytes, formatDate, formatNumber, displayVersion, withVersionPrefix } from '@/lib/format'
import { faBoxOpen, faMagnifyingGlass, faRotateRight, faTrash } from '@/lib/icons'

// Props from router
const props = defineProps<{
  registry?: string
}>()

const route = useRoute()
const router = useRouter()
const store = usePackageStore()
const toasts = useToastStore()
const { packagePage, loading, error } = storeToRefs(store)

const showDeleteModal = ref(false)
const packageToDelete = ref<Package | null>(null)
const REGISTRY_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'npm', label: 'npm' },
  { value: 'pypi', label: 'PyPI' },
  { value: 'go', label: 'Go' },
]

const PAGE_SIZE = 25
const SEARCH_DEBOUNCE_MS = 300

const selectedRegistry = ref<string>(props.registry || 'all')
const searchTerm = ref<string>('')
// What the server was last asked: the search text lags the input by the debounce.
const activeQuery = ref<string>('')
const currentPage = ref<number>(1)

const totalGroups = computed(() => packagePage.value.totalGroups)
const totalPages = computed(() => Math.ceil(totalGroups.value / PAGE_SIZE))
const filtersActive = computed(() => selectedRegistry.value !== 'all' || activeQuery.value.trim() !== '')

// The server pages whole (registry, name) groups and sends every version row of each.
const groups = computed(() => {
  const byKey = new Map<string, { registry: string; name: string; versions: Package[] }>()
  for (const pkg of packagePage.value.packages) {
    const key = `${pkg.registry}\u0000${pkg.name}`
    let group = byKey.get(key)
    if (!group) {
      group = { registry: pkg.registry, name: pkg.name, versions: [] }
      byKey.set(key, group)
    }
    group.versions.push(pkg)
  }
  return Array.from(byKey.values()).map((group) => ({
    ...group,
    totalSize: group.versions.reduce((sum, v) => sum + v.size, 0),
    totalDownloads: group.versions.reduce((sum, v) => sum + v.download_count, 0),
  }))
})

async function load() {
  await store.fetchPackagePage({
    page: currentPage.value,
    pageSize: PAGE_SIZE,
    registry: selectedRegistry.value,
    q: activeQuery.value,
  })
}

function changePage(page: number) {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
    void load()
    // Scroll to top of packages list
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }
}

// A burst of keystrokes asks the server once.
let searchTimer: ReturnType<typeof setTimeout> | undefined
watch(searchTerm, (term) => {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(() => {
    if (term === activeQuery.value) return
    activeQuery.value = term
    currentPage.value = 1
    void load()
  }, SEARCH_DEBOUNCE_MS)
})
onBeforeUnmount(() => clearTimeout(searchTimer))

// Watch for route parameter changes to update filter
watch(() => route.params.registry, (newRegistry) => {
  selectedRegistry.value = (newRegistry as string) || 'all'
  currentPage.value = 1
  void load()
})

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
  const label = `${target.name}@${target.version}`
  if (store.error) {
    toasts.error('Could not delete package', `${label}: ${store.error}`)
    // The toast reports it; the list loaded fine, so it must not be replaced by a load error.
    store.error = null
  } else {
    toasts.success('Package deleted', label)
    await load()
    // Deleting the last group of the last page leaves that page empty.
    if (packagePage.value.packages.length === 0 && totalGroups.value > 0 && currentPage.value > 1) {
      currentPage.value = Math.max(totalPages.value, 1)
      await load()
    }
  }
}

function showVulnerabilityDetails(registry: string, name: string, version: string) {
  // Navigate to the package details page
  router.push({
    name: 'package-details',
    params: {
      registry,
      name,
      version,
    },
  })
}

function changeRegistryFilter(registry: string) {
  const path = registry === 'all' ? '/packages' : `/packages/${registry}`
  router.push(path)
}
</script>
