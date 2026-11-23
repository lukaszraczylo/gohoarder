<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Packages" description="Everything the proxy has cached, grouped by package.">
      <template #actions>
        <Button variant="outline" :icon-start="faRotateRight" @click="store.fetchPackages()">Refresh</Button>
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
      @retry="store.fetchPackages()"
    />

    <Card v-else>
      <CardContent>
        <EmptyState
          v-if="packages.length === 0"
          :icon="faBoxOpen"
          title="No packages cached yet"
          description="Packages will appear here once they are downloaded through the proxy."
        />
        <EmptyState
          v-else-if="groupedPackages.length === 0"
          :icon="faMagnifyingGlass"
          title="No packages match"
          description="Change the registry filter or the search text."
        />
        <Accordion v-else type="multiple" class="w-full">
          <AccordionItem
            v-for="group in groupedPackages"
            :key="`${group.registry}:${group.name}`"
            :value="`${group.registry}:${group.name}`"
          >
            <AccordionTrigger :heading-level="2">
              <span class="flex w-full min-w-0 items-center justify-between gap-4">
                <span class="min-w-0 text-start">
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
            Page {{ currentPage }} of {{ totalPages }} ({{ allGroupedPackages.length }} total packages)
          </p>
          <Pagination
            :page="currentPage"
            :total="allGroupedPackages.length"
            :page-size="itemsPerPage"
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
import { onMounted, ref, computed, watch } from 'vue'
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
const { packages, loading, error } = storeToRefs(store)

const showDeleteModal = ref(false)
const packageToDelete = ref<Package | null>(null)
const REGISTRY_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'npm', label: 'npm' },
  { value: 'pypi', label: 'PyPI' },
  { value: 'go', label: 'Go' },
]

const selectedRegistry = ref<string>(props.registry || 'all')
const searchTerm = ref<string>('')
const currentPage = ref<number>(1)
const itemsPerPage = ref<number>(10)

// Group packages by name
const allGroupedPackages = computed(() => {
  const groups = new Map<string, Package[]>()

  // Filter packages by selected registry and search term
  let filteredPackages = selectedRegistry.value === 'all'
    ? packages.value
    : packages.value.filter(pkg => pkg.registry === selectedRegistry.value)

  // Apply search filter if search term exists
  if (searchTerm.value.trim()) {
    const searchLower = searchTerm.value.toLowerCase()
    filteredPackages = filteredPackages.filter(pkg =>
      pkg.name.toLowerCase().includes(searchLower) ||
      displayVersion(pkg).toLowerCase().includes(searchLower) ||
      pkg.version.toLowerCase().includes(searchLower)
    )
  }

  filteredPackages.forEach(pkg => {
    const key = `${pkg.registry}:${pkg.name}`
    if (!groups.has(key)) {
      groups.set(key, [])
    }
    groups.get(key)!.push(pkg)
  })

  // Convert to array and sort versions within each group
  return Array.from(groups.entries()).map(([key, versions]) => {
    const [registry, name] = key.split(':')
    return {
      registry,
      name,
      versions: versions.sort((a, b) =>
        new Date(b.cached_at).getTime() - new Date(a.cached_at).getTime()
      ),
      totalSize: versions.reduce((sum, v) => sum + v.size, 0),
      totalDownloads: versions.reduce((sum, v) => sum + v.download_count, 0),
    }
  }).sort((a, b) => a.name.localeCompare(b.name))
})

// Pagination
const totalPages = computed(() => Math.ceil(allGroupedPackages.value.length / itemsPerPage.value))

const groupedPackages = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage.value
  const end = start + itemsPerPage.value
  return allGroupedPackages.value.slice(start, end)
})

function changePage(page: number) {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
    // Scroll to top of packages list
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }
}

// Reset to page 1 when filters change
function resetPagination() {
  currentPage.value = 1
}

// Watch for filter/search changes and reset pagination
watch([selectedRegistry, searchTerm], () => {
  resetPagination()
})

// Watch for route parameter changes to update filter
watch(() => route.params.registry, (newRegistry) => {
  selectedRegistry.value = (newRegistry as string) || 'all'
})

onMounted(async () => {
  await store.fetchPackages()
})

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
  } else toasts.success('Package deleted', label)
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
