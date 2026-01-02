<template>
  <div>
    <div class="flex justify-between items-center mb-8">
      <h2 class="text-3xl font-bold text-gray-900">Packages</h2>
      <Button @click="store.fetchPackages()">
        <i class="fas fa-sync-alt mr-2"></i>Refresh
      </Button>
    </div>

    <!-- Filter and Search Section -->
    <div class="mb-6 flex flex-col sm:flex-row items-start sm:items-center gap-4">
      <div class="flex items-center gap-2">
        <span class="text-sm font-medium text-gray-700">Filter by registry:</span>
        <div class="flex gap-2">
          <Button
            @click="selectedRegistry = 'all'"
            :variant="selectedRegistry === 'all' ? 'default' : 'outline'"
            size="sm"
          >
            All
          </Button>
          <Button
            @click="selectedRegistry = 'npm'"
            :variant="selectedRegistry === 'npm' ? 'default' : 'outline'"
            size="sm"
          >
            <i class="fab fa-npm mr-2"></i>NPM
          </Button>
          <Button
            @click="selectedRegistry = 'pypi'"
            :variant="selectedRegistry === 'pypi' ? 'default' : 'outline'"
            size="sm"
          >
            <i class="fab fa-python mr-2"></i>PyPI
          </Button>
          <Button
            @click="selectedRegistry = 'go'"
            :variant="selectedRegistry === 'go' ? 'default' : 'outline'"
            size="sm"
          >
            <i class="fas fa-code mr-2"></i>Go
          </Button>
        </div>
      </div>
      <div class="flex items-center gap-2 w-full sm:w-auto sm:ml-auto">
        <i class="fas fa-search text-gray-500"></i>
        <Input
          v-model="searchTerm"
          type="text"
          placeholder="Search packages..."
          class="w-full sm:w-64"
        />
      </div>
    </div>

    <!-- Error Alert -->
    <Alert v-if="error" variant="destructive" class="mb-4">
      <i class="fas fa-exclamation-circle mr-2"></i>
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <i class="fas fa-spinner fa-spin text-4xl text-primary-600"></i>
      <p class="mt-4 text-gray-600">Loading packages...</p>
    </div>

    <!-- Package List -->
    <Card v-else>
      <CardContent class="p-6">
        <div v-if="packages.length === 0" class="text-center py-12 text-gray-500">
          <i class="fas fa-inbox text-6xl mb-4"></i>
          <p class="text-xl">No packages cached yet</p>
          <p class="mt-2">Packages will appear here once they are downloaded through the proxy</p>
        </div>
        <Accordion v-else type="multiple" class="w-full">
        <AccordionItem
          v-for="group in groupedPackages"
          :key="`${group.registry}:${group.name}`"
          :value="`${group.registry}:${group.name}`"
          class="border-b border-gray-200"
        >
          <AccordionTrigger class="px-4 py-4 hover:bg-gray-50">
            <div class="flex items-center justify-between w-full pr-4">
              <div class="flex items-center space-x-4">
                <div class="text-left">
                  <h4 class="font-semibold text-gray-900">{{ group.name }}</h4>
                  <p class="text-sm text-gray-500">{{ group.versions.length }} version{{ group.versions.length > 1 ? 's' : '' }}</p>
                </div>
              </div>
              <div class="flex items-center space-x-6">
                <Badge variant="outline" :class="getRegistryBadgeClass(group.registry)">
                  {{ group.registry }}
                </Badge>
                <div class="text-right">
                  <p class="text-sm font-medium text-gray-900">{{ formatBytes(group.totalSize) }}</p>
                  <p class="text-xs text-gray-500">{{ formatNumber(group.totalDownloads) }} downloads</p>
                </div>
              </div>
            </div>
          </AccordionTrigger>
          <AccordionContent class="px-4 pb-4">
            <div class="space-y-3">
              <div
                v-for="version in group.versions"
                :key="version.id"
                class="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100"
              >
                <div class="flex items-center space-x-4 flex-1">
                  <div class="flex-1">
                    <p class="font-medium text-gray-900">{{ version.version.startsWith('v') ? version.version : 'v' + version.version }}</p>
                    <div class="flex items-center space-x-4 mt-1 text-sm text-gray-500">
                      <span>
                        <i class="fas fa-download mr-1"></i>{{ formatNumber(version.download_count) }}
                      </span>
                      <span>
                        <i class="fas fa-hard-drive mr-1"></i>{{ formatBytes(version.size) }}
                      </span>
                      <span>
                        <i class="fas fa-clock mr-1"></i>{{ formatDate(version.cached_at) }}
                      </span>
                    </div>
                    <!-- Vulnerability Badge -->
                    <div v-if="version.vulnerabilities" class="mt-2">
                      <VulnerabilityBadge
                        :scanned="version.vulnerabilities.scanned"
                        :status="version.vulnerabilities.status"
                        :counts="version.vulnerabilities.counts"
                        :total="version.vulnerabilities.total"
                        :scannedAt="version.vulnerabilities.scannedAt"
                        @click="showVulnerabilityDetails(group.registry, group.name, version.version)"
                      />
                    </div>
                  </div>
                </div>
                <button
                  @click="confirmDelete(version)"
                  class="text-red-600 hover:text-red-900 p-2"
                  title="Delete this version"
                >
                  <i class="fas fa-trash"></i>
                </button>
              </div>
            </div>
          </AccordionContent>
        </AccordionItem>
        </Accordion>

        <!-- Pagination -->
        <div v-if="totalPages > 1" class="mt-6 flex items-center justify-between border-t pt-4">
          <div class="text-sm text-gray-700">
            Page {{ currentPage }} of {{ totalPages }} ({{ allGroupedPackages.length }} total packages)
          </div>
          <div class="flex items-center gap-2">
            <Button
              @click="changePage(currentPage - 1)"
              :disabled="currentPage === 1"
              variant="outline"
              size="sm"
            >
              <i class="fas fa-chevron-left mr-2"></i>Previous
            </Button>

            <div class="flex gap-1">
              <!-- First page -->
              <Button
                v-if="currentPage > 3"
                @click="changePage(1)"
                variant="outline"
                size="sm"
              >
                1
              </Button>
              <span v-if="currentPage > 4" class="px-2">...</span>

              <!-- Page numbers around current page -->
              <Button
                v-for="page in getPageNumbers()"
                :key="page"
                @click="changePage(page)"
                :variant="page === currentPage ? 'default' : 'outline'"
                size="sm"
              >
                {{ page }}
              </Button>

              <span v-if="currentPage < totalPages - 3" class="px-2">...</span>
              <!-- Last page -->
              <Button
                v-if="currentPage < totalPages - 2"
                @click="changePage(totalPages)"
                variant="outline"
                size="sm"
              >
                {{ totalPages }}
              </Button>
            </div>

            <Button
              @click="changePage(currentPage + 1)"
              :disabled="currentPage === totalPages"
              variant="outline"
              size="sm"
            >
              Next<i class="fas fa-chevron-right ml-2"></i>
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>

    <!-- Delete Confirmation Dialog -->
    <Dialog v-model:open="showDeleteModal">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Confirm Deletion</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete <strong>{{ packageToDelete?.name }}@{{ packageToDelete?.version }}</strong>?
            This action cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button @click="showDeleteModal = false" variant="outline">
            Cancel
          </Button>
          <Button @click="deletePackage" variant="destructive">
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Vulnerability Details Modal -->
    <VulnerabilityDetailsModal
      v-if="selectedPackage"
      v-model:open="showVulnerabilityModal"
      :registry="selectedPackage.registry"
      :package-name="selectedPackage.name"
      :version="selectedPackage.version"
    />
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, computed, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { usePackageStore, type Package } from '../stores/packages'
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import VulnerabilityDetailsModal from './VulnerabilityDetailsModal.vue'

const store = usePackageStore()
const { packages, loading, error } = storeToRefs(store)

const showDeleteModal = ref(false)
const packageToDelete = ref<Package | null>(null)
const showVulnerabilityModal = ref(false)
const selectedPackage = ref<{ registry: string; name: string; version: string } | null>(null)
const selectedRegistry = ref<string>('all')
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

// Get page numbers to display around current page
function getPageNumbers(): number[] {
  const pages: number[] = []
  const start = Math.max(1, currentPage.value - 2)
  const end = Math.min(totalPages.value, currentPage.value + 2)

  for (let i = start; i <= end; i++) {
    pages.push(i)
  }
  return pages
}

// Reset to page 1 when filters change
function resetPagination() {
  currentPage.value = 1
}

// Watch for filter/search changes and reset pagination
watch([selectedRegistry, searchTerm], () => {
  resetPagination()
})

onMounted(async () => {
  await store.fetchPackages()
})

function confirmDelete(pkg: Package) {
  packageToDelete.value = pkg
  showDeleteModal.value = true
}

async function deletePackage() {
  if (packageToDelete.value) {
    await store.deletePackage(
      packageToDelete.value.registry,
      packageToDelete.value.name,
      packageToDelete.value.version
    )
    showDeleteModal.value = false
    packageToDelete.value = null
  }
}

function getRegistryBadgeClass(registry: string): string {
  const classes: Record<string, string> = {
    npm: 'bg-blue-100 text-blue-800 border-blue-200',
    pypi: 'bg-green-100 text-green-800 border-green-200',
    go: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  }
  return classes[registry] || 'bg-gray-100 text-gray-800 border-gray-200'
}

function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num)
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}

function formatDate(date: string): string {
  return new Date(date).toLocaleString()
}

function showVulnerabilityDetails(registry: string, name: string, version: string) {
  selectedPackage.value = { registry, name, version }
  showVulnerabilityModal.value = true
}
</script>
