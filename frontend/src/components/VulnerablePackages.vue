<template>
  <div class="max-w-7xl mx-auto px-4 py-8">
    <!-- Header -->
    <div class="mb-6">
      <Button @click="goBack" variant="ghost" class="mb-4">
        <i class="fas fa-arrow-left mr-2"></i>
        Back to Stats
      </Button>
      <div class="flex items-center gap-3">
        <i :class="showOnlyBlocked ? 'fas fa-hand' : 'fas fa-exclamation-triangle'" class="text-3xl text-red-600"></i>
        <div>
          <h1 class="text-3xl font-bold text-gray-900">
            {{ showOnlyBlocked ? 'Blocked Packages' : 'Vulnerable Packages' }}
          </h1>
          <p class="text-gray-600 mt-1">
            {{ showOnlyBlocked
              ? 'Packages blocked from download due to exceeding vulnerability thresholds'
              : 'Packages with known security vulnerabilities, sorted by risk'
            }}
          </p>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <i class="fas fa-spinner fa-spin text-4xl text-primary-600"></i>
      <p class="mt-4 text-gray-600">Loading vulnerable packages...</p>
    </div>

    <!-- Error State -->
    <Alert v-else-if="error" variant="destructive" class="mb-4">
      <i class="fas fa-exclamation-circle mr-2"></i>
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <!-- Empty State -->
    <Card v-else-if="sortedVulnerablePackages.length === 0">
      <CardContent class="text-center py-12">
        <i class="fas fa-check-circle text-6xl text-green-500 mb-4"></i>
        <p class="text-xl font-semibold text-gray-900">No Vulnerable Packages</p>
        <p class="mt-2 text-gray-600">All your packages are clean and safe to use!</p>
      </CardContent>
    </Card>

    <!-- Vulnerable Packages List -->
    <div v-else class="space-y-6">
      <!-- Summary Card -->
      <Card>
        <CardContent class="p-6">
          <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div class="text-center p-4 bg-red-50 rounded-lg border border-red-200">
              <p class="text-3xl font-bold text-red-600">{{ criticalCount }}</p>
              <p class="text-sm text-gray-600 mt-1">Critical</p>
            </div>
            <div class="text-center p-4 bg-orange-50 rounded-lg border border-orange-200">
              <p class="text-3xl font-bold text-orange-600">{{ highCount }}</p>
              <p class="text-sm text-gray-600 mt-1">High</p>
            </div>
            <div class="text-center p-4 bg-yellow-50 rounded-lg border border-yellow-200">
              <p class="text-3xl font-bold text-yellow-600">{{ moderateCount }}</p>
              <p class="text-sm text-gray-600 mt-1">Moderate</p>
            </div>
            <div class="text-center p-4 bg-blue-50 rounded-lg border border-blue-200">
              <p class="text-3xl font-bold text-blue-600">{{ lowCount }}</p>
              <p class="text-sm text-gray-600 mt-1">Low</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- Packages List -->
      <Card>
        <CardContent class="p-6">
          <div class="mb-4">
            <h3 class="text-xl font-semibold text-gray-900">
              <i class="fas fa-list mr-2"></i>
              Vulnerable Packages ({{ sortedVulnerablePackages.length }})
            </h3>
            <p class="text-sm text-gray-600 mt-1">
              {{ groupedPackages.length }} unique package{{ groupedPackages.length !== 1 ? 's' : '' }} • Sorted by risk: Critical → High → Moderate → Low
            </p>
          </div>
          <Accordion type="multiple" class="w-full">
            <AccordionItem
              v-for="group in groupedPackages"
              :key="`${group.registry}:${group.name}`"
              :value="`${group.registry}:${group.name}`"
              class="border-b border-gray-200"
            >
              <AccordionTrigger class="px-4 py-4 hover:bg-gray-50">
                <div class="flex items-center justify-between w-full pr-4">
                  <div class="flex items-center space-x-4 flex-1 min-w-0">
                    <div class="text-left flex-1 min-w-0">
                      <h4 class="font-semibold text-gray-900 break-words">{{ group.name }}</h4>
                      <p class="text-sm text-gray-500">{{ group.versions.length }} vulnerable version{{ group.versions.length > 1 ? 's' : '' }}</p>
                    </div>
                  </div>
                  <div class="flex items-center space-x-6 flex-shrink-0">
                    <Badge variant="outline" :class="getRegistryBadgeClass(group.registry)">
                      {{ group.registry }}
                    </Badge>
                    <div class="text-right whitespace-nowrap">
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
                    class="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 cursor-pointer"
                    @click="navigateToPackage(version)"
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
                            :isBlocked="version.vulnerabilities.isBlocked"
                            @click.stop="navigateToPackage(version)"
                          />
                        </div>
                      </div>
                    </div>
                    <div class="ml-4 flex-shrink-0">
                      <i class="fas fa-chevron-right text-gray-400"></i>
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { usePackageStore, type Package } from '../stores/packages'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion'
import VulnerabilityBadge from './VulnerabilityBadge.vue'
import { getRegistryBadgeClass } from '@/composables/useBadgeStyles'

const store = usePackageStore()
const router = useRouter()
const route = useRoute()

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
    await store.fetchPackages()
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

// Sort packages by risk: Critical count DESC, High count DESC, Moderate count DESC, Low count DESC
const sortedVulnerablePackages = computed(() => {
  return [...vulnerablePackages.value].sort((a, b) => {
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

// Calculate total counts across all packages
const criticalCount = computed(() =>
  vulnerablePackages.value.reduce((sum, pkg) => sum + (pkg.vulnerabilities?.counts?.critical || 0), 0)
)

const highCount = computed(() =>
  vulnerablePackages.value.reduce((sum, pkg) => sum + (pkg.vulnerabilities?.counts?.high || 0), 0)
)

const moderateCount = computed(() =>
  vulnerablePackages.value.reduce((sum, pkg) => sum + (pkg.vulnerabilities?.counts?.moderate || 0), 0)
)

const lowCount = computed(() =>
  vulnerablePackages.value.reduce((sum, pkg) => sum + (pkg.vulnerabilities?.counts?.low || 0), 0)
)

function navigateToPackage(pkg: Package) {
  router.push(`/package/${pkg.registry}/${pkg.name}/${pkg.version}`)
}

function goBack() {
  router.push('/stats')
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

function formatDate(dateString: string): string {
  if (!dateString) return 'N/A'
  try {
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  } catch {
    return dateString
  }
}
</script>
