<template>
  <div>
    <h2 class="text-3xl font-bold text-gray-900 mb-8">Dashboard</h2>

    <!-- Error Alert -->
    <Alert v-if="error" variant="destructive" class="mb-4">
      <i class="fas fa-exclamation-circle mr-2"></i>
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <i class="fas fa-spinner fa-spin text-4xl text-primary-600"></i>
      <p class="mt-4 text-gray-600">Loading statistics...</p>
    </div>

    <!-- Stats Grid -->
    <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
      <Card class="border-0 shadow-lg hover:shadow-xl transition-shadow">
        <CardContent class="p-6">
          <div class="flex items-start justify-between">
            <div class="space-y-2">
              <p class="text-sm font-medium text-muted-foreground">Total Packages</p>
              <p class="text-3xl font-bold text-foreground tracking-tight">
                {{ formatNumber(stats?.total_packages || 0) }}
              </p>
            </div>
            <div class="w-12 h-12 bg-slate-100 rounded-xl flex items-center justify-center">
              <i class="fas fa-boxes text-slate-700 text-lg"></i>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card class="border-0 shadow-lg hover:shadow-xl transition-shadow">
        <CardContent class="p-6">
          <div class="flex items-start justify-between">
            <div class="space-y-2">
              <p class="text-sm font-medium text-muted-foreground">Total Size</p>
              <p class="text-3xl font-bold text-foreground tracking-tight">
                {{ formatBytes(stats?.total_size || 0) }}
              </p>
            </div>
            <div class="w-12 h-12 bg-sky-50 rounded-xl flex items-center justify-center">
              <i class="fas fa-hard-drive text-sky-600 text-lg"></i>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card class="border-0 shadow-lg hover:shadow-xl transition-shadow">
        <CardContent class="p-6">
          <div class="flex items-start justify-between">
            <div class="space-y-2">
              <p class="text-sm font-medium text-muted-foreground">Total Downloads</p>
              <p class="text-3xl font-bold text-foreground tracking-tight">
                {{ formatNumber(stats?.total_downloads || 0) }}
              </p>
            </div>
            <div class="w-12 h-12 bg-emerald-50 rounded-xl flex items-center justify-center">
              <i class="fas fa-download text-emerald-600 text-lg"></i>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card class="border-0 shadow-lg hover:shadow-xl transition-shadow">
        <CardContent class="p-6">
          <div class="flex items-start justify-between">
            <div class="space-y-2">
              <p class="text-sm font-medium text-muted-foreground">Scanned Packages</p>
              <p class="text-3xl font-bold text-foreground tracking-tight">
                {{ formatNumber(stats?.scanned_packages || 0) }}
              </p>
            </div>
            <div class="w-12 h-12 bg-violet-50 rounded-xl flex items-center justify-center">
              <i class="fas fa-shield-alt text-violet-600 text-lg"></i>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>

    <!-- Downloads Chart -->
    <Card class="border-0 shadow-lg mb-10">
      <CardContent class="p-6">
        <div class="flex items-center justify-between mb-6">
          <h3 class="text-xl font-semibold text-foreground">Download Activity</h3>
          <div class="flex gap-2">
            <Button
              v-for="period in chartPeriods"
              :key="period.value"
              @click="selectedPeriod = period.value"
              :variant="selectedPeriod === period.value ? 'default' : 'outline'"
              size="sm"
            >
              {{ period.label }}
            </Button>
          </div>
        </div>
        <div class="h-64 flex items-end justify-between gap-2">
          <div
            v-for="(value, index) in chartData"
            :key="index"
            class="flex-1 flex flex-col items-center gap-2"
          >
            <div class="w-full bg-slate-100 rounded-t-lg relative" :style="{ height: `${(value / maxChartValue) * 100}%` }">
              <div class="absolute inset-0 bg-gradient-to-t from-slate-700 to-slate-500 rounded-t-lg"></div>
            </div>
            <span class="text-xs text-muted-foreground">{{ getChartLabel(index) }}</span>
          </div>
        </div>
        <div v-if="chartLoading || chartData.length === 0" class="mt-4 text-center">
          <p class="text-sm text-muted-foreground">
            <i class="fas fa-info-circle mr-1"></i>
            {{ chartLoading ? 'Loading chart data...' : 'No download activity in this period' }}
          </p>
        </div>
      </CardContent>
    </Card>

    <!-- Recent Packages -->
    <Card><CardContent class="p-6">
      <h3 class="text-xl font-semibold text-gray-900 mb-4">
        <i class="fas fa-clock mr-2"></i>Recent Packages
      </h3>
      <div v-if="packages.length === 0" class="text-center py-8 text-gray-500">
        <i class="fas fa-inbox text-4xl mb-4"></i>
        <p>No packages cached yet</p>
      </div>
      <div v-else class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
          <thead>
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Package
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Version
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Registry
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Size
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Downloads
              </th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">
            <tr v-for="pkg in recentPackages" :key="pkg.id">
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                {{ pkg.name }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ pkg.version }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <Badge variant="outline" :class="getRegistryBadgeClass(pkg.registry)">
                  {{ pkg.registry }}
                </Badge>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ formatBytes(pkg.size) }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ formatNumber(pkg.download_count) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      </CardContent>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import axios from 'axios'
import { usePackageStore } from '../stores/packages'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { getRegistryBadgeClass } from '@/composables/useBadgeStyles'

const store = usePackageStore()
const { packages, stats, loading, error } = storeToRefs(store)

// Chart periods and data
const selectedPeriod = ref<string>('1day')
const chartPeriods = [
  { value: '1h', label: '1 Hour' },
  { value: '1day', label: '24 Hours' },
  { value: '7day', label: '7 Days' },
  { value: '30day', label: '30 Days' },
]

// Time-series data from API
interface TimeSeriesDataPoint {
  timestamp: string
  value: number
}

interface TimeSeriesStats {
  period: string
  registry: string
  data_points: TimeSeriesDataPoint[]
}

const timeSeriesData = ref<TimeSeriesStats | null>(null)
const chartLoading = ref(false)

// Fetch time-series data from API
async function fetchTimeSeriesData() {
  chartLoading.value = true
  try {
    const response = await axios.get(`/api/stats/timeseries?period=${selectedPeriod.value}`)
    timeSeriesData.value = response.data
  } catch (err) {
    console.error('Failed to fetch time-series data:', err)
    timeSeriesData.value = null
  } finally {
    chartLoading.value = false
  }
}

// Extract chart values from time-series data
const chartData = computed(() => {
  if (!timeSeriesData.value || !timeSeriesData.value.data_points) {
    return []
  }
  return timeSeriesData.value.data_points.map(point => point.value)
})

const maxChartValue = computed(() => {
  if (chartData.value.length === 0) return 100
  const max = Math.max(...chartData.value)
  return max === 0 ? 100 : max
})

function getChartLabel(index: number): string {
  // Use timestamp from data if available
  if (timeSeriesData.value && timeSeriesData.value.data_points[index]) {
    const date = new Date(timeSeriesData.value.data_points[index].timestamp)

    switch (selectedPeriod.value) {
      case '1h':
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
      case '1day':
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
      case '7day':
        return date.toLocaleDateString('en-US', { weekday: 'short' })
      case '30day':
        return date.toLocaleDateString('en-US', { day: 'numeric' })
      default:
        return `${index}`
    }
  }

  // Fallback to index-based labels
  const labels: Record<string, (i: number) => string> = {
    '1h': (i) => `${i * 5}m`,
    '1day': (i) => `${i}:00`,
    '7day': (i) => ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][i] || `Day ${i + 1}`,
    '30day': (i) => `${i + 1}`,
  }
  return labels[selectedPeriod.value]?.(index) || `${index}`
}

// API returns clean, deduplicated data - just sort and limit
const recentPackages = computed(() => {
  return packages.value
    .slice()
    .sort((a, b) => new Date(b.cached_at).getTime() - new Date(a.cached_at).getTime())
    .slice(0, 10)
})

// Watch for period changes and fetch new data
watch(selectedPeriod, () => {
  fetchTimeSeriesData()
})

onMounted(async () => {
  await store.fetchStats()
  await store.fetchPackages()
  await fetchTimeSeriesData()
})

function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num)
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}
</script>
