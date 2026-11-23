<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Dashboard" description="What the cache holds and what is moving through it.">
      <template #actions>
        <StatusBadge
          :status="rt.connected ? 'live' : 'paused'"
          :label="rt.connected ? 'Live' : 'Live updates paused'"
          :tones="{ live: 'success', paused: 'neutral' }"
          :pulse="rt.connected"
          data-testid="ws-live-indicator"
        />
      </template>
    </PageHeader>

    <LoadingState v-if="loading" variant="kpi-grid" :columns="4" label="Loading statistics..." />

    <ErrorState
      v-else-if="error"
      variant="card"
      title="Could not load statistics"
      :message="error"
      @retry="refresh"
    />

    <template v-else>
    <StatGroup :columns="4" aria-label="Cache totals">
      <KpiTile label="Total packages" :value="displayStats?.total_packages || 0" :icon="faBoxesStacked" />
      <KpiTile label="Total size" :value="formatBytes(displayStats?.total_size || 0)" :icon="faHardDrive" />
      <KpiTile label="Total downloads" :value="displayStats?.total_downloads || 0" :icon="faDownload" />
      <KpiTile label="Scanned packages" :value="displayStats?.scanned_packages || 0" :icon="faShieldHalved" />
    </StatGroup>

    <Card v-if="recentRealtimeEvents.length > 0" data-testid="ws-event-feed">
      <CardHeader>
        <CardTitle as="h2">Live activity</CardTitle>
      </CardHeader>
      <CardContent>
        <ActivityFeed :events="feedEvents" variant="compact" label="Live activity" />
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle as="h2">Download activity</CardTitle>
        <CardAction>
          <SegmentedControl v-model="selectedPeriod" :options="chartPeriods" aria-label="Period" />
        </CardAction>
      </CardHeader>
      <CardContent>
        <LoadingState
          v-if="chartLoading && chartData.length === 0"
          layout="inline"
          label="Loading chart data..."
        />
        <ErrorState
          v-else-if="chartError"
          variant="inline"
          title="Could not load download activity"
          :message="chartError"
          @retry="fetchTimeSeriesData"
        />
        <BarChart
          v-else
          :labels="chartLabels"
          :series="[{ name: 'Downloads', data: chartData }]"
          label="Downloads over the selected period"
          empty-text="No download activity in this period"
        />
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle as="h2">Recent packages</CardTitle>
      </CardHeader>
      <CardContent>
        <EmptyState
          v-if="packages.length === 0"
          size="sm"
          :icon="faBoxOpen"
          title="No packages cached yet"
          description="Packages appear here once they are downloaded through the proxy."
        />
        <DataTable
          v-else
          label="Recent packages"
          layout="cards"
          :columns="packageColumns"
          :rows="recentPackages"
        >
          <template #cell-registry="{ row }">
            <Badge variant="outline">{{ row.registry }}</Badge>
          </template>
        </DataTable>
      </CardContent>
    </Card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import axios from 'axios'
import {
  ActivityFeed,
  BarChart,
  Badge,
  Card,
  CardAction,
  CardContent,
  CardHeader,
  CardTitle,
  DataTable,
  EmptyState,
  ErrorState,
  KpiTile,
  LoadingState,
  PageHeader,
  SegmentedControl,
  StatGroup,
  StatusBadge,
  type ActivityEvent,
  type DataTableColumn,
} from '@perfect-design/ui'
import type { IconDefinition } from '@perfect-design/ui/lib/icons-tools'
import { usePackageStore, type Package } from '../stores/packages'
import { useRealtimeStore } from '../stores/realtime'
import type { EventType, RealtimeEvent } from '@/lib/ws'
import { formatBytes, formatNumber } from '@/lib/format'
import {
  faBox,
  faBoxOpen,
  faBoxesStacked,
  faChartLine,
  faDownload,
  faHardDrive,
  faShieldHalved,
  faTrash,
} from '@/lib/icons'

const store = usePackageStore()
const { packages, stats, loading, error } = storeToRefs(store)

const rt = useRealtimeStore()
const { lastStats, events: rtEvents } = storeToRefs(rt)

// Realtime stats override polled stats when available; otherwise fall back.
const displayStats = computed(() => lastStats.value ?? stats.value)

const recentRealtimeEvents = computed<RealtimeEvent[]>(() => {
  const list = rtEvents.value
  return list.slice(Math.max(list.length - 5, 0)).reverse()
})

const EVENT_LABELS: Record<EventType, string> = {
  package_cached: 'Cached',
  package_deleted: 'Deleted',
  package_downloaded: 'Downloaded',
  scan_complete: 'Scan complete',
  stats_update: 'Stats update',
}

const EVENT_ICONS: Record<EventType, IconDefinition> = {
  package_cached: faBox,
  package_deleted: faTrash,
  package_downloaded: faDownload,
  scan_complete: faShieldHalved,
  stats_update: faChartLine,
}

function iconForEvent(type: EventType): IconDefinition {
  return EVENT_ICONS[type] ?? faChartLine
}

const feedEvents = computed<ActivityEvent[]>(() =>
  recentRealtimeEvents.value.map((evt, idx) => ({
    id: `${evt.timestamp}-${idx}`,
    action: labelForEvent(evt.type),
    target: describeEvent(evt) || undefined,
    time: evt.timestamp,
    icon: iconForEvent(evt.type),
  })),
)

function labelForEvent(type: EventType): string {
  return EVENT_LABELS[type] ?? type
}

function describeEvent(evt: RealtimeEvent): string {
  const p = evt.payload
  const name = typeof p.name === 'string' ? p.name : ''
  const version = typeof p.version === 'string' ? `@${p.version}` : ''
  const registry = typeof p.registry === 'string' ? `[${p.registry}] ` : ''
  if (evt.type === 'stats_update') return ''
  if (name) return `${registry}${name}${version}`
  return ''
}

// Chart periods and data
const selectedPeriod = ref<string>('1day')
const chartPeriods = [
  { value: '1h', label: '1 hour' },
  { value: '1day', label: '24 hours' },
  { value: '7day', label: '7 days' },
  { value: '30day', label: '30 days' },
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
const chartError = ref<string | null>(null)

// Fetch time-series data from API
async function fetchTimeSeriesData() {
  chartLoading.value = true
  chartError.value = null
  try {
    const response = await axios.get(`/api/stats/timeseries?period=${selectedPeriod.value}`)
    timeSeriesData.value = response.data
  } catch (err) {
    console.error('Failed to fetch time-series data:', err)
    timeSeriesData.value = null
    chartError.value = err instanceof Error ? err.message : 'Failed to load download activity'
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

const chartLabels = computed(() => chartData.value.map((_, index) => getChartLabel(index)))

const packageColumns: DataTableColumn<Package>[] = [
  { key: 'name', header: 'Package', rowHeader: true },
  { key: 'version', header: 'Version' },
  { key: 'registry', header: 'Registry' },
  { key: 'size', header: 'Size', numeric: true, accessor: (pkg) => formatBytes(pkg.size) },
  { key: 'download_count', header: 'Downloads', numeric: true, accessor: (pkg) => formatNumber(pkg.download_count) },
]

function refresh() {
  void store.fetchStats()
  void store.fetchPackages()
}

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
  // Connect to realtime stream first so we can pick up live events while
  // initial polling resolves. Singleton survives navigation, so we
  // intentionally do not disconnect on unmount.
  rt.connect()
  await store.fetchStats()
  await store.fetchPackages()
  await fetchTimeSeriesData()
})

</script>
