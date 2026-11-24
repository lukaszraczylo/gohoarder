<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Insights" description="How the cache grows, what each registry holds, and how much of it the scanners have covered.">
      <template #actions>
        <Button variant="outline" :icon-start="faRotateRight" @click="refresh">Refresh</Button>
      </template>
    </PageHeader>

    <LoadingState v-if="loading && !stats" variant="kpi-grid" :columns="3" label="Loading statistics..." />

    <ErrorState v-else-if="error && !stats" variant="card" title="Could not load statistics" :message="error" @retry="refresh" />

    <template v-else>
      <Callout v-if="idleTtl > 0" type="note" size="sm">
        Cached items not requested for {{ formatDuration(idleTtl) }} are removed.
      </Callout>

      <Card data-testid="registry-breakdown">
        <CardHeader>
          <CardTitle as="h2">By registry</CardTitle>
          <CardDescription>Packages, disk and traffic for each upstream.</CardDescription>
        </CardHeader>
        <CardContent class="flex flex-col gap-6">
          <EmptyState v-if="registryRows.length === 0" size="sm" title="No registry data yet" description="Each registry appears after its first download." />
          <template v-else>
            <BarChart
              :labels="registryRows.map((r) => r.registry)"
              :series="[
                { name: 'Packages', data: registryRows.map((r) => r.count) },
                { name: 'Downloads', data: registryRows.map((r) => r.downloads) },
              ]"
              label="Packages and downloads by registry"
            />
            <DataTable label="Registry breakdown" layout="cards" row-key="registry" :columns="registryColumns" :rows="registryRows">
              <template #cell-registry="{ row }"><Badge variant="outline">{{ row.registry }}</Badge></template>
              <template #cell-share="{ row }">
                <StatBar label="Share of disk" hide-label :value="row.size" :max="Math.max(totalSize, 1)" :value-text="sharePercent(row.size)" />
              </template>
            </DataTable>
          </template>
        </CardContent>
      </Card>

      <Card data-testid="scan-coverage">
        <CardHeader>
          <CardTitle as="h2">Scan coverage</CardTitle>
          <CardDescription>Share of cached package files with a scan result.</CardDescription>
        </CardHeader>
        <CardContent class="flex flex-col gap-6">
          <StatBar
            label="Scanned"
            :value="stats?.scanned_packages ?? 0"
            :max="Math.max(stats?.total_packages ?? 0, 1)"
            :value-text="`${stats?.scanned_packages ?? 0} of ${stats?.total_packages ?? 0}`"
          />
          <StatGroup :columns="4" aria-label="Scan outcomes">
            <KpiTile v-for="tile in outcomeTiles" :key="tile.verdict" :as="RouterLink" :to="tile.to" variant="interactive" :label="tile.label" :value="tile.value" />
          </StatGroup>
        </CardContent>
      </Card>

      <TrendChart />

      <Card data-testid="daily-downloads">
        <CardHeader>
          <CardTitle as="h2">Daily downloads</CardTitle>
          <CardDescription>The last 30 days. A stronger colour is a busier day.</CardDescription>
        </CardHeader>
        <CardContent>
          <LoadingState v-if="heatLoading && heatData.length === 0" layout="inline" label="Loading daily downloads..." />
          <ErrorState v-else-if="heatError" variant="inline" title="Could not load daily downloads" :message="heatError" @retry="loadHeatmap" />
          <EmptyState v-else-if="heatData.length === 0" size="sm" title="No downloads yet" description="Days fill in as clients request packages." />
          <div v-else class="flex flex-wrap items-start gap-x-12 gap-y-6">
            <CalendarHeatmap
              :data="heatData"
              :start="heatStart"
              :end="heatEnd"
              label="Downloads per day over the last 30 days"
              :cell-title="(date: string, value: number | null) => `${date}: ${value ?? 0} downloads`"
            />
            <DescriptionList variant="grid" :columns="3" class="min-w-64 flex-1" data-testid="heatmap-summary">
              <DescriptionItem term="Total">{{ formatNumber(heatSummary.total) }}</DescriptionItem>
              <DescriptionItem term="Active days">{{ heatSummary.activeDays }} of {{ heatData.length }}</DescriptionItem>
              <DescriptionItem term="Busiest day">{{ heatSummary.busiest }}</DescriptionItem>
            </DescriptionList>
          </div>
        </CardContent>
      </Card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { storeToRefs } from 'pinia'
import axios from 'axios'
import { RouterLink } from 'vue-router'
import {
  Badge,
  BarChart,
  Button,
  CalendarHeatmap,
  DescriptionItem,
  DescriptionList,
  Callout,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataTable,
  EmptyState,
  ErrorState,
  KpiTile,
  LoadingState,
  PageHeader,
  StatBar,
  StatGroup,
  type DataTableColumn,
} from '@perfect-design/ui'
import TrendChart from './TrendChart.vue'
import { usePackageStore } from '../stores/packages'
import { formatBytes, formatDuration, formatNumber } from '@/lib/format'
import { faRotateRight } from '@/lib/icons'
import { isoDay, type TimeSeries } from '@/lib/timeseries'

interface RegistryRow {
  registry: string
  count: number
  size: number
  downloads: number
}

const store = usePackageStore()
const { stats, registries, loading, error } = storeToRefs(store)

const idleTtl = computed(() => stats.value?.idle_ttl ?? 0)
const totalSize = computed(() => stats.value?.total_size ?? 0)

const registryRows = computed<RegistryRow[]>(() =>
  Object.entries(registries.value)
    .map(([registry, r]) => ({ registry, count: r.count ?? 0, size: r.size ?? 0, downloads: r.downloads ?? 0 }))
    .sort((a, b) => b.size - a.size),
)

function sharePercent(size: number): string {
  return totalSize.value > 0 ? `${Math.round((size / totalSize.value) * 100)}%` : '0%'
}

const registryColumns: DataTableColumn<RegistryRow>[] = [
  { key: 'registry', header: 'Registry', rowHeader: true },
  { key: 'count', header: 'Packages', numeric: true, accessor: (r) => formatNumber(r.count) },
  { key: 'size', header: 'Disk', numeric: true, accessor: (r) => formatBytes(r.size) },
  { key: 'downloads', header: 'Downloads', numeric: true, accessor: (r) => formatNumber(r.downloads) },
  { key: 'share', header: 'Share of disk', accessor: (r) => r.size },
]

const outcomeTiles = computed(() => {
  const s = stats.value
  const total = s?.total_packages ?? 0
  const scanned = s?.scanned_packages ?? 0
  const held = s?.blocked_packages ?? 0
  const bypassed = s?.bypassed_packages ?? 0
  return [
    { verdict: 'cleared', label: 'Cleared', value: Math.max(scanned - held - bypassed, 0), to: '/packages?verdict=cleared' },
    { verdict: 'held', label: 'Held', value: held, to: '/security?tab=held' },
    { verdict: 'bypassed', label: 'Bypassed', value: bypassed, to: '/security?tab=bypassed' },
    { verdict: 'pending', label: 'Awaiting scan', value: Math.max(total - scanned, 0), to: '/packages?verdict=pending' },
  ]
})

const heatPoints = ref<TimeSeries['data_points']>([])
const heatLoading = ref(false)
const heatError = ref<string | null>(null)

// An all-zero month has nothing to shade, so it reads as empty.
const heatData = computed(() =>
  heatPoints.value.some((p) => p.value > 0) ? heatPoints.value.map((p) => ({ date: isoDay(p.timestamp), value: p.value })) : [],
)
const heatSummary = computed(() => {
  const days = heatData.value
  const busiest = days.reduce((max, d) => (d.value > max.value ? d : max), days[0] ?? { date: '', value: 0 })
  return {
    total: days.reduce((sum, d) => sum + d.value, 0),
    activeDays: days.filter((d) => d.value > 0).length,
    busiest: busiest.value > 0 ? `${busiest.date}, ${formatNumber(busiest.value)}` : 'None',
  }
})
const heatStart = computed(() => heatData.value[0]?.date ?? '')
const heatEnd = computed(() => heatData.value[heatData.value.length - 1]?.date ?? '')

async function loadHeatmap() {
  heatLoading.value = true
  heatError.value = null
  try {
    const response = await axios.get<TimeSeries>('/api/stats/timeseries?period=30day')
    heatPoints.value = response.data.data_points ?? []
  } catch (err) {
    heatError.value = err instanceof Error ? err.message : 'Failed to load daily downloads'
  } finally {
    heatLoading.value = false
  }
}

function refresh() {
  void store.fetchStats()
  void loadHeatmap()
}

onMounted(refresh)
</script>
