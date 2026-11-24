<template>
  <Card class="min-w-0" data-testid="download-trend">
    <CardHeader>
      <CardTitle as="h2">Downloads</CardTitle>
      <CardDescription>Packages served to clients, in UTC.</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <div class="flex sm:justify-end">
        <SegmentedControl v-model="period" :options="DOWNLOAD_PERIODS" aria-label="Download period" />
      </div>
      <LoadingState v-if="loading && points.length === 0" layout="inline" label="Loading downloads..." />
      <ErrorState v-else-if="error" variant="inline" title="Could not load downloads" :message="error" @retry="load" />
      <LineChart
        v-else
        variant="area"
        :y-min="0"
        :labels="labels"
        :series="[{ name: 'Downloads', data: values, tone: 'primary' }]"
        :label="`Downloads over the last ${periodLabel}, ${total} in total`"
        empty-text="No downloads in this period"
      />
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import axios from 'axios'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  ErrorState,
  LineChart,
  LoadingState,
  SegmentedControl,
} from '@perfect-design/ui'
import { DOWNLOAD_PERIODS, bucketLabel, type DownloadPeriod, type TimeSeries } from '@/lib/timeseries'

const period = ref<DownloadPeriod>('1day')
const data = ref<TimeSeries | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
let request = 0

const points = computed(() => data.value?.data_points ?? [])
const values = computed(() => points.value.map((p) => p.value))
const labels = computed(() => points.value.map((p) => bucketLabel(period.value, p.timestamp)))
const total = computed(() => values.value.reduce((sum, v) => sum + v, 0))
const periodLabel = computed(() => DOWNLOAD_PERIODS.find((p) => p.value === period.value)?.label ?? '')

async function load() {
  const current = ++request
  loading.value = true
  error.value = null
  try {
    const response = await axios.get<TimeSeries>(`/api/stats/timeseries?period=${period.value}`)
    if (current === request) data.value = response.data
  } catch (err) {
    if (current !== request) return
    data.value = null
    error.value = err instanceof Error ? err.message : 'Failed to load downloads'
  } finally {
    if (current === request) loading.value = false
  }
}

watch(period, load)
onMounted(load)
</script>
