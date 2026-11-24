<template>
  <Card data-testid="trend-card">
    <CardHeader>
      <CardTitle as="h2">{{ compact ? 'Cached packages' : 'Packages over time' }}</CardTitle>
      <CardDescription>
        {{ compact ? 'Daily total, last 30 days.' : 'The cache at the end of each UTC day.' }}
      </CardDescription>
      <CardAction>
        <SegmentedControl v-if="!compact" v-model="period" :options="TREND_PERIODS" aria-label="Trend period" />
        <Button v-else as-child variant="link" size="sm">
          <RouterLink to="/stats">Open the full history</RouterLink>
        </Button>
      </CardAction>
    </CardHeader>
    <CardContent class="flex flex-col gap-8">
      <LoadingState v-if="loading && !data" layout="inline" label="Loading package history..." />
      <ErrorState
        v-else-if="error"
        variant="inline"
        title="Could not load the package history"
        :message="error"
        @retry="load"
      />
      <EmptyState
        v-else-if="points.length === 0"
        title="No history yet"
        description="The server records the first daily snapshot when it starts, then one more each day."
      />
      <template v-else>
        <section class="flex flex-col gap-3" aria-labelledby="trend-packages-heading">
          <h3 id="trend-packages-heading" class="text-sm font-medium">Cached packages</h3>
          <p v-if="singleDay" class="m-0 text-sm text-muted-foreground" data-testid="trend-single-day">{{ SINGLE_DAY_NOTE }}</p>
          <LineChart
            variant="area"
            :size="compact ? 'sm' : 'md'"
            :y-min="0"
            :labels="labels"
            :series="[{ name: 'Cached packages', data: values('total_packages'), tone: 'primary' }]"
            :label="packagesLabel"
          />
        </section>

        <p v-if="compact" class="text-sm text-muted-foreground" data-testid="trend-compact-vulnerable">
          {{ compactVulnerable }}
        </p>

        <section v-else class="flex flex-col gap-3" aria-labelledby="trend-vulnerable-heading">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h3 id="trend-vulnerable-heading" class="text-sm font-medium">Vulnerable packages</h3>
            <ToggleGroup
              v-model="severities"
              type="multiple"
              variant="outline"
              tone="primary"
              size="sm"
              aria-label="Add a line per severity"
            >
              <ToggleGroupItem v-for="level in SEVERITY_LEVELS" :key="level" :value="level">
                {{ formatSeverityName(level) }}
              </ToggleGroupItem>
            </ToggleGroup>
          </div>
          <p v-if="vulnerabilityNote" class="text-sm text-muted-foreground" data-testid="trend-vulnerability-note">
            {{ vulnerabilityNote }}
          </p>
          <p v-if="singleDay" class="m-0 text-sm text-muted-foreground">{{ SINGLE_DAY_NOTE }}</p>
          <p class="m-0 text-sm text-muted-foreground" data-testid="trend-series-key">{{ seriesKey }}</p>
          <LineChart
            v-if="data?.vulnerability_history_start"
            :y-min="0"
            :labels="labels"
            :series="vulnerableSeries"
            :label="vulnerableLabel"
          />
          <EmptyState
            v-else
            size="sm"
            title="Vulnerability history has not started"
            description="Scan results are counted from the first daily snapshot that includes them."
          />
        </section>
      </template>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import axios from 'axios'
import { RouterLink } from 'vue-router'
import {
  Button,
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  ErrorState,
  LineChart,
  LoadingState,
  SegmentedControl,
  ToggleGroup,
  ToggleGroupItem,
} from '@perfect-design/ui'
import { plural } from '@/lib/reason'
import { SEVERITY_LEVELS, formatSeverityName, type SeverityLevel } from '@/lib/severity'
import {
  DEFAULT_TREND_PERIOD,
  SEVERITY_LINE_TONES,
  TREND_PERIODS,
  formatTrendDate,
  trendValues,
  type TrendPeriod,
  type TrendPoint,
  type TrendResponse,
} from '@/lib/trend'

const props = defineProps<{
  /** Dashboard card: 30 days, cached packages only, a link to the full history. */
  compact?: boolean
}>()

const period = ref<TrendPeriod>(DEFAULT_TREND_PERIOD)
const severities = ref<SeverityLevel[]>([])
const data = ref<TrendResponse | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

let request = 0

async function load() {
  const current = ++request
  loading.value = true
  error.value = null
  try {
    const response = await axios.get(`/api/stats/trend?period=${props.compact ? DEFAULT_TREND_PERIOD : period.value}`)
    if (current !== request) return
    const body = response.data as TrendResponse | undefined
    if (!body || !Array.isArray(body.points)) {
      data.value = null
      error.value = 'Unexpected response format from server'
      return
    }
    data.value = body
  } catch (err) {
    if (current !== request) return
    data.value = null
    error.value = err instanceof Error ? err.message : 'Failed to load the package history'
  } finally {
    if (current === request) loading.value = false
  }
}

onMounted(load)
watch(period, load)

const points = computed<TrendPoint[]>(() => data.value?.points ?? [])
const labels = computed(() => points.value.map((p) => formatTrendDate(p.date, period.value === '1year')))
const values = (key: keyof Omit<TrendPoint, 'date'>) => trendValues(points.value, key)

function span(key: keyof Omit<TrendPoint, 'date'>): string {
  const known = points.value.filter((p) => p[key] !== null)
  const first = known[0]
  const last = known[known.length - 1]
  if (!first || !last) return ''
  return `from ${first[key]} on ${formatTrendDate(first.date, true)} to ${last[key]} on ${formatTrendDate(last.date, true)}`
}

const packagesLabel = computed(() => `Cached packages per day, ${span('total_packages')}`)
const vulnerableLabel = computed(() => {
  const extra = severities.value.length ? `, with lines for ${severities.value.join(', ')}` : ''
  return `Vulnerable packages per day, ${span('vulnerable_packages')}${extra}`
})

const vulnerableSeries = computed(() => [
  { name: 'Vulnerable packages', data: values('vulnerable_packages'), tone: 'primary' as const },
  ...SEVERITY_LEVELS.filter((level) => severities.value.includes(level)).map((level) => ({
    name: `Packages with ${level} vulnerabilities`,
    data: values(level),
    tone: SEVERITY_LINE_TONES[level],
  })),
])

const SINGLE_DAY_NOTE = 'One day of history so far. A line appears once there is a second day.'
const singleDay = computed(() => points.value.length === 1)

const seriesKey = computed(() => {
  const all = 'Plotted: packages with any finding.'
  if (severities.value.length === 0) return `${all} Select a severity to add its own line.`
  return `${all} Added: ${severities.value.join(', ')}.`
})

// Earlier days were never scanned, so their counts are unknown and drawn as a gap.
const vulnerabilityNote = computed(() => {
  const start = data.value?.vulnerability_history_start
  const first = points.value[0]
  if (!start) return 'Vulnerability history has not started in this period.'
  if (first && start > first.date) return `Vulnerability history starts ${formatTrendDate(start, true)}.`
  return ''
})

const compactVulnerable = computed(() => {
  const last = points.value[points.value.length - 1]
  const n = last?.vulnerable_packages
  if (n === null || n === undefined) return 'Vulnerability history has not started yet.'
  return `${plural(n, 'vulnerable package')} on ${formatTrendDate(last!.date, true)}.`
})
</script>
