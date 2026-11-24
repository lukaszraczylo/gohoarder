<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Overview" description="Packages arrive at the proxy, the scanners inspect them, and each is cleared, held or waved through.">
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

    <PolicyLine />

    <LoadingState v-if="loading && !displayStats" variant="kpi-grid" :columns="4" label="Loading statistics..." />

    <ErrorState
      v-else-if="error && !displayStats"
      variant="card"
      title="Could not load statistics"
      :message="error"
      @retry="refresh"
    />

    <template v-else>
      <StatGroup :columns="4" aria-label="Verdicts" data-testid="verdict-strip">
        <KpiTile
          v-for="tile in verdictTiles"
          :key="tile.verdict"
          :as="RouterLink"
          :to="tile.to"
          variant="interactive"
          :label="VERDICT_LABELS[tile.verdict]"
          :value="tile.value"
          :hint="tile.hint"
          :data-verdict="tile.verdict"
        >
          <template #icon><Icon :icon="tile.icon" :class="VERDICT_TEXT[tile.verdict]" /></template>
        </KpiTile>
      </StatGroup>

      <div class="grid items-start gap-6 xl:grid-cols-3">
        <CacheCapacity :used="displayStats?.total_size ?? 0" :max-size="displayStats?.max_cache_size ?? 0" :registries="registries" />
        <DownloadTrend class="xl:col-span-2" />
      </div>

      <TopPackages />

      <div class="grid gap-6 lg:grid-cols-2">
        <ScannerHealth />
        <Card class="min-w-0" data-testid="ws-event-feed">
          <CardHeader>
            <CardTitle as="h2">Live activity</CardTitle>
            <CardDescription>What the proxy just did.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState
              v-if="feedEvents.length === 0"
              size="sm"
              :icon="faBoxOpen"
              title="Quiet at the desk"
              description="Cached, downloaded and scanned packages appear here as they happen."
            />
            <ActivityFeed v-else :events="feedEvents" variant="compact" label="Live activity" />
          </CardContent>
        </Card>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { RouterLink } from 'vue-router'
import {
  ActivityFeed,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  ErrorState,
  Icon,
  KpiTile,
  LoadingState,
  PageHeader,
  StatGroup,
  StatusBadge,
  type ActivityEvent,
} from '@perfect-design/ui'
import type { IconDefinition } from '@perfect-design/ui/lib/icons-tools'
import CacheCapacity from './parts/CacheCapacity.vue'
import DownloadTrend from './parts/DownloadTrend.vue'
import PolicyLine from './parts/PolicyLine.vue'
import ScannerHealth from './parts/ScannerHealth.vue'
import TopPackages from './parts/TopPackages.vue'
import { usePackageStore, type Stats } from '../stores/packages'
import { useRealtimeStore } from '../stores/realtime'
import type { EventType, RealtimeEvent } from '@/lib/ws'
import { VERDICT_LABELS, VERDICT_TEXT, type Verdict } from '@/lib/verdict'
import {
  faBan,
  faBox,
  faBoxOpen,
  faChartLine,
  faCircleCheck,
  faDownload,
  faHourglassHalf,
  faShieldHalved,
  faTrash,
  faUnlockKeyhole,
} from '@/lib/icons'

const store = usePackageStore()
const { stats, registries, loading, error } = storeToRefs(store)

const rt = useRealtimeStore()
const { lastStats, events: rtEvents } = storeToRefs(rt)

// A live stats frame can lack counters the polled response carries, so it overlays rather than replaces.
const displayStats = computed<Stats | null>(() => {
  if (!stats.value && !lastStats.value) return null
  return { ...stats.value, ...lastStats.value } as Stats
})

interface VerdictTile {
  verdict: Verdict
  value: number
  hint: string
  to: string
  icon: IconDefinition
}

const verdictTiles = computed<VerdictTile[]>(() => {
  const s = displayStats.value
  const total = s?.total_packages ?? 0
  const scanned = s?.scanned_packages ?? 0
  const held = s?.blocked_packages ?? 0
  const bypassed = s?.bypassed_packages ?? 0
  const tiles: Array<[Verdict, number, string, string, IconDefinition]> = [
    ['cleared', Math.max(scanned - held - bypassed, 0), 'Scanned and served', '/packages?verdict=cleared', faCircleCheck],
    ['held', held, 'Blocked with a 403', '/security?tab=held', faBan],
    ['bypassed', bypassed, 'Served under an admin bypass', '/security?tab=bypassed', faUnlockKeyhole],
    ['pending', Math.max(total - scanned, 0), 'No scan result yet', '/packages?verdict=pending', faHourglassHalf],
  ]
  return tiles.map(([verdict, value, hint, to, icon]) => ({ verdict, value, hint, to, icon }))
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

const FEED_LENGTH = 6

const feedEvents = computed<ActivityEvent[]>(() =>
  rtEvents.value
    .filter((evt) => evt.type !== 'stats_update')
    .slice(-FEED_LENGTH)
    .reverse()
    .map((evt, idx) => ({
      id: `${evt.timestamp}-${idx}`,
      action: EVENT_LABELS[evt.type] ?? evt.type,
      target: describeEvent(evt) || undefined,
      time: evt.timestamp,
      icon: EVENT_ICONS[evt.type] ?? faChartLine,
    })),
)

function describeEvent(evt: RealtimeEvent): string {
  const p = evt.payload
  const name = typeof p.name === 'string' ? p.name : ''
  const shown = typeof p.release_version === 'string' && p.release_version ? p.release_version : p.version
  const version = typeof shown === 'string' ? `@${shown}` : ''
  const registry = typeof p.registry === 'string' ? `[${p.registry}] ` : ''
  return name ? `${registry}${name}${version}` : ''
}

function refresh() {
  void store.fetchStats()
}

onMounted(() => {
  // The realtime client is a singleton that outlives this view, so it is never disconnected here.
  rt.connect()
  refresh()
})
</script>
