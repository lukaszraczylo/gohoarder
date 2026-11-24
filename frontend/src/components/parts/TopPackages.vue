<template>
  <div class="grid gap-6 lg:grid-cols-2" data-testid="top-packages">
    <Card class="min-w-0">
      <CardHeader>
        <CardTitle as="h2">Most requested</CardTitle>
        <CardDescription>Total downloads since the server started.</CardDescription>
      </CardHeader>
      <CardContent>
        <LoadingState v-if="loading" layout="inline" label="Loading top packages..." />
        <ErrorState v-else-if="error" variant="inline" title="Could not load top packages" :message="error" @retry="load" />
        <EmptyState v-else-if="top.length === 0" size="sm" title="No downloads yet" description="Rankings appear after the first download." />
        <Leaderboard v-else label="Most requested packages" bars :entries="top" :column-labels="{ rank: 'Rank', name: 'Package', value: 'Downloads', delta: 'Change' }" />
      </CardContent>
    </Card>
    <Card class="min-w-0">
      <CardHeader>
        <CardTitle as="h2">Trending</CardTitle>
        <CardDescription>Downloads in the last 7 days.</CardDescription>
      </CardHeader>
      <CardContent>
        <LoadingState v-if="loading" layout="inline" label="Loading trending packages..." />
        <ErrorState v-else-if="error" variant="inline" title="Could not load trending packages" :message="error" @retry="load" />
        <EmptyState v-else-if="trending.length === 0" size="sm" title="Nothing trending" description="No package was downloaded in the last 7 days." />
        <Leaderboard v-else label="Trending packages" bars :entries="trending" :column-labels="{ rank: 'Rank', name: 'Package', value: 'Last 7 days', delta: 'Change' }" />
      </CardContent>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import axios from 'axios'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  ErrorState,
  Leaderboard,
  LoadingState,
  type LeaderboardEntry,
} from '@perfect-design/ui'
import { modulePath } from '@/lib/format'

/** The analytics engine serialises Go field names. */
interface PopularPackage {
  Registry: string
  Name: string
  Downloads: number
  RecentDownloads: number
}

const LIMIT = 8
const popular = ref<PopularPackage[]>([])
const recent = ref<PopularPackage[]>([])
const loading = ref(false)
const error = ref<string | null>(null)

// Rows with equal registry and module path (a Go module's .zip, .mod and .info) are one package.
function entries(rows: PopularPackage[], pick: (p: PopularPackage) => number): LeaderboardEntry[] {
  const totals = new Map<string, LeaderboardEntry>()
  for (const row of rows) {
    const id = `${row.Registry}/${modulePath(row.Name)}`
    const existing = totals.get(id)
    if (existing) existing.value += pick(row)
    else totals.set(id, { id, label: `${row.Registry} · ${modulePath(row.Name)}`, value: pick(row) })
  }
  return [...totals.values()].filter((e) => e.value > 0).sort((a, b) => b.value - a.value).slice(0, LIMIT)
}

const top = computed(() => entries(popular.value, (p) => p.Downloads))
const trending = computed(() => entries(recent.value, (p) => p.RecentDownloads))

async function load() {
  loading.value = true
  error.value = null
  try {
    const [topRes, trendRes] = await Promise.all([
      axios.get<{ packages: PopularPackage[] }>('/api/analytics/top?limit=50'),
      axios.get<{ packages: PopularPackage[] }>('/api/analytics/trending?limit=50'),
    ])
    popular.value = topRes.data.packages ?? []
    recent.value = trendRes.data.packages ?? []
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load package rankings'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
