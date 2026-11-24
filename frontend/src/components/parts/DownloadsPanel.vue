<template>
  <LoadingState v-if="loading" layout="inline" label="Loading download history..." />
  <ErrorState v-else-if="error" variant="inline" title="Could not load download history" :message="error" @retry="load" />
  <EmptyState
    v-else-if="!stats"
    size="sm"
    :icon="faDownload"
    title="No download history"
    description="The server records downloads in memory, so history starts at its last restart."
  />
  <div v-else class="flex flex-col gap-4">
    <StatGroup :columns="3" aria-label="Downloads of this package">
      <KpiTile label="This version" :value="downloadCount" hint="Times served from the cache" />
      <KpiTile
        :label="isGo ? 'Module zip' : 'All versions'"
        :value="stats.TotalDownloads"
        :hint="isGo ? 'Downloads of this version' : `${stats.UniqueVersions} version${stats.UniqueVersions === 1 ? '' : 's'} seen`"
      />
      <KpiTile label="Data served" :value="formatBytes(stats.BytesServed)" :hint="isGo ? 'This version' : 'Across all versions'" />
    </StatGroup>
    <DescriptionList :columns="2" divided>
      <DescriptionItem term="First seen"><RelativeTime :datetime="stats.FirstSeen" /></DescriptionItem>
      <DescriptionItem term="Last download"><RelativeTime :datetime="stats.LastDownload" /></DescriptionItem>
    </DescriptionList>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import axios from 'axios'
import {
  DescriptionItem,
  DescriptionList,
  EmptyState,
  ErrorState,
  KpiTile,
  LoadingState,
  RelativeTime,
  StatGroup,
} from '@perfect-design/ui'
import { formatBytes, modulePath } from '@/lib/format'
import { faDownload } from '@/lib/icons'

/** The analytics engine serialises Go field names. */
interface PackageAnalytics {
  TotalDownloads: number
  UniqueVersions: number
  BytesServed: number
  FirstSeen: string
  LastDownload: string
}

const props = defineProps<{ registry: string; name: string; version: string; downloadCount: number }>()

const isGo = computed(() => props.registry === 'go')

const stats = ref<PackageAnalytics | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

// Go analytics are keyed by cache file, one per version.
const analyticsName = computed(() => (isGo.value ? `${modulePath(props.name)}/@v/${props.version}.zip` : props.name))

async function load() {
  loading.value = true
  error.value = null
  try {
    const response = await axios.get<{ package: PackageAnalytics }>(
      `/api/analytics/package/${props.registry}/${analyticsName.value}`,
    )
    stats.value = response.data.package
  } catch (err) {
    stats.value = null
    const status = (err as { response?: { status?: number } }).response?.status
    if (status !== 404) error.value = err instanceof Error ? err.message : 'Failed to load download history'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
