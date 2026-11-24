<template>
  <LoadingState v-if="loading" layout="inline" label="Loading download history..." />
  <ErrorState v-else-if="error" variant="inline" title="Could not load download history" :message="error" @retry="load" />
  <div v-else class="flex flex-col gap-4">
    <StatGroup :columns="3" aria-label="Downloads of this package">
      <KpiTile label="This version" :value="downloadCount" hint="Times served from the cache, kept across restarts" />
      <template v-if="stats">
        <KpiTile
          label="All versions"
          :value="stats.TotalDownloads"
          :hint="`${stats.UniqueVersions} version${stats.UniqueVersions === 1 ? '' : 's'} since the last restart`"
        />
        <KpiTile label="Data served" :value="formatBytes(stats.BytesServed)" hint="Across all versions, since the last restart" />
      </template>
    </StatGroup>
    <DescriptionList v-if="stats" :columns="2" divided>
      <DescriptionItem term="First seen since restart"><RelativeTime :datetime="stats.FirstSeen" /></DescriptionItem>
      <DescriptionItem term="Last download"><RelativeTime :datetime="stats.LastDownload" /></DescriptionItem>
    </DescriptionList>
    <EmptyState
      v-else
      size="sm"
      :icon="faDownload"
      title="No downloads since the last restart"
      description="The totals across versions are counted in memory, so they start again when the server restarts."
    />
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

const props = defineProps<{ registry: string; name: string; downloadCount: number }>()

const stats = ref<PackageAnalytics | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

// Analytics are keyed by package name; a Go module is named by its path.
const analyticsName = computed(() => modulePath(props.name))

async function load() {
  loading.value = true
  error.value = null
  try {
    const response = await axios.get<{ package: PackageAnalytics | null }>(
      `/api/analytics/package/${props.registry}/${analyticsName.value}`,
    )
    stats.value = response.data.package
  } catch (err) {
    stats.value = null
    error.value = err instanceof Error ? err.message : 'Failed to load download history'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
