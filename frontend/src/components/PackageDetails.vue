<template>
  <div class="flex flex-col gap-6">
    <PageHeader :title="packageName" back-href="/packages" back-label="Back to packages">
      <template #description>
        <span class="flex flex-wrap items-center gap-2">
          <Badge variant="outline">{{ registry }}</Badge>
          <Badge variant="outline" class="font-mono">{{ withVersionPrefix(shownVersion) }}</Badge>
          <VerdictBadge v-if="report" :verdict="verdict" />
        </span>
      </template>
    </PageHeader>

    <LoadingState v-if="loading" variant="card" label="Loading package details..." />

    <ErrorState
      v-else-if="error"
      variant="card"
      title="Could not load this package"
      :message="error"
      @retry="load"
    />

    <template v-else-if="report">
      <Callout v-if="banner" :type="banner.type" :title="banner.title" data-testid="verdict-banner">{{ banner.body }}</Callout>

      <Card>
        <CardHeader>
          <CardTitle as="h2">Details</CardTitle>
        </CardHeader>
        <CardContent>
          <DescriptionList variant="grid" :columns="3" data-testid="package-meta">
            <DescriptionItem term="Size">{{ row ? formatBytes(row.size) : 'Unknown' }}</DescriptionItem>
            <DescriptionItem term="Downloads">{{ row ? formatNumber(row.download_count) : 'Unknown' }}</DescriptionItem>
            <DescriptionItem term="Checksum (SHA-256)" :copyable="Boolean(row?.checksum_sha256)" :copy-text="row?.checksum_sha256">
              <span class="break-all font-mono text-xs">{{ row?.checksum_sha256 || 'Not recorded' }}</span>
            </DescriptionItem>
            <DescriptionItem term="Upstream">{{ upstream }}</DescriptionItem>
            <DescriptionItem term="Cached">
              <RelativeTime v-if="row" :datetime="row.cached_at" />
              <template v-else>Unknown</template>
            </DescriptionItem>
            <DescriptionItem term="Last accessed">
              <RelativeTime v-if="row" :datetime="row.last_accessed" />
              <template v-else>Unknown</template>
            </DescriptionItem>
            <DescriptionItem term="Expiry">{{ expiry }}</DescriptionItem>
            <DescriptionItem term="Last scanned">
              <RelativeTime v-if="report.scanned_at" :datetime="report.scanned_at" />
              <template v-else>Never</template>
            </DescriptionItem>
          </DescriptionList>
        </CardContent>
      </Card>

      <Tabs v-model="tab">
        <TabsList aria-label="Package sections">
          <TabsTrigger value="vulnerabilities">Vulnerabilities ({{ report.vulnerability_count }})</TabsTrigger>
          <TabsTrigger value="inspectors">Inspectors</TabsTrigger>
          <TabsTrigger value="downloads">Downloads</TabsTrigger>
          <TabsTrigger value="bypass">Bypass</TabsTrigger>
        </TabsList>

        <TabsContent value="vulnerabilities" class="pt-4">
          <div class="flex flex-col gap-4">
            <SeveritySummary :counts="severityCounts" label="Findings by severity" />
            <EmptyState
              v-if="report.vulnerabilities.length === 0"
              tone="success"
              :icon="faCircleCheck"
              :title="report.scanned ? 'No vulnerabilities found' : 'Not scanned yet'"
              :description="report.scanned ? 'The scanners reported nothing for this package version.' : 'Findings appear here once a scan completes.'"
            />
            <VulnerabilityTable v-else :vulnerabilities="report.vulnerabilities" />
          </div>
        </TabsContent>

        <TabsContent value="inspectors" class="pt-4">
          <InspectorMatrix :registry="registry" :results="report.scanners" :configured="configured" />
        </TabsContent>

        <TabsContent value="downloads" class="pt-4">
          <DownloadsPanel :registry="registry" :name="packageName" :version="version" :download-count="row?.download_count ?? 0" />
        </TabsContent>

        <TabsContent value="bypass" class="pt-4">
          <BypassPanel
            :applied="report.decision.bypass"
            :registry="registry"
            :name="packageName"
            :version="version"
            :release-version="report.package?.release_version"
          />
        </TabsContent>
      </Tabs>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import axios from 'axios'
import { useRoute, useRouter } from 'vue-router'
import {
  Badge,
  Callout,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  DescriptionItem,
  DescriptionList,
  EmptyState,
  ErrorState,
  LoadingState,
  PageHeader,
  RelativeTime,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@perfect-design/ui'
import SeveritySummary from './SeveritySummary.vue'
import BypassPanel from './parts/BypassPanel.vue'
import DownloadsPanel from './parts/DownloadsPanel.vue'
import InspectorMatrix from './parts/InspectorMatrix.vue'
import VerdictBadge from './parts/VerdictBadge.vue'
import VulnerabilityTable from './parts/VulnerabilityTable.vue'
import type { Package } from '../stores/packages'
import { formatBytes, formatDate, formatNumber, formatDuration, withVersionPrefix } from '@/lib/format'
import { faCircleCheck } from '@/lib/icons'
import type { PackageReport } from '@/lib/report'
import { NO_VULNERABILITIES } from '@/lib/severity'
import { describePolicy, useSystem } from '@/lib/system'
import type { Verdict } from '@/lib/verdict'
import { verdictBanner } from '@/lib/verdictBanner'

const TABS = ['vulnerabilities', 'inspectors', 'downloads', 'bypass'] as const
type TabName = (typeof TABS)[number]

const route = useRoute()
const router = useRouter()
const system = useSystem()

const registry = computed(() => route.params.registry as string)
// Names with slashes (scoped npm, Go modules) arrive as segments.
const packageName = computed(() => {
  const name = route.params.name
  return Array.isArray(name) ? name.join('/') : (name as string)
})
const version = computed(() => route.params.version as string)
const shownVersion = computed(() => report.value?.package?.release_version || version.value)

const loading = ref(false)
const error = ref<string | null>(null)
const report = ref<PackageReport | null>(null)
const row = ref<Package | null>(null)

const tab = ref<TabName>(TABS.find((t) => t === route.query.tab) ?? 'vulnerabilities')
watch(tab, (value) => void router.replace({ query: { ...route.query, tab: value === 'vulnerabilities' ? undefined : value } }))

const severityCounts = computed(() => report.value?.severity_counts ?? NO_VULNERABILITIES)
const configured = computed(() => system.info.value?.security.scanners ?? [])
const verdict = computed<Verdict>(() => report.value?.decision.verdict ?? 'unscanned')

const banner = computed(() => {
  if (!report.value) return null
  const sec = system.info.value?.security
  return verdictBanner(report.value, sec ? describePolicy(sec) : '', sec?.fail_closed ?? false)
})

const upstream = computed(() => system.info.value?.upstreams[registry.value] || 'Not reported')

// Idle eviction is the only expiry the server enforces on a cached package.
const expiry = computed(() => {
  const idle = system.info.value?.cache.idle_ttl
  if (idle === undefined) return 'Not reported'
  if (idle === 0) return 'Never. Idle eviction is off.'
  const last = row.value ? Date.parse(row.value.last_accessed) : Number.NaN
  const after = `Removed after ${formatDuration(idle)} without a request`
  return Number.isNaN(last) ? after : `${after}, on ${formatDate(new Date(last + idle * 1000).toISOString())} if unused`
})

async function load() {
  loading.value = true
  error.value = null
  report.value = null
  try {
    const encoded = `${registry.value}/${packageName.value}/${version.value}`
    const [details, list] = await Promise.all([
      axios.get<PackageReport>(`/api/packages/${encoded}/vulnerabilities`),
      axios
        .get<{ packages: Package[] }>(`/api/packages?registry=${encodeURIComponent(registry.value)}&q=${encodeURIComponent(packageName.value)}`)
        .catch(() => null),
      system.load(),
    ])
    report.value = details.data
    row.value = list?.data.packages?.find((p) => p.name === packageName.value && p.version === version.value) ?? null
  } catch (err: unknown) {
    const e = err as { response?: { data?: { error?: string } }; message?: string }
    error.value = e.response?.data?.error || e.message || 'Failed to load package details'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
