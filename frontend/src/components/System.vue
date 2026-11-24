<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="System" description="The policy the proxy applies, the scanners behind it, and the settings that shape the cache.">
      <template #actions>
        <Badge v-if="info" variant="outline" class="font-mono" data-testid="build-version">{{ info.version }}</Badge>
        <Button variant="outline" :icon-start="faRotateRight" @click="load(true)">Refresh</Button>
      </template>
    </PageHeader>

    <LoadingState v-if="!info && !error" variant="card" label="Loading system settings..." />
    <ErrorState v-else-if="!info" variant="card" title="Could not load system settings" :message="error ?? ''" @retry="load(true)" />

    <template v-else>
      <div class="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle as="h2">Policy</CardTitle>
            <CardDescription>What clears a package and what holds it.</CardDescription>
          </CardHeader>
          <CardContent>
            <DescriptionList :columns="1" divided data-testid="policy-list">
              <DescriptionItem term="Scanning">
                <StatusBadge :status="info.security.enabled ? 'on' : 'off'" :label="info.security.enabled ? 'On' : 'Off'" :tones="{ on: 'success', off: 'neutral' }" />
              </DescriptionItem>
              <DescriptionItem term="Block policy">{{ describePolicy(info.security) }}</DescriptionItem>
              <DescriptionItem term="When a scan fails">
                {{ info.security.fail_closed ? 'Fail-closed. The package is held.' : 'Fail-open on scanner outage. The package is served and the scan retried.' }}
              </DescriptionItem>
              <DescriptionItem term="Scan on download">{{ info.security.scan_on_download ? 'Yes' : 'No' }}</DescriptionItem>
              <DescriptionItem term="First download waits">up to {{ formatDuration(info.security.scan_wait_timeout) }} for its scan</DescriptionItem>
            </DescriptionList>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle as="h2">Rescans</CardTitle>
            <CardDescription>Cached packages are inspected again as advisories change.</CardDescription>
          </CardHeader>
          <CardContent>
            <DescriptionList :columns="1" divided data-testid="rescan-list">
              <DescriptionItem term="Interval">{{ duration(info.security.rescan.interval, 'Rescans are off') }}</DescriptionItem>
              <DescriptionItem term="Active window">{{ duration(info.security.rescan.active_window, 'Every cached package') }}</DescriptionItem>
              <DescriptionItem term="Parallel scans">{{ info.security.rescan.concurrency }}</DescriptionItem>
              <DescriptionItem term="Rescan on access">{{ info.security.rescan.on_access ? 'Yes. A stale hit is rescanned before it is served.' : 'No' }}</DescriptionItem>
            </DescriptionList>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle as="h2">Inspectors</CardTitle>
          <CardDescription>Health is probed at most every 30 seconds. A scanner that is off is not probed.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable label="Scanners" layout="cards" density="compact" row-key="name" :columns="scannerColumns" :rows="info.security.scanners">
            <template #cell-name="{ row }"><span class="font-medium">{{ row.name }}</span></template>
            <template #cell-state="{ row }">
              <StatusBadge :status="scannerState(row)" :label="STATE_LABELS[scannerState(row)]" :tones="STATE_TONES" />
            </template>
            <template #cell-version="{ row }">{{ scannerVersion(row) || 'Not applicable' }}</template>
          </DataTable>
        </CardContent>
      </Card>

      <div class="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle as="h2">Cache</CardTitle>
            <CardDescription>Limits and where packages come from.</CardDescription>
          </CardHeader>
          <CardContent>
            <DescriptionList :columns="1" divided data-testid="cache-list">
              <DescriptionItem term="Size limit">{{ info.cache.max_size > 0 ? formatBytes(info.cache.max_size) : 'None' }}</DescriptionItem>
              <DescriptionItem term="Idle eviction">{{ duration(info.cache.idle_ttl, 'Off', 'Removed after ', ' without a request') }}</DescriptionItem>
              <DescriptionItem term="Default TTL">{{ duration(info.cache.default_ttl, 'None') }}</DescriptionItem>
              <DescriptionItem v-for="(host, registry) in info.upstreams" :key="registry" :term="`Upstream ${registry}`">{{ host || 'Not set' }}</DescriptionItem>
            </DescriptionList>
          </CardContent>
        </Card>

        <Card data-testid="prewarming">
          <CardHeader>
            <CardTitle as="h2">Pre-warming</CardTitle>
            <CardDescription>Fetches the most requested packages ahead of clients.</CardDescription>
          </CardHeader>
          <CardContent class="flex flex-col gap-4">
            <DescriptionList :columns="1" divided>
              <DescriptionItem term="Status">
                <StatusBadge :status="info.prewarming.enabled ? 'on' : 'off'" :label="info.prewarming.enabled ? 'On' : 'Off'" :tones="{ on: 'success', off: 'neutral' }" />
              </DescriptionItem>
              <DescriptionItem term="Interval">{{ duration(info.prewarming.interval, 'None') }}</DescriptionItem>
              <DescriptionItem term="Top packages">{{ info.prewarming.top_packages }}</DescriptionItem>
            </DescriptionList>
            <div class="flex flex-col gap-2 sm:flex-row sm:items-center">
              <Button :icon-start="faRotateRight" :loading="triggering" :disabled="!info.prewarming.enabled" @click="trigger">Run a cycle now</Button>
              <p class="m-0 text-sm text-muted-foreground">
                {{ info.prewarming.enabled ? 'Needs the admin API key.' : 'Pre-warming is off in the configuration.' }}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </template>

    <AdminKeyDialog v-model:open="showKeyDialog" description="Enter your admin API key to start a pre-warming cycle." @saved="trigger" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import axios from 'axios'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataTable,
  DescriptionItem,
  DescriptionList,
  ErrorState,
  LoadingState,
  PageHeader,
  StatusBadge,
  useToastStore,
  type DataTableColumn,
} from '@perfect-design/ui'
import AdminKeyDialog from './parts/AdminKeyDialog.vue'
import { useAdminKey } from '@/lib/adminKey'
import { formatBytes, formatDuration } from '@/lib/format'
import { faRotateRight } from '@/lib/icons'
import { describePolicy, scannerState, scannerVersion, useSystem, type ScannerInfo } from '@/lib/system'

const { info, error, load } = useSystem()
const adminKey = useAdminKey()
const toasts = useToastStore()

const triggering = ref(false)
const showKeyDialog = ref(false)

const STATE_LABELS = { healthy: 'Healthy', down: 'Unavailable', off: 'Off' }
const STATE_TONES = { healthy: 'success', down: 'danger', off: 'neutral' } as const

const scannerColumns: DataTableColumn<ScannerInfo>[] = [
  { key: 'name', header: 'Scanner', rowHeader: true },
  { key: 'state', header: 'State', accessor: (s) => scannerState(s) },
  { key: 'version', header: 'Version' },
]

/** Seconds as words; zero means the feature is off, so `zero` explains that. */
function duration(seconds: number, zero: string, before = '', after = ''): string {
  return seconds === 0 ? zero : `${before}${formatDuration(seconds)}${after}`
}

async function trigger() {
  adminKey.load()
  if (!adminKey.key.value) {
    showKeyDialog.value = true
    return
  }
  triggering.value = true
  try {
    await axios.post('/api/admin/prewarming/trigger', null, { headers: adminKey.headers.value })
    toasts.success('Pre-warming started', 'The cycle runs in the background.')
  } catch (err) {
    const status = (err as { response?: { status?: number } }).response?.status
    if (status === 401 || status === 403) {
      adminKey.clear()
      toasts.error('Admin key refused', 'Enter a key with the admin role.')
    } else {
      toasts.error('Could not start pre-warming', err instanceof Error ? err.message : 'Request failed')
    }
  } finally {
    triggering.value = false
  }
}

onMounted(() => void load(true))
</script>
