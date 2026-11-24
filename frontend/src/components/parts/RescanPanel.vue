<template>
  <Card data-testid="rescan-panel">
    <CardHeader>
      <CardTitle as="h2">Rescan</CardTitle>
      <CardDescription>Scan cached packages again now, without waiting for the interval. Stored findings are refreshed with the current scanners.</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-4">
      <div class="flex flex-col gap-2 sm:flex-row sm:items-center">
        <Button :icon-start="faRotateRight" :loading="starting === 'vulnerable'" :disabled="blocked" data-testid="rescan-vulnerable" @click="start('vulnerable')">
          Rescan vulnerable packages
        </Button>
        <Button variant="outline" :icon-start="faRotateRight" :loading="starting === 'all'" :disabled="blocked" data-testid="rescan-all" @click="askAll">
          Rescan everything
        </Button>
      </div>
      <p class="m-0 text-sm text-muted-foreground" data-testid="rescan-note">{{ note }}</p>

      <div v-if="status && status.queued > 0" class="flex flex-col gap-2" data-testid="rescan-progress">
        <Progress :model-value="processed" :max="status.queued" label="Rescan progress" show-value />
        <p class="m-0 text-sm" data-testid="rescan-counts">
          {{ status.running ? 'Running.' : 'Finished.' }}
          {{ formatNumber(status.done) }} scanned, {{ formatNumber(status.failed) }} failed, of {{ formatNumber(status.queued) }} queued.
        </p>
      </div>
    </CardContent>

    <ConfirmDialog
      v-model:open="confirmOpen"
      title="Rescan every cached package?"
      :description="everythingWarning"
      confirm-label="Rescan everything"
      @confirm="start('all')"
    />
    <AdminKeyDialog v-model:open="showKeyDialog" description="Enter your admin API key to start a rescan." @saved="resume" />
  </Card>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import axios from 'axios'
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ConfirmDialog, Progress, useToastStore } from '@perfect-design/ui'
import AdminKeyDialog from './AdminKeyDialog.vue'
import { useAdminKey } from '@/lib/adminKey'
import { formatDuration, formatNumber } from '@/lib/format'
import { faRotateRight } from '@/lib/icons'

type Scope = 'vulnerable' | 'all'

/** Response of GET /api/admin/rescan/status. */
interface RescanStatus {
  enabled: boolean
  running: boolean
  scope: string
  queued: number
  done: number
  failed: number
}

const props = defineProps<{ enabled: boolean; concurrency: number }>()

const POLL_MS = 2000
// A guess: one scan of one artifact takes seconds, and the server does not report a measured rate.
const SECONDS_PER_ARTIFACT = 10

const adminKey = useAdminKey()
const toasts = useToastStore()

const status = ref<RescanStatus | null>(null)
const starting = ref<Scope | null>(null)
const confirmOpen = ref(false)
const showKeyDialog = ref(false)
const cachedArtifacts = ref<number | null>(null)
let pendingScope: Scope | null = null
let timer: ReturnType<typeof setTimeout> | undefined

const running = computed(() => status.value?.running === true)
const blocked = computed(() => !props.enabled || running.value || starting.value !== null)
const processed = computed(() => (status.value ? status.value.done + status.value.failed : 0))
const note = computed(() => {
  if (!props.enabled) return 'Security scanning is off in the configuration.'
  if (running.value) return 'A rescan is running. Another one can start when it finishes.'
  return 'Needs the admin API key. The rescan runs in the background.'
})
const everythingWarning = computed(() => {
  const base = 'This re-runs all scanners on every cached artifact.'
  const count = cachedArtifacts.value
  if (count === null) return `${base} It can take a long time and loads the scanners at ${props.concurrency} in parallel.`
  const seconds = Math.max(60, Math.ceil(((count * SECONDS_PER_ARTIFACT) / Math.max(props.concurrency, 1)) / 60) * 60)
  return `${base} For ${formatNumber(count)} artifacts, ${props.concurrency} at a time and about ${SECONDS_PER_ARTIFACT} seconds each, that takes roughly ${formatDuration(seconds)}.`
})

function errorStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } }).response?.status
}

async function refresh() {
  const res = await axios.get<RescanStatus>('/api/admin/rescan/status', { headers: adminKey.headers.value })
  status.value = res.data
  return res.data
}

function schedulePoll() {
  clearTimeout(timer)
  timer = setTimeout(async () => {
    try {
      if ((await refresh()).running) schedulePoll()
    } catch {
      // The next click shows the error; a failed poll must not toast every two seconds.
    }
  }, POLL_MS)
}

async function askAll() {
  confirmOpen.value = true
  try {
    const res = await axios.get<{ stats?: { total_packages?: number } }>('/api/stats')
    cachedArtifacts.value = res.data.stats?.total_packages ?? null
  } catch {
    cachedArtifacts.value = null
  }
}

async function start(scope: Scope) {
  adminKey.load()
  if (!adminKey.key.value) {
    pendingScope = scope
    showKeyDialog.value = true
    return
  }
  starting.value = scope
  try {
    const res = await axios.post<{ queued: number }>('/api/admin/rescan', { scope }, { headers: adminKey.headers.value })
    toasts.success('Rescan started', `${formatNumber(res.data.queued)} artifacts queued.`)
    await refresh()
    if (status.value?.running) schedulePoll()
  } catch (err) {
    const code = errorStatus(err)
    if (code === 409) {
      toasts.info('A rescan is already running', 'Wait for it to finish.')
      await refresh().then(schedulePoll, () => undefined)
    } else if (code === 401 || code === 403) {
      adminKey.clear()
      toasts.error('Admin key refused', 'Enter a key with the admin role.')
    } else {
      toasts.error('Could not start the rescan', err instanceof Error ? err.message : 'Request failed')
    }
  } finally {
    starting.value = null
  }
}

function resume() {
  const scope = pendingScope
  pendingScope = null
  if (scope) void start(scope)
}

onMounted(async () => {
  adminKey.load()
  if (!props.enabled || !adminKey.key.value) return
  try {
    if ((await refresh()).running) schedulePoll()
  } catch {
    // Progress is optional here; a stale or missing key surfaces when the admin starts a rescan.
  }
})

onUnmounted(() => clearTimeout(timer))
</script>
