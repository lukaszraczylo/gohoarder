<template>
  <div class="flex flex-col gap-6">
    <section v-if="applied" class="flex flex-col gap-3" aria-labelledby="bypass-applied-heading">
      <h3 id="bypass-applied-heading" class="m-0 text-sm font-semibold">Bypass in effect</h3>
      <DescriptionList :columns="2" divided data-testid="applied-bypass">
        <DescriptionItem term="Scope">{{ applied.type === 'package' ? 'Whole package' : 'One advisory' }}</DescriptionItem>
        <DescriptionItem term="Target"><InlineCode>{{ applied.target }}</InlineCode></DescriptionItem>
        <DescriptionItem term="Reason">{{ applied.reason }}</DescriptionItem>
        <DescriptionItem term="Created by">{{ applied.created_by }}</DescriptionItem>
        <DescriptionItem term="Created"><RelativeTime :datetime="applied.created_at" /></DescriptionItem>
        <DescriptionItem term="Expires">{{ formatDate(applied.expires_at) }}</DescriptionItem>
      </DescriptionList>
    </section>
    <p v-else class="m-0 text-sm text-muted-foreground">No bypass applies to this package.</p>

    <section class="flex flex-col gap-3" aria-labelledby="bypass-list-heading">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h3 id="bypass-list-heading" class="m-0 text-sm font-semibold">Bypasses that cover this package</h3>
        <Button :as="RouterLink" :to="addRoute" variant="outline" size="sm" :icon-start="faPlus">Add a bypass</Button>
      </div>
      <Callout v-if="!adminKey.key.value" type="note" size="sm" title="Admin key needed">
        Listing bypasses needs the admin API key. Enter it on the
        <Link :as="RouterLink" to="/admin/bypasses">Bypasses page</Link>.
      </Callout>
      <LoadingState v-else-if="loading" layout="inline" label="Loading bypasses..." />
      <ErrorState v-else-if="error" variant="inline" title="Could not load bypasses" :message="error" @retry="load" />
      <EmptyState v-else-if="covering.length === 0" size="sm" title="No bypass covers this package" description="Add one to serve it despite the findings." />
      <DataTable v-else label="Bypasses covering this package" layout="cards" density="compact" :columns="columns" :rows="covering">
        <template #cell-status="{ row }">
          <StatusBadge :status="statusOf(row)" :label="STATUS_LABELS[statusOf(row)]" :tones="STATUS_TONES" />
        </template>
        <template #cell-target="{ row }"><InlineCode>{{ row.target }}</InlineCode></template>
      </DataTable>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import axios from 'axios'
import { RouterLink } from 'vue-router'
import {
  Button,
  Callout,
  DataTable,
  DescriptionItem,
  DescriptionList,
  EmptyState,
  ErrorState,
  InlineCode,
  Link,
  LoadingState,
  RelativeTime,
  StatusBadge,
  type DataTableColumn,
} from '@perfect-design/ui'
import { useAdminKey } from '@/lib/adminKey'
import { bypassesFor, isExpired, type Bypass } from '@/lib/bypass'
import { formatDate } from '@/lib/format'
import { faPlus } from '@/lib/icons'
import type { AppliedBypass } from '@/stores/packages'

const props = defineProps<{
  applied: AppliedBypass | null
  registry: string
  name: string
  version: string
  releaseVersion?: string
}>()

const adminKey = useAdminKey()
const all = ref<Bypass[]>([])
const loading = ref(false)
const error = ref<string | null>(null)

type BypassStatus = 'active' | 'expired' | 'inactive'
const STATUS_LABELS: Record<BypassStatus, string> = { active: 'Active', expired: 'Expired', inactive: 'Inactive' }
const STATUS_TONES = { active: 'success', expired: 'neutral', inactive: 'neutral' } as const

function statusOf(b: Bypass): BypassStatus {
  if (isExpired(b.expires_at)) return 'expired'
  return b.active ? 'active' : 'inactive'
}

const covering = computed(() =>
  bypassesFor(all.value, { registry: props.registry, name: props.name, version: props.version, releaseVersion: props.releaseVersion }),
)

const addRoute = computed(() => ({
  path: '/admin/bypasses',
  query: { type: 'package', target: `${props.registry}/${props.name}@${props.releaseVersion || props.version}` },
}))

const columns: DataTableColumn<Bypass>[] = [
  { key: 'target', header: 'Target', rowHeader: true },
  { key: 'type', header: 'Type' },
  { key: 'status', header: 'Status', accessor: (b) => statusOf(b) },
  { key: 'reason', header: 'Reason' },
  { key: 'created_by', header: 'Created by' },
  { key: 'expires_at', header: 'Expires', accessor: (b) => formatDate(b.expires_at) },
]

async function load() {
  if (!adminKey.key.value) return
  loading.value = true
  error.value = null
  try {
    const response = await axios.get<{ bypasses: Bypass[] }>('/api/admin/bypasses?include_expired=true', { headers: adminKey.headers.value })
    all.value = response.data.bypasses ?? []
  } catch (err) {
    const status = (err as { response?: { status?: number } }).response?.status
    error.value = status === 401 || status === 403 ? 'The admin key was refused.' : err instanceof Error ? err.message : 'Failed to load bypasses'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
