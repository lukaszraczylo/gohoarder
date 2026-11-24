<template>
  <div class="flex flex-col gap-3">
    <p class="m-0 text-sm text-muted-foreground">
      Each scanner reports its own findings before they are merged. A finding several scanners agree on counts once in the verdict.
    </p>
    <DataTable label="Findings by scanner and severity" layout="cards" density="compact" row-key="name" :columns="columns" :rows="rows">
      <template #cell-name="{ row }"><span class="font-medium">{{ row.name }}</span></template>
      <template #cell-status="{ row }">
        <span class="flex flex-wrap items-center gap-2">
          <StatusBadge :status="row.status" :label="INSPECTOR_STATUS_LABELS[row.status]" :tones="STATUS_TONES" />
          <StatusBadge v-if="row.health === 'down'" status="down" label="Unavailable now" :tones="{ down: 'danger' }" />
        </span>
      </template>
      <template #cell-version="{ row }">{{ row.version ? `v${row.version}` : 'Not reported' }}</template>
    </DataTable>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { DataTable, StatusBadge, type DataTableColumn } from '@perfect-design/ui'
import { INSPECTOR_STATUS_LABELS, inspectorRows, type InspectorRow, type ScannerResult } from '@/lib/inspectors'
import type { ScannerInfo } from '@/lib/system'

const props = defineProps<{
  registry: string
  results: readonly ScannerResult[]
  configured: readonly ScannerInfo[]
}>()

const STATUS_TONES = { reported: 'success', 'no-result': 'warning', 'not-applicable': 'neutral', off: 'neutral' } as const

const rows = computed(() => inspectorRows(props.registry, props.results, props.configured))

function count(row: InspectorRow, level: 'critical' | 'high' | 'moderate' | 'low'): string {
  return row.counts ? String(row.counts[level]) : '–'
}

const columns: DataTableColumn<InspectorRow>[] = [
  { key: 'name', header: 'Scanner', rowHeader: true },
  { key: 'critical', header: 'Critical', numeric: true, accessor: (r) => count(r, 'critical') },
  { key: 'high', header: 'High', numeric: true, accessor: (r) => count(r, 'high') },
  { key: 'moderate', header: 'Moderate', numeric: true, accessor: (r) => count(r, 'moderate') },
  { key: 'low', header: 'Low', numeric: true, accessor: (r) => count(r, 'low') },
  { key: 'status', header: 'Status' },
  { key: 'version', header: 'Version' },
]
</script>
