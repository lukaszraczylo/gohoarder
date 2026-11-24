<template>
  <Card class="min-w-0" data-testid="cache-capacity">
    <CardHeader>
      <CardTitle as="h2">Cache capacity</CardTitle>
      <CardDescription>Disk the cache holds, by registry.</CardDescription>
    </CardHeader>
    <CardContent class="flex flex-col gap-6">
      <StatBar
        v-if="maxSize > 0"
        label="Used"
        tone="auto"
        :value="used"
        :max="maxSize"
        :value-text="`${formatBytes(used)} of ${formatBytes(maxSize)}`"
      />
      <p v-else class="m-0 text-sm text-muted-foreground">
        <span class="font-medium text-foreground">{{ formatBytes(used) }}</span> used. No size limit is set.
      </p>

      <EmptyState v-if="rows.length === 0" size="sm" title="Nothing cached" description="Each registry appears here after its first download." />
      <template v-else>
        <DonutChart
          :data="donut"
          :value-formatter="formatBytes"
          center-text="cached"
          label="Cache size by registry"
          layout="stacked"
          size="md"
        />
        <DataTable label="Cache by registry" layout="cards" density="compact" :columns="columns" :rows="rows" row-key="registry">
          <template #cell-registry="{ row }"><Badge variant="outline">{{ row.registry }}</Badge></template>
        </DataTable>
      </template>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import {
  Badge,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  DataTable,
  DonutChart,
  EmptyState,
  StatBar,
  type DataTableColumn,
  type DonutDatum,
} from '@perfect-design/ui'
import { formatBytes, formatNumber } from '@/lib/format'

export interface RegistryUsage {
  registry: string
  count: number
  size: number
  downloads: number
}

const props = defineProps<{
  used: number
  maxSize: number
  registries: Record<string, { count?: number; size?: number; downloads?: number }>
}>()

const rows = computed<RegistryUsage[]>(() =>
  Object.entries(props.registries)
    .map(([registry, r]) => ({ registry, count: r.count ?? 0, size: r.size ?? 0, downloads: r.downloads ?? 0 }))
    .sort((a, b) => b.size - a.size),
)
// chart-1 and chart-2 are neighbouring teals in this theme, so each registry gets a distinct hue.
const REGISTRY_TONES: Record<string, DonutDatum['tone']> = { npm: 'info', go: 'primary', pypi: 'warning' }
const SPARE_TONES: DonutDatum['tone'][] = ['danger', 'success', 'muted']
const donut = computed<DonutDatum[]>(() =>
  rows.value.map((r, i) => ({ label: r.registry, value: r.size, tone: REGISTRY_TONES[r.registry] ?? SPARE_TONES[i % SPARE_TONES.length] })),
)

const columns: DataTableColumn<RegistryUsage>[] = [
  { key: 'registry', header: 'Registry', rowHeader: true },
  { key: 'count', header: 'Packages', numeric: true, accessor: (r) => formatNumber(r.count) },
  { key: 'size', header: 'Size', numeric: true, accessor: (r) => formatBytes(r.size) },
]
</script>
