<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Statistics" description="Storage, traffic and scan results across every registry." />

    <ErrorState
      v-if="error"
      variant="card"
      title="Could not load statistics"
      :message="error"
      @retry="refresh"
    />

    <LoadingState v-if="loading" variant="kpi-grid" :columns="3" label="Loading statistics..." />

    <template v-else>
      <Card>
        <CardHeader>
          <CardTitle as="h2">Overall statistics</CardTitle>
        </CardHeader>
        <CardContent>
          <StatGroup :columns="3" aria-label="Overall statistics">
            <KpiTile label="Total packages" :value="stats?.total_packages || 0" :icon="faBoxesStacked" />
            <KpiTile
              label="Storage used"
              :value="`${formatBytes(stats?.total_size || 0)} / ${formatBytes(stats?.max_cache_size || 0)}`"
              :hint="`${storagePercentage.toFixed(1)}% used`"
              :progress="storagePercentage"
              :tone="storageTone"
              :icon="faHardDrive"
            />
            <KpiTile label="Total downloads" :value="stats?.total_downloads || 0" :icon="faDownload" />
          </StatGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle as="h2">Security scanning</CardTitle>
        </CardHeader>
        <CardContent>
          <StatGroup :columns="3" aria-label="Security scanning">
            <KpiTile label="Scanned packages" :value="stats?.scanned_packages || 0" :icon="faCircleCheck" />
            <KpiTile
              as="button"
              type="button"
              variant="interactive"
              label="Vulnerable packages"
              :value="stats?.vulnerable_packages || 0"
              :hint="(stats?.vulnerable_packages || 0) > 0 ? 'View the list' : undefined"
              :icon="faTriangleExclamation"
              :disabled="(stats?.vulnerable_packages || 0) === 0"
              @click="showVulnerablePackages"
            />
            <KpiTile
              as="button"
              type="button"
              variant="interactive"
              label="Blocked packages"
              :value="stats?.blocked_packages || 0"
              :hint="(stats?.blocked_packages || 0) > 0 ? 'View the list' : undefined"
              :icon="faBan"
              :disabled="(stats?.blocked_packages || 0) === 0"
              @click="showBlockedPackages"
            />
          </StatGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle as="h2">Registry breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            label="Registry breakdown"
            layout="cards"
            row-key="name"
            empty-text="No registries reported"
            :columns="registryColumns"
            :rows="registries"
          />
        </CardContent>
      </Card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { useRouter } from 'vue-router'
import { usePackageStore } from '../stores/packages'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  DataTable,
  ErrorState,
  KpiTile,
  LoadingState,
  PageHeader,
  StatGroup,
  type DataTableColumn,
} from '@perfect-design/ui'
import { formatBytes, formatNumber } from '@/lib/format'
import { faBan, faDownload, faHardDrive, faBoxesStacked, faCircleCheck, faTriangleExclamation } from '@/lib/icons'

const store = usePackageStore()
const { stats, loading, error } = storeToRefs(store)
const router = useRouter()

onMounted(async () => {
  await store.fetchStats()
})

function showVulnerablePackages() {
  if ((stats.value?.vulnerable_packages || 0) === 0) {
    return
  }

  router.push('/vulnerable-packages')
}

function showBlockedPackages() {
  if ((stats.value?.blocked_packages || 0) === 0) {
    return
  }

  router.push('/blocked-packages')
}

const REGISTRY_LABELS: Record<string, string> = {
  npm: 'npm',
  pypi: 'PyPI',
  go: 'Go modules',
}

interface RegistryRow {
  name: string
  label: string
  packages: number
  size: string
  downloads: number
}

const registryColumns: DataTableColumn<RegistryRow>[] = [
  { key: 'label', header: 'Registry', rowHeader: true },
  { key: 'packages', header: 'Packages', numeric: true, accessor: (r) => formatNumber(r.packages) },
  { key: 'size', header: 'Size', numeric: true },
  { key: 'downloads', header: 'Downloads', numeric: true, accessor: (r) => formatNumber(r.downloads) },
]

const registries = computed(() => {
  const apiRegistries = store.registries || {}
  return Object.entries(apiRegistries).map(([name, data]: [string, any]): RegistryRow => ({
    name,
    label: REGISTRY_LABELS[name] ?? name.toUpperCase(),
    packages: data.count || 0,
    size: formatBytes(data.size || 0),
    downloads: data.downloads || 0,
  }))
})

const storagePercentage = computed(() => {
  const totalSize = stats.value?.total_size || 0
  const maxSize = stats.value?.max_cache_size || 1
  return (totalSize / maxSize) * 100
})

const storageTone = computed(() => {
  if (storagePercentage.value >= 90) return 'danger'
  if (storagePercentage.value >= 50) return 'warning'
  return 'success'
})

function refresh() {
  void store.fetchStats()
}
</script>
