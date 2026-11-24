<template>
  <Card data-testid="scanner-health">
    <CardHeader>
      <CardTitle as="h2">Inspectors</CardTitle>
      <CardDescription>The scanners that examine each package. Health is probed every 30 seconds.</CardDescription>
    </CardHeader>
    <CardContent>
      <ErrorState v-if="error && !info" variant="inline" title="Could not load scanners" :message="error" @retry="load(true)" />
      <LoadingState v-else-if="!info" layout="inline" label="Loading scanners..." />
      <EmptyState
        v-else-if="!info.security.enabled"
        size="sm"
        title="Scanning is off"
        description="Packages are served without inspection."
      />
      <ul v-else class="m-0 grid list-none grid-cols-1 gap-2 p-0 sm:grid-cols-2 xl:grid-cols-3">
        <li
          v-for="scanner in info.security.scanners"
          :key="scanner.name"
          class="flex items-center justify-between gap-3 rounded-md border px-3 py-2"
          :data-scanner="scanner.name"
        >
          <span class="min-w-0">
            <span class="block truncate text-sm font-medium">{{ scanner.name }}</span>
            <span class="block text-xs text-muted-foreground">{{ scanner.version ? `v${scanner.version}` : 'version not reported' }}</span>
          </span>
          <StatusBadge :status="scannerState(scanner)" :label="STATE_LABELS[scannerState(scanner)]" :tones="STATE_TONES" />
        </li>
      </ul>
    </CardContent>
  </Card>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  EmptyState,
  ErrorState,
  LoadingState,
  StatusBadge,
} from '@perfect-design/ui'
import { scannerState, useSystem } from '@/lib/system'

const { info, error, load } = useSystem()

const STATE_LABELS = { healthy: 'Healthy', down: 'Unavailable', off: 'Off' }
const STATE_TONES = { healthy: 'success', down: 'danger', off: 'neutral' } as const

onMounted(() => void load())
</script>
