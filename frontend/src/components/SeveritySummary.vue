<template>
  <StatGroup :columns="4" :aria-label="label">
    <KpiTile v-for="level in SEVERITY_LEVELS" :key="level" :label="formatSeverityName(level)" :value="counts[level]">
      <template #icon><StatusDot :tone="SEVERITY_TONES[level]" /></template>
    </KpiTile>
  </StatGroup>
</template>

<script setup lang="ts">
import { KpiTile, StatGroup, StatusDot } from '@perfect-design/ui'
import type { VulnerabilityCounts } from '../stores/packages'
import { SEVERITY_LEVELS, SEVERITY_TONES, formatSeverityName } from '@/lib/severity'

defineProps<{
  counts: VulnerabilityCounts
  label: string
}>()
</script>
