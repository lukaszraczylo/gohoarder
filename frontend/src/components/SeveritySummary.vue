<template>
  <StatGroup :columns="4" :aria-label="label">
    <template v-if="selectable">
      <KpiTile
        v-for="level in SEVERITY_LEVELS"
        :key="level"
        as="button"
        type="button"
        variant="interactive"
        :label="formatSeverityName(level)"
        :value="counts[level]"
        :aria-pressed="isSelected(level)"
        :class="isSelected(level) && 'ring-2 ring-primary'"
        :data-severity="level"
        @click="toggle(level)"
      >
        <template #icon><StatusDot :tone="SEVERITY_TONES[level]" /></template>
        <template #hint>
          <span v-if="packageCounts">{{ formatPackageCount(packageCounts[level]) }}</span>
          <span v-if="isSelected(level)" class="font-medium text-foreground" data-testid="severity-filter-on">
            {{ packageCounts ? ' · ' : '' }}Filter on
          </span>
        </template>
      </KpiTile>
    </template>
    <template v-else>
      <KpiTile v-for="level in SEVERITY_LEVELS" :key="level" :label="formatSeverityName(level)" :value="counts[level]">
        <template #icon><StatusDot :tone="SEVERITY_TONES[level]" /></template>
      </KpiTile>
    </template>
  </StatGroup>
</template>

<script setup lang="ts">
import { KpiTile, StatGroup, StatusDot } from '@perfect-design/ui'
import type { VulnerabilityCounts } from '../stores/packages'
import { SEVERITY_LEVELS, SEVERITY_TONES, formatSeverityName, type SeverityLevel } from '@/lib/severity'

const props = defineProps<{
  counts: VulnerabilityCounts
  label: string
  /** Tiles become toggle buttons that edit `modelValue`. */
  selectable?: boolean
  /** Selected severities; several are allowed. */
  modelValue?: readonly SeverityLevel[]
  /** Packages per severity, shown on each tile in selectable mode. */
  packageCounts?: VulnerabilityCounts
}>()

const emit = defineEmits<{ 'update:modelValue': [value: SeverityLevel[]] }>()

function isSelected(level: SeverityLevel): boolean {
  return props.modelValue?.includes(level) ?? false
}

function toggle(level: SeverityLevel) {
  const current = props.modelValue ?? []
  const next = current.includes(level) ? current.filter((l) => l !== level) : [...current, level]
  emit('update:modelValue', SEVERITY_LEVELS.filter((l) => next.includes(l)))
}

function formatPackageCount(n: number): string {
  return `${n} package${n === 1 ? '' : 's'}`
}
</script>
