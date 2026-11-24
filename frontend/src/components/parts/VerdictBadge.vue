<template>
  <StatusBadge :status="verdict" :label="VERDICT_LABELS[verdict]" :tones="TONES" :title="VERDICT_MEANINGS[verdict]" />
</template>

<script setup lang="ts">
import { StatusBadge } from '@perfect-design/ui'
import { VERDICT_LABELS, VERDICT_MEANINGS, VERDICT_TONES, type Verdict } from '@/lib/verdict'

defineProps<{ verdict: Verdict }>()

const TONES = VERDICT_TONES
</script>
