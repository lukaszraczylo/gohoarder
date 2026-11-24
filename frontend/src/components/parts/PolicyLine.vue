<template>
  <p class="m-0 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground" data-testid="policy-line">
    <template v-if="info">
      <span class="font-medium text-foreground">Policy</span>
      <span>{{ describePolicy(info.security) }}</span>
      <span v-if="info.security.enabled">{{ info.security.fail_closed ? 'Fail-closed' : 'Fail-open on scanner outage' }}.</span>
      <span v-if="info.security.enabled">{{ enabledScanners }} of {{ info.security.scanners.length }} scanners on.</span>
      <Link :as="RouterLink" to="/admin/system">System settings</Link>
    </template>
    <span v-else-if="error">Policy unavailable: {{ error }}</span>
    <span v-else>Loading policy...</span>
  </p>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterLink } from 'vue-router'
import { Link } from '@perfect-design/ui'
import { describePolicy, useSystem } from '@/lib/system'

const { info, error, load } = useSystem()
const enabledScanners = computed(() => info.value?.security.scanners.filter((s) => s.enabled).length ?? 0)

onMounted(() => void load())
</script>
