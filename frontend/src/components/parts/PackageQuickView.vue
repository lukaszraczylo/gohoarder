<template>
  <Sheet :open="pkg !== null" @update:open="(open: boolean) => !open && emit('close')">
    <SheetContent side="right" size="md">
      <template v-if="pkg">
        <SheetHeader>
          <SheetTitle class="break-words">{{ pkg.name }}</SheetTitle>
          <SheetDescription>{{ withVersionPrefix(displayVersion(pkg)) }} from {{ pkg.registry }}</SheetDescription>
        </SheetHeader>

        <div class="flex flex-col gap-5 px-4 pb-4">
          <div class="flex flex-col gap-2">
            <VerdictBadge :verdict="verdict" class="self-start" />
            <p v-if="explanation" class="m-0 text-sm text-muted-foreground" data-testid="quick-view-reason">{{ explanation }}</p>
          </div>

          <SeveritySummary v-if="pkg.vulnerabilities?.counts" class="grid-cols-2! lg:grid-cols-2!" :counts="pkg.vulnerabilities.counts" label="Findings by severity" />

          <DescriptionList :columns="1" divided>
            <DescriptionItem term="Size">{{ formatBytes(pkg.size) }}</DescriptionItem>
            <DescriptionItem term="Downloads">{{ formatNumber(pkg.download_count) }}</DescriptionItem>
            <DescriptionItem term="Cached"><RelativeTime :datetime="pkg.cached_at" /></DescriptionItem>
            <DescriptionItem term="Last accessed"><RelativeTime :datetime="pkg.last_accessed" /></DescriptionItem>
            <DescriptionItem term="Last scanned">
              <RelativeTime v-if="pkg.vulnerabilities?.scannedAt" :datetime="pkg.vulnerabilities.scannedAt" />
              <template v-else>Never</template>
            </DescriptionItem>
          </DescriptionList>
        </div>

        <SheetFooter>
          <Button :as="RouterLink" :to="packageRoute(pkg)" :icon-end="faArrowRight">Open full page</Button>
          <Button variant="outline" :icon-start="faTrash" @click="emit('delete', pkg)">Remove from cache</Button>
        </SheetFooter>
      </template>
    </SheetContent>
  </Sheet>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import {
  Button,
  DescriptionItem,
  DescriptionList,
  RelativeTime,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@perfect-design/ui'
import SeveritySummary from '../SeveritySummary.vue'
import VerdictBadge from './VerdictBadge.vue'
import type { Package } from '@/stores/packages'
import { displayVersion, formatBytes, formatNumber, withVersionPrefix } from '@/lib/format'
import { packageRoute } from '@/lib/packages'
import { faArrowRight, faTrash } from '@/lib/icons'
import { VERDICT_MEANINGS, verdictOf } from '@/lib/verdict'

const props = defineProps<{ pkg: Package | null }>()
const emit = defineEmits<{ close: []; delete: [pkg: Package] }>()

const verdict = computed(() => (props.pkg ? verdictOf(props.pkg) : 'unscanned'))
const explanation = computed(() => props.pkg?.vulnerabilities?.reason || VERDICT_MEANINGS[verdict.value])
</script>
