<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { SidebarNav, type SidebarNavGroup } from '@perfect-design/ui'
import {
  faBoxesStacked,
  faChartColumn,
  faChartPie,
  faGear,
  faShieldHalved,
  faTriangleExclamation,
} from '@/lib/icons'

// The sidebar slot of AppShell hides itself below md and the header's mobile slot only shows below md,
// so each placement renders one nav and the two never compete for the same viewport.
defineProps<{ readonly sheet?: boolean }>()

const GROUPS: SidebarNavGroup[] = [
  {
    items: [
      { label: 'Overview', to: '/', icon: faChartPie },
      { label: 'Packages', to: '/packages', icon: faBoxesStacked },
      { label: 'Security', to: '/security', icon: faTriangleExclamation },
      { label: 'Insights', to: '/stats', icon: faChartColumn },
    ],
  },
  {
    label: 'Admin',
    items: [
      { label: 'Bypasses', to: '/admin/bypasses', icon: faShieldHalved },
      { label: 'System', to: '/admin/system', icon: faGear },
    ],
  },
]

const SECTION_PREFIXES: ReadonlyArray<readonly [string, string]> = [
  ['/packages', '/packages'],
  ['/package/', '/packages'],
  ['/security', '/security'],
  ['/vulnerable-packages', '/security'],
  ['/blocked-packages', '/security'],
  ['/admin/bypasses', '/admin/bypasses'],
  ['/admin/system', '/admin/system'],
  ['/stats', '/stats'],
]

const route = useRoute()
const current = computed(() => SECTION_PREFIXES.find(([prefix]) => route.path.startsWith(prefix))?.[1] ?? '/')
</script>

<template>
  <SidebarNav
    :groups="GROUPS"
    :current="current"
    :link-as="RouterLink"
    :label="sheet ? 'Sections menu' : 'Sections'"
    class="w-full p-3"
  />
</template>
