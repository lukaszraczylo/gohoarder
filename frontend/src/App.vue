<script setup lang="ts">
import { onMounted } from 'vue'
import { RouterView } from 'vue-router'
import { AppHeader, AppShell, Icon, ThemeToggle, Toaster, useThemeStore } from '@perfect-design/ui'
import AppNav from '@/components/shell/AppNav.vue'
import { faBoxOpen } from '@/lib/icons'

// init() installs the watcher that applies and persists the choice; the style is set after it so a stored value cannot override the pack.
onMounted(() => {
  const theme = useThemeStore()
  theme.init()
  theme.setStyle('workbench')
})
</script>

<template>
  <div class="flex min-h-dvh flex-col">
    <!-- Rendered here, not by AppShell: the header sits above the shell, and the skip link must be the first tab stop. -->
    <a
      href="#main-content"
      class="sr-only focus:not-sr-only focus:absolute focus:start-2 focus:top-2 focus:z-(--z-toast) focus:rounded-md focus:bg-primary focus:px-3 focus:py-2 focus:text-sm focus:text-primary-foreground"
      >Skip to main content</a
    >
    <!-- px-6 on the bar equals the sidebar nav's p-3 plus the link's px-3, so the brand icon sits over the nav icons. -->
    <!-- AppShell wraps its #header slot in its own <header> and AppHeader renders one too; outside the shell there is one banner. -->
    <AppHeader sticky mobile-variant="sheet" class="[&>div]:h-(--header-h) [&>div]:px-6">
      <template #brand>
        <Icon :icon="faBoxOpen" size="lg" class="text-primary" />
        <p class="m-0 text-lg font-semibold">GoHoarder</p>
        <p class="m-0 hidden text-sm text-muted-foreground sm:block">Package cache manager</p>
      </template>
      <template #actions><ThemeToggle /></template>
      <template #mobile><AppNav sheet /></template>
    </AppHeader>

    <!-- The aside scrolls itself, so only the aside can stick; both offsets come from --header-h. -->
    <AppShell
      :skip-link="false"
      drawer-breakpoint="md"
      sidebar-label="Sections"
      content-max-width="7xl"
      class="flex-1 md:[&_[data-slot=app-shell-sidebar]]:sticky md:[&_[data-slot=app-shell-sidebar]]:top-(--header-h) md:[&_[data-slot=app-shell-sidebar]]:h-[calc(100dvh-var(--header-h))] md:[&_[data-slot=app-shell-sidebar]]:self-start"
    >
      <template #sidebar><AppNav /></template>
      <div class="py-6"><RouterView /></div>
    </AppShell>

    <Toaster />
  </div>
</template>
