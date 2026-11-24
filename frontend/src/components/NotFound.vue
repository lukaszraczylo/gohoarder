<template>
  <div class="flex flex-col gap-6">
    <PageHeader title="Page not found" />
    <EmptyState
      title-as="h2"
      size="lg"
      :icon="faMagnifyingGlass"
      title="No page at this address"
      :description="`Nothing lives at ${route.path}.`"
    >
      <template #action>
        <Button as-child>
          <RouterLink to="/">Back to the overview</RouterLink>
        </Button>
      </template>
    </EmptyState>
  </div>
</template>

<script setup lang="ts">
import { RouterLink, useRoute } from 'vue-router'
import { Button, EmptyState, PageHeader } from '@perfect-design/ui'
import { faMagnifyingGlass } from '@/lib/icons'

const route = useRoute()
</script>
