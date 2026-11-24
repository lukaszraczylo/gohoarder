<template>
  <Dialog :open="open" @update:open="(value: boolean) => emit('update:open', value)">
    <DialogContent size="sm">
      <DialogHeader>
        <DialogTitle>Admin API key</DialogTitle>
        <DialogDescription>{{ description }}</DialogDescription>
      </DialogHeader>
      <form class="flex flex-col gap-4" @submit.prevent="submit">
        <Field label="API key" required>
          <Input v-model="draft" type="password" autocomplete="off" />
        </Field>
        <DialogFooter>
          <Button variant="outline" @click="emit('update:open', false)">Cancel</Button>
          <Button type="submit" :disabled="draft.trim() === ''">Continue</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { Button, Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, Field, Input } from '@perfect-design/ui'
import { useAdminKey } from '@/lib/adminKey'

const props = defineProps<{ open: boolean; description: string }>()
const emit = defineEmits<{ 'update:open': [open: boolean]; saved: [] }>()

const adminKey = useAdminKey()
const draft = ref('')

watch(
  () => props.open,
  (open) => {
    if (open) draft.value = ''
  },
)

function submit() {
  const value = draft.value.trim()
  if (!value) return
  adminKey.save(value)
  emit('update:open', false)
  emit('saved')
}
</script>
