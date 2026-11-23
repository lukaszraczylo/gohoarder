<template>
  <div class="flex flex-col gap-6">
    <PageHeader
      title="CVE bypass management"
      description="Manage temporary security bypasses for packages and CVEs."
    >
      <template #actions>
        <Button :icon-start="faPlus" @click="showCreateModal = true">Create bypass</Button>
      </template>
    </PageHeader>

    <div class="flex flex-col gap-4 sm:flex-row sm:flex-wrap sm:items-center">
      <SegmentedControl v-model="activeFilter" :options="FILTER_OPTIONS" aria-label="Filter by status" />
      <SegmentedControl v-model="typeFilter" :options="TYPE_OPTIONS" aria-label="Filter by type" />
      <Button variant="outline" size="sm" :icon-start="faRotateRight" class="sm:ms-auto" @click="fetchBypasses">
        Refresh
      </Button>
    </div>

    <LoadingState v-if="loading" variant="table" label="Loading bypasses..." />

    <ErrorState
      v-else-if="error"
      variant="card"
      title="Could not load bypasses"
      :message="error"
      @retry="fetchBypasses"
    />

    <Card v-else>
      <CardContent>
        <EmptyState
          v-if="filteredBypasses.length === 0"
          :icon="faShieldHalved"
          title="No bypasses found"
          description="Create a bypass to allow packages with known vulnerabilities."
        />
        <DataTable
          v-else
          label="Bypasses"
          layout="cards"
          row-key="id"
          :columns="bypassColumns"
          :rows="filteredBypasses"
        >
          <template #cell-type="{ row }">
            <Badge :variant="row.type === 'cve' ? 'default' : 'outline'">{{ row.type === 'cve' ? 'CVE' : 'Package' }}</Badge>
          </template>
          <template #cell-status="{ row }">
            <span class="flex flex-wrap gap-1">
              <StatusBadge
                :status="row.active ? 'active' : 'inactive'"
                :tones="{ active: 'success', inactive: 'neutral' }"
              />
              <StatusBadge v-if="isExpired(row.expires_at)" status="expired" :tones="{ expired: 'danger' }" />
            </span>
          </template>
          <template #cell-actions="{ row }">
            <span class="flex gap-1">
              <IconButton :icon="faPen" :label="`Edit bypass for ${row.target}`" @click="editBypass(row)" />
              <IconButton :icon="faTrash" :label="`Delete bypass for ${row.target}`" @click="confirmDeleteBypass(row)" />
            </span>
          </template>
        </DataTable>
      </CardContent>
    </Card>

    <Dialog v-model:open="showCreateModal">
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{{ editingBypass ? 'Edit' : 'Create' }} bypass</DialogTitle>
          <DialogDescription>
            {{ editingBypass ? 'Update the bypass settings.' : 'Create a temporary bypass for a CVE or package.' }}
          </DialogDescription>
        </DialogHeader>

        <form class="flex flex-col gap-4" @submit.prevent="submitBypass">
          <Field v-if="!editingBypass" label="Bypass type">
            <SegmentedControl v-model="bypassForm.type" :options="BYPASS_TYPE_OPTIONS" full-width />
          </Field>

          <Field
            v-if="!editingBypass"
            :label="bypassForm.type === 'cve' ? 'CVE ID' : 'Package'"
            :hint="
              bypassForm.type === 'cve'
                ? 'Enter the CVE ID, for example CVE-2021-23337.'
                : 'Enter a package, for example npm/lodash@4.17.20, or npm/lodash for all versions. PyPI packages use the release version, for example pypi/six@1.17.0.'
            "
            required
          >
            <Input
              v-model="bypassForm.target"
              :placeholder="bypassForm.type === 'cve' ? 'CVE-2021-23337' : 'npm/lodash@4.17.20'"
            />
          </Field>

          <Field
            v-if="!editingBypass && bypassForm.type === 'cve'"
            label="Applies to (optional)"
            hint="Limit this CVE bypass to one package. Leave empty to apply it to every package with this CVE."
          >
            <Input v-model="bypassForm.applies_to" placeholder="npm/lodash@4.17.20" />
          </Field>

          <Field label="Reason" hint="Explain why this bypass is needed. It is kept for the audit trail." required>
            <Textarea v-model="bypassForm.reason" placeholder="No fix available, business critical dependency" />
          </Field>

          <Field v-if="!editingBypass" label="Created by" required>
            <Input v-model="bypassForm.created_by" placeholder="admin@example.com" />
          </Field>

          <Field
            label="Expires in (hours)"
            hint="Hours until this bypass expires. 168 is 7 days and 720 is 30 days."
            required
          >
            <Input
              :model-value="bypassForm.expires_in_hours"
              type="number"
              min="1"
              placeholder="168"
              @update:model-value="setExpiresInHours"
            />
          </Field>

          <Checkbox v-if="editingBypass" v-model="bypassForm.active" label="Active" />

          <Checkbox v-model="bypassForm.notify_on_expiry" label="Send a notification when the bypass expires" />

          <DialogFooter>
            <Button variant="outline" @click="closeCreateModal">Cancel</Button>
            <Button type="submit" :disabled="!isFormValid">{{ editingBypass ? 'Update' : 'Create' }} bypass</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <ConfirmDialog
      v-model:open="showDeleteModal"
      title="Delete bypass?"
      :description="`Delete the bypass for ${bypassToDelete?.target}? This cannot be undone and the security check is re-enabled immediately.`"
      confirm-label="Delete bypass"
      tone="danger"
      destructive
      @confirm="deleteBypass"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import axios from 'axios'
import {
  Badge,
  Button,
  Card,
  CardContent,
  Checkbox,
  ConfirmDialog,
  DataTable,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  EmptyState,
  ErrorState,
  Field,
  IconButton,
  Input,
  LoadingState,
  PageHeader,
  SegmentedControl,
  StatusBadge,
  Textarea,
  useToastStore,
  type DataTableColumn,
} from '@perfect-design/ui'
import { formatDate } from '@/lib/format'
import { faPen, faPlus, faRotateRight, faShieldHalved, faTrash } from '@/lib/icons'

interface Bypass {
  id: string
  type: 'cve' | 'package'
  target: string
  reason: string
  created_by: string
  created_at: string
  expires_at: string
  applies_to?: string
  notify_on_expiry: boolean
  active: boolean
}

const loading = ref(false)
const error = ref<string | null>(null)
const toasts = useToastStore()
const bypasses = ref<Bypass[]>([])
const activeFilter = ref<'all' | 'active' | 'expired'>('all')
const typeFilter = ref<'all' | 'cve' | 'package'>('all')

const showCreateModal = ref(false)
const showDeleteModal = ref(false)
const editingBypass = ref<Bypass | null>(null)
const bypassToDelete = ref<Bypass | null>(null)

const EMPTY_FORM = {
  type: 'cve' as 'cve' | 'package',
  target: '',
  reason: '',
  created_by: '',
  expires_in_hours: 168,
  applies_to: '',
  notify_on_expiry: false,
  active: true,
}

const bypassForm = ref({ ...EMPTY_FORM })

// Get API key from localStorage or prompt user
const apiKey = ref<string>('')

const filteredBypasses = computed(() => {
  let filtered = bypasses.value

  // Filter by active/expired
  if (activeFilter.value === 'active') {
    filtered = filtered.filter(b => b.active && !isExpired(b.expires_at))
  } else if (activeFilter.value === 'expired') {
    filtered = filtered.filter(b => isExpired(b.expires_at))
  }

  // Filter by type
  if (typeFilter.value !== 'all') {
    filtered = filtered.filter(b => b.type === typeFilter.value)
  }

  return filtered
})

const isFormValid = computed(() => {
  if (editingBypass.value) {
    return bypassForm.value.reason.trim() !== '' && bypassForm.value.expires_in_hours > 0
  }
  return (
    bypassForm.value.target.trim() !== '' &&
    bypassForm.value.reason.trim() !== '' &&
    bypassForm.value.created_by.trim() !== '' &&
    bypassForm.value.expires_in_hours > 0
  )
})

onMounted(() => {
  // Try to get API key from localStorage
  apiKey.value = localStorage.getItem('admin_api_key') || ''
  if (!apiKey.value) {
    promptForApiKey()
  } else {
    fetchBypasses()
  }
})

function promptForApiKey() {
  const key = prompt('Enter your admin API key:')
  if (key) {
    apiKey.value = key
    localStorage.setItem('admin_api_key', key)
    fetchBypasses()
  } else {
    error.value = 'Admin API key required to manage bypasses'
  }
}

async function fetchBypasses() {
  if (!apiKey.value) {
    promptForApiKey()
    return
  }

  loading.value = true
  error.value = null
  try {
    const params = new URLSearchParams()
    if (activeFilter.value === 'active') {
      params.append('active_only', 'true')
    } else if (activeFilter.value === 'expired') {
      params.append('include_expired', 'true')
    }
    if (typeFilter.value !== 'all') {
      params.append('type', typeFilter.value)
    }

    const response = await axios.get('/api/admin/bypasses?' + params.toString(), {
      headers: {
        Authorization: `Bearer ${apiKey.value}`,
      },
    })
    bypasses.value = response.data.bypasses || []
  } catch (err: any) {
    console.error('Failed to fetch bypasses:', err)
    if (err.response?.status === 401) {
      error.value = 'Invalid API key. Please check your credentials.'
      localStorage.removeItem('admin_api_key')
      apiKey.value = ''
    } else {
      error.value = err.response?.data?.error?.message || err.message || 'Failed to load bypasses'
    }
  } finally {
    loading.value = false
  }
}

async function submitBypass() {
  if (!isFormValid.value) return

  loading.value = true

  try {
    if (editingBypass.value) {
      // Update existing bypass
      await axios.patch(
        `/api/admin/bypasses/${editingBypass.value.id}`,
        {
          active: bypassForm.value.active,
          reason: bypassForm.value.reason,
          expires_in_hours: bypassForm.value.expires_in_hours,
        },
        {
          headers: {
            Authorization: `Bearer ${apiKey.value}`,
          },
        }
      )
      toasts.success('Bypass updated')
    } else {
      // Create new bypass
      await axios.post(
        '/api/admin/bypasses',
        {
          type: bypassForm.value.type,
          target: bypassForm.value.target,
          reason: bypassForm.value.reason,
          created_by: bypassForm.value.created_by,
          expires_in_hours: bypassForm.value.expires_in_hours,
          applies_to: bypassForm.value.applies_to || undefined,
          notify_on_expiry: bypassForm.value.notify_on_expiry,
        },
        {
          headers: {
            Authorization: `Bearer ${apiKey.value}`,
          },
        }
      )
      toasts.success('Bypass created')
    }

    closeCreateModal()
    await fetchBypasses()
  } catch (err: any) {
    console.error('Failed to submit bypass:', err)
    toasts.error('Could not save bypass', err.response?.data?.error?.message || err.message || 'Failed to save bypass')
  } finally {
    loading.value = false
  }
}

function editBypass(bypass: Bypass) {
  editingBypass.value = bypass
  bypassForm.value = {
    type: bypass.type,
    target: bypass.target,
    reason: bypass.reason,
    created_by: bypass.created_by,
    expires_in_hours: 168, // Default extension
    applies_to: bypass.applies_to || '',
    notify_on_expiry: bypass.notify_on_expiry,
    active: bypass.active,
  }
  showCreateModal.value = true
}

function closeCreateModal() {
  showCreateModal.value = false
}

// Also covers dismissal by Escape or the close button, so the next open never reuses an old edit.
watch(showCreateModal, (open) => {
  if (open) return
  editingBypass.value = null
  bypassForm.value = { ...EMPTY_FORM }
})

function confirmDeleteBypass(bypass: Bypass) {
  bypassToDelete.value = bypass
  showDeleteModal.value = true
}

async function deleteBypass() {
  if (!bypassToDelete.value) return

  loading.value = true

  try {
    await axios.delete(`/api/admin/bypasses/${bypassToDelete.value.id}`, {
      headers: {
        Authorization: `Bearer ${apiKey.value}`,
      },
    })

    toasts.success('Bypass deleted')
    showDeleteModal.value = false
    bypassToDelete.value = null
    await fetchBypasses()
  } catch (err: any) {
    console.error('Failed to delete bypass:', err)
    toasts.error('Could not delete bypass', err.response?.data?.error?.message || err.message || 'Failed to delete bypass')
  } finally {
    loading.value = false
  }
}

function isExpired(expiresAt: string): boolean {
  return new Date(expiresAt) < new Date()
}

const FILTER_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'active', label: 'Active' },
  { value: 'expired', label: 'Expired' },
]

const TYPE_OPTIONS = [
  { value: 'all', label: 'All' },
  { value: 'cve', label: 'CVE' },
  { value: 'package', label: 'Package' },
]

const BYPASS_TYPE_OPTIONS = [
  { value: 'cve', label: 'CVE bypass' },
  { value: 'package', label: 'Package bypass' },
]

const bypassColumns: DataTableColumn<Bypass>[] = [
  { key: 'target', header: 'Target', rowHeader: true },
  { key: 'type', header: 'Type' },
  { key: 'status', header: 'Status', accessor: (b) => (b.active ? 'active' : 'inactive') },
  { key: 'reason', header: 'Reason' },
  { key: 'created_by', header: 'Created by' },
  { key: 'created_at', header: 'Created', accessor: (b) => formatDate(b.created_at) },
  { key: 'expires_at', header: 'Expires', accessor: (b) => formatDate(b.expires_at) },
  { key: 'applies_to', header: 'Applies to' },
  { key: 'actions', header: 'Actions', actions: true, accessor: () => '' },
]

function setExpiresInHours(value: string | number) {
  bypassForm.value.expires_in_hours = Number(value)
}

</script>
