<template>
  <div>
    <div class="flex justify-between items-center mb-8">
      <div>
        <h2 class="text-3xl font-bold text-gray-900">CVE Bypass Management</h2>
        <p class="text-gray-600 mt-1">Manage temporary security bypasses for packages and CVEs</p>
      </div>
      <Button @click="showCreateModal = true" class="bg-green-600 hover:bg-green-700">
        <i class="fas fa-plus mr-2"></i>Create Bypass
      </Button>
    </div>

    <!-- Filter Section -->
    <div class="mb-6 flex flex-col sm:flex-row items-start sm:items-center gap-4">
      <div class="flex items-center gap-2">
        <span class="text-sm font-medium text-gray-700">Filter:</span>
        <div class="flex gap-2">
          <Button
            @click="activeFilter = 'all'"
            :variant="activeFilter === 'all' ? 'default' : 'outline'"
            size="sm"
          >
            All
          </Button>
          <Button
            @click="activeFilter = 'active'"
            :variant="activeFilter === 'active' ? 'default' : 'outline'"
            size="sm"
          >
            <i class="fas fa-check-circle mr-1"></i>Active
          </Button>
          <Button
            @click="activeFilter === 'expired'"
            :variant="activeFilter === 'expired' ? 'default' : 'outline'"
            size="sm"
          >
            <i class="fas fa-clock mr-1"></i>Expired
          </Button>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <span class="text-sm font-medium text-gray-700">Type:</span>
        <div class="flex gap-2">
          <Button
            @click="typeFilter = ''"
            :variant="typeFilter === '' ? 'default' : 'outline'"
            size="sm"
          >
            All
          </Button>
          <Button
            @click="typeFilter = 'cve'"
            :variant="typeFilter === 'cve' ? 'default' : 'outline'"
            size="sm"
          >
            CVE
          </Button>
          <Button
            @click="typeFilter = 'package'"
            :variant="typeFilter === 'package' ? 'default' : 'outline'"
            size="sm"
          >
            Package
          </Button>
        </div>
      </div>
      <Button @click="fetchBypasses" variant="outline" size="sm" class="sm:ml-auto">
        <i class="fas fa-sync-alt mr-2"></i>Refresh
      </Button>
    </div>

    <!-- Error Alert -->
    <Alert v-if="error" variant="destructive" class="mb-4">
      <i class="fas fa-exclamation-circle mr-2"></i>
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <!-- Success Alert -->
    <Alert v-if="successMessage" class="mb-4 bg-green-50 border-green-200">
      <i class="fas fa-check-circle mr-2 text-green-600"></i>
      <AlertDescription class="text-green-800">{{ successMessage }}</AlertDescription>
    </Alert>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <i class="fas fa-spinner fa-spin text-4xl text-primary-600"></i>
      <p class="mt-4 text-gray-600">Loading bypasses...</p>
    </div>

    <!-- Bypass List -->
    <Card v-else>
      <CardContent class="p-6">
        <div v-if="filteredBypasses.length === 0" class="text-center py-12 text-gray-500">
          <i class="fas fa-shield-alt text-6xl mb-4"></i>
          <p class="text-xl">No bypasses found</p>
          <p class="mt-2">Create a bypass to allow packages with known vulnerabilities</p>
        </div>
        <div v-else class="space-y-4">
          <div
            v-for="bypass in filteredBypasses"
            :key="bypass.id"
            class="border rounded-lg p-4 hover:bg-gray-50"
            :class="bypass.active ? 'border-gray-200' : 'border-gray-300 bg-gray-50'"
          >
            <div class="flex items-start justify-between">
              <div class="flex-1">
                <div class="flex items-center gap-2 mb-2">
                  <Badge :variant="bypass.type === 'cve' ? 'default' : 'outline'">
                    {{ bypass.type.toUpperCase() }}
                  </Badge>
                  <Badge
                    :class="bypass.active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'"
                  >
                    {{ bypass.active ? 'ACTIVE' : 'INACTIVE' }}
                  </Badge>
                  <Badge
                    v-if="isExpired(bypass.expires_at)"
                    class="bg-red-100 text-red-800"
                  >
                    EXPIRED
                  </Badge>
                </div>
                <h4 class="font-semibold text-lg text-gray-900">{{ bypass.target }}</h4>
                <p class="text-sm text-gray-600 mt-1">{{ bypass.reason }}</p>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-3 text-sm text-gray-500">
                  <div>
                    <i class="fas fa-user mr-1"></i>
                    <strong>Created by:</strong> {{ bypass.created_by }}
                  </div>
                  <div>
                    <i class="fas fa-calendar mr-1"></i>
                    <strong>Created:</strong> {{ formatDate(bypass.created_at) }}
                  </div>
                  <div>
                    <i class="fas fa-clock mr-1"></i>
                    <strong>Expires:</strong> {{ formatDate(bypass.expires_at) }}
                  </div>
                  <div v-if="bypass.applies_to">
                    <i class="fas fa-box mr-1"></i>
                    <strong>Applies to:</strong> {{ bypass.applies_to }}
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-2 ml-4">
                <Button
                  @click="editBypass(bypass)"
                  variant="outline"
                  size="sm"
                  title="Edit bypass"
                >
                  <i class="fas fa-edit"></i>
                </Button>
                <Button
                  @click="confirmDeleteBypass(bypass)"
                  variant="destructive"
                  size="sm"
                  title="Delete bypass"
                >
                  <i class="fas fa-trash"></i>
                </Button>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>

    <!-- Create/Edit Bypass Modal -->
    <Dialog v-model:open="showCreateModal">
      <DialogContent class="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{{ editingBypass ? 'Edit' : 'Create' }} Bypass</DialogTitle>
          <DialogDescription>
            {{ editingBypass ? 'Update bypass settings' : 'Create a temporary bypass for a CVE or package' }}
          </DialogDescription>
        </DialogHeader>

        <div class="space-y-4 py-4">
          <!-- Type Selection -->
          <div v-if="!editingBypass">
            <label class="text-sm font-medium text-gray-700 mb-2 block">Bypass Type</label>
            <div class="flex gap-4">
              <Button
                @click="bypassForm.type = 'cve'"
                :variant="bypassForm.type === 'cve' ? 'default' : 'outline'"
                class="flex-1"
              >
                <i class="fas fa-bug mr-2"></i>CVE Bypass
              </Button>
              <Button
                @click="bypassForm.type = 'package'"
                :variant="bypassForm.type === 'package' ? 'default' : 'outline'"
                class="flex-1"
              >
                <i class="fas fa-box mr-2"></i>Package Bypass
              </Button>
            </div>
          </div>

          <!-- Target -->
          <div v-if="!editingBypass">
            <label class="text-sm font-medium text-gray-700 mb-2 block">
              {{ bypassForm.type === 'cve' ? 'CVE ID' : 'Package' }}
            </label>
            <Input
              v-model="bypassForm.target"
              :placeholder="bypassForm.type === 'cve' ? 'CVE-2021-23337' : 'npm/lodash@4.17.20'"
              class="w-full"
            />
            <p class="text-xs text-gray-500 mt-1">
              {{ bypassForm.type === 'cve' ? 'Enter the CVE ID (e.g., CVE-2021-23337)' : 'Enter package (e.g., npm/lodash@4.17.20 or npm/lodash for all versions)' }}
            </p>
          </div>

          <!-- Applies To (CVE only) -->
          <div v-if="!editingBypass && bypassForm.type === 'cve'">
            <label class="text-sm font-medium text-gray-700 mb-2 block">
              Applies To (Optional)
            </label>
            <Input
              v-model="bypassForm.applies_to"
              placeholder="npm/lodash@4.17.20"
              class="w-full"
            />
            <p class="text-xs text-gray-500 mt-1">
              Limit this CVE bypass to a specific package. Leave empty to apply to all packages with this CVE.
            </p>
          </div>

          <!-- Reason -->
          <div>
            <label class="text-sm font-medium text-gray-700 mb-2 block">Reason *</label>
            <Input
              v-model="bypassForm.reason"
              placeholder="No fix available, business critical dependency"
              class="w-full"
            />
            <p class="text-xs text-gray-500 mt-1">
              Explain why this bypass is needed (required for audit trail)
            </p>
          </div>

          <!-- Created By -->
          <div v-if="!editingBypass">
            <label class="text-sm font-medium text-gray-700 mb-2 block">Created By *</label>
            <Input
              v-model="bypassForm.created_by"
              placeholder="admin@example.com"
              class="w-full"
            />
          </div>

          <!-- Expires In -->
          <div>
            <label class="text-sm font-medium text-gray-700 mb-2 block">Expires In (Hours) *</label>
            <Input
              v-model.number="bypassForm.expires_in_hours"
              type="number"
              min="1"
              placeholder="168"
              class="w-full"
            />
            <p class="text-xs text-gray-500 mt-1">
              How many hours until this bypass expires (e.g., 168 = 7 days, 720 = 30 days)
            </p>
          </div>

          <!-- Active (Edit only) -->
          <div v-if="editingBypass" class="flex items-center gap-2">
            <input
              type="checkbox"
              v-model="bypassForm.active"
              id="active-checkbox"
              class="w-4 h-4"
            />
            <label for="active-checkbox" class="text-sm font-medium text-gray-700">
              Active
            </label>
          </div>

          <!-- Notify on Expiry -->
          <div class="flex items-center gap-2">
            <input
              type="checkbox"
              v-model="bypassForm.notify_on_expiry"
              id="notify-checkbox"
              class="w-4 h-4"
            />
            <label for="notify-checkbox" class="text-sm font-medium text-gray-700">
              Send notification when bypass expires
            </label>
          </div>
        </div>

        <DialogFooter>
          <Button @click="closeCreateModal" variant="outline">
            Cancel
          </Button>
          <Button @click="submitBypass" :disabled="!isFormValid">
            {{ editingBypass ? 'Update' : 'Create' }} Bypass
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Delete Confirmation Dialog -->
    <Dialog v-model:open="showDeleteModal">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Confirm Deletion</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete this bypass for <strong>{{ bypassToDelete?.target }}</strong>?
            This action cannot be undone and the security check will be re-enabled immediately.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button @click="showDeleteModal = false" variant="outline">
            Cancel
          </Button>
          <Button @click="deleteBypass" variant="destructive">
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import axios from 'axios'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'

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
const successMessage = ref<string | null>(null)
const bypasses = ref<Bypass[]>([])
const activeFilter = ref<'all' | 'active' | 'expired'>('all')
const typeFilter = ref<'' | 'cve' | 'package'>('')

const showCreateModal = ref(false)
const showDeleteModal = ref(false)
const editingBypass = ref<Bypass | null>(null)
const bypassToDelete = ref<Bypass | null>(null)

const bypassForm = ref({
  type: 'cve' as 'cve' | 'package',
  target: '',
  reason: '',
  created_by: '',
  expires_in_hours: 168,
  applies_to: '',
  notify_on_expiry: false,
  active: true,
})

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
  if (typeFilter.value) {
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
    if (typeFilter.value) {
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
  error.value = null
  successMessage.value = null

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
      successMessage.value = 'Bypass updated successfully'
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
      successMessage.value = 'Bypass created successfully'
    }

    closeCreateModal()
    await fetchBypasses()

    // Clear success message after 5 seconds
    setTimeout(() => {
      successMessage.value = null
    }, 5000)
  } catch (err: any) {
    console.error('Failed to submit bypass:', err)
    error.value = err.response?.data?.error?.message || err.message || 'Failed to save bypass'
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
  editingBypass.value = null
  bypassForm.value = {
    type: 'cve',
    target: '',
    reason: '',
    created_by: '',
    expires_in_hours: 168,
    applies_to: '',
    notify_on_expiry: false,
    active: true,
  }
}

function confirmDeleteBypass(bypass: Bypass) {
  bypassToDelete.value = bypass
  showDeleteModal.value = true
}

async function deleteBypass() {
  if (!bypassToDelete.value) return

  loading.value = true
  error.value = null
  successMessage.value = null

  try {
    await axios.delete(`/api/admin/bypasses/${bypassToDelete.value.id}`, {
      headers: {
        Authorization: `Bearer ${apiKey.value}`,
      },
    })

    successMessage.value = 'Bypass deleted successfully'
    showDeleteModal.value = false
    bypassToDelete.value = null
    await fetchBypasses()

    // Clear success message after 5 seconds
    setTimeout(() => {
      successMessage.value = null
    }, 5000)
  } catch (err: any) {
    console.error('Failed to delete bypass:', err)
    error.value = err.response?.data?.error?.message || err.message || 'Failed to delete bypass'
  } finally {
    loading.value = false
  }
}

function isExpired(expiresAt: string): boolean {
  return new Date(expiresAt) < new Date()
}

function formatDate(date: string): string {
  return new Date(date).toLocaleString()
}
</script>
