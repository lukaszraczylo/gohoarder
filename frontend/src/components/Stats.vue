<template>
  <div>
    <h2 class="text-3xl font-bold text-gray-900 mb-8">Statistics</h2>

    <!-- Error Alert -->
    <Alert v-if="error" variant="destructive" class="mb-4">
      <i class="fas fa-exclamation-circle mr-2"></i>
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <i class="fas fa-spinner fa-spin text-4xl text-primary-600"></i>
      <p class="mt-4 text-gray-600">Loading statistics...</p>
    </div>

    <!-- Stats Cards -->
    <div v-else>
      <!-- Overall Stats -->
      <Card class="mb-8">
        <CardContent class="p-6">
          <h3 class="text-xl font-bold text-gray-900 mb-6">
            <i class="fas fa-chart-bar mr-2"></i>Overall Statistics
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="text-center p-6 bg-gray-50 rounded-lg">
              <p class="text-4xl font-bold text-primary-600 mb-2">
                {{ formatNumber(stats?.total_packages || 0) }}
              </p>
              <p class="text-sm text-gray-600">Total Packages</p>
            </div>
            <div class="text-center p-6 bg-gray-50 rounded-lg">
              <p class="text-4xl font-bold text-blue-600 mb-2">
                {{ formatBytes(stats?.total_size || 0) }}
              </p>
              <p class="text-sm text-gray-600">Total Storage Used</p>
            </div>
            <div class="text-center p-6 bg-gray-50 rounded-lg">
              <p class="text-4xl font-bold text-green-600 mb-2">
                {{ formatNumber(stats?.total_downloads || 0) }}
              </p>
              <p class="text-sm text-gray-600">Total Downloads</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- Security Stats -->
      <Card class="mb-8">
        <CardContent class="p-6">
          <h3 class="text-xl font-bold text-gray-900 mb-6">
            <i class="fas fa-shield-alt mr-2"></i>Security Scanning
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="flex items-center justify-between p-6 bg-green-50 rounded-lg border border-green-200">
              <div>
                <p class="text-3xl font-bold text-green-600">
                  {{ formatNumber(stats?.scanned_packages || 0) }}
                </p>
                <p class="text-sm text-gray-600 mt-1">Scanned Packages</p>
              </div>
              <i class="fas fa-check-circle text-5xl text-green-400"></i>
            </div>
            <div class="flex items-center justify-between p-6 bg-red-50 rounded-lg border border-red-200">
              <div>
                <p class="text-3xl font-bold text-red-600">
                  {{ formatNumber(stats?.vulnerable_packages || 0) }}
                </p>
                <p class="text-sm text-gray-600 mt-1">Vulnerable Packages</p>
              </div>
              <i class="fas fa-exclamation-triangle text-5xl text-red-400"></i>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- Registry Breakdown -->
      <Card>
        <CardContent class="p-6">
          <h3 class="text-xl font-bold text-gray-900 mb-6">
            <i class="fas fa-server mr-2"></i>Registry Breakdown
          </h3>
          <div class="space-y-4">
            <div
              v-for="registry in registries"
              :key="registry.name"
              class="flex items-center justify-between p-4 bg-gray-50 rounded-lg"
            >
              <div class="flex items-center space-x-4">
                <div
                  class="w-12 h-12 rounded-full flex items-center justify-center"
                  :class="registry.color"
                >
                  <i :class="registry.icon + ' text-2xl'"></i>
                </div>
                <div>
                  <p class="font-bold text-gray-900">{{ registry.label }}</p>
                  <p class="text-sm text-gray-600">{{ registry.packages }} packages</p>
                </div>
              </div>
              <div class="text-right">
                <p class="text-lg font-bold text-gray-900">{{ registry.size }}</p>
                <p class="text-sm text-gray-600">{{ registry.downloads }} downloads</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { storeToRefs } from 'pinia'
import { usePackageStore } from '../stores/packages'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent } from '@/components/ui/card'

const store = usePackageStore()
const { stats, loading, error } = storeToRefs(store)

onMounted(async () => {
  await store.fetchStats()
})

// Registry configuration for icons and colors
const registryConfig: Record<string, {label: string, icon: string, color: string}> = {
  npm: {
    label: 'NPM Registry',
    icon: 'fab fa-npm text-red-500',
    color: 'bg-red-100'
  },
  pypi: {
    label: 'PyPI Registry',
    icon: 'fab fa-python text-blue-500',
    color: 'bg-blue-100'
  },
  go: {
    label: 'Go Modules',
    icon: 'fas fa-code text-cyan-500',
    color: 'bg-cyan-100'
  }
}

const registries = computed(() => {
  const apiRegistries = store.registries || {}
  return Object.entries(apiRegistries).map(([name, data]: [string, any]) => {
    const config = registryConfig[name] || {
      label: name.toUpperCase(),
      icon: 'fas fa-box',
      color: 'bg-gray-100'
    }
    return {
      name,
      label: config.label,
      icon: config.icon,
      color: config.color,
      packages: data.count || 0,
      size: formatBytes(data.size || 0),
      downloads: data.downloads || 0
    }
  })
})

function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num)
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}
</script>
