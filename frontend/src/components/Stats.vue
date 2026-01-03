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
          <h3 class="text-xl font-semibold text-gray-900 mb-6">
            <i class="fas fa-chart-bar mr-2"></i>Overall Statistics
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="text-center p-6 bg-gray-50 rounded-lg">
              <p class="text-4xl font-bold text-primary-600 mb-2">
                {{ formatNumber(stats?.total_packages || 0) }}
              </p>
              <p class="text-sm text-gray-600">Total Packages</p>
            </div>
            <div class="p-6 bg-gray-50 rounded-lg">
              <div class="text-center mb-3">
                <p class="text-2xl font-bold text-blue-600">
                  {{ formatBytes(stats?.total_size || 0) }} / {{ formatBytes(stats?.max_cache_size || 0) }}
                </p>
                <p class="text-sm text-gray-600 mt-1">Storage Used</p>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
                <div
                  class="h-full bg-blue-600 rounded-full transition-all duration-300"
                  :style="{ width: storagePercentage + '%' }"
                  :class="{
                    'bg-green-600': storagePercentage < 50,
                    'bg-yellow-600': storagePercentage >= 50 && storagePercentage < 80,
                    'bg-orange-600': storagePercentage >= 80 && storagePercentage < 90,
                    'bg-red-600': storagePercentage >= 90
                  }"
                ></div>
              </div>
              <p class="text-xs text-gray-500 text-center mt-1">{{ storagePercentage.toFixed(1) }}% used</p>
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
          <h3 class="text-xl font-semibold text-gray-900 mb-6">
            <i class="fas fa-shield-alt mr-2"></i>Security Scanning
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="flex items-center justify-between p-6 bg-green-50 rounded-lg border border-green-200">
              <div>
                <p class="text-3xl font-bold text-green-600">
                  {{ formatNumber(stats?.scanned_packages || 0) }}
                </p>
                <p class="text-sm text-gray-600 mt-1">Scanned Packages</p>
              </div>
              <i class="fas fa-check-circle text-5xl text-green-400"></i>
            </div>
            <div
              @click="showVulnerablePackages"
              class="flex items-center justify-between p-6 bg-orange-50 rounded-lg border border-orange-200 cursor-pointer hover:bg-orange-100 transition-colors"
              :class="{ 'opacity-50': (stats?.vulnerable_packages || 0) === 0 }"
            >
              <div>
                <p class="text-3xl font-bold text-orange-600">
                  {{ formatNumber(stats?.vulnerable_packages || 0) }}
                </p>
                <p class="text-sm text-gray-600 mt-1">
                  Vulnerable Packages
                  <span v-if="(stats?.vulnerable_packages || 0) > 0" class="text-xs ml-1">(click to view)</span>
                </p>
              </div>
              <i class="fas fa-exclamation-triangle text-5xl text-orange-400"></i>
            </div>
            <div
              @click="showBlockedPackages"
              class="flex items-center justify-between p-6 bg-red-50 rounded-lg border border-red-200 cursor-pointer hover:bg-red-100 transition-colors"
              :class="{ 'opacity-50': (stats?.blocked_packages || 0) === 0 }"
            >
              <div>
                <p class="text-3xl font-bold text-red-600">
                  {{ formatNumber(stats?.blocked_packages || 0) }}
                </p>
                <p class="text-sm text-gray-600 mt-1">
                  Blocked Packages
                  <span v-if="(stats?.blocked_packages || 0) > 0" class="text-xs ml-1">(click to view)</span>
                </p>
              </div>
              <i class="fas fa-hand text-5xl text-red-400"></i>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- Registry Breakdown -->
      <Card>
        <CardContent class="p-6">
          <h3 class="text-xl font-semibold text-gray-900 mb-6">
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
import { useRouter } from 'vue-router'
import { usePackageStore } from '../stores/packages'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent } from '@/components/ui/card'

const store = usePackageStore()
const { stats, loading, error } = storeToRefs(store)
const router = useRouter()

onMounted(async () => {
  await store.fetchStats()
})

function showVulnerablePackages() {
  if ((stats.value?.vulnerable_packages || 0) === 0) {
    return
  }

  router.push('/vulnerable-packages')
}

function showBlockedPackages() {
  if ((stats.value?.blocked_packages || 0) === 0) {
    return
  }

  router.push('/blocked-packages')
}

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

const storagePercentage = computed(() => {
  const totalSize = stats.value?.total_size || 0
  const maxSize = stats.value?.max_cache_size || 1
  return (totalSize / maxSize) * 100
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
