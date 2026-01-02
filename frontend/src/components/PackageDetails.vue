<template>
  <div class="max-w-7xl mx-auto px-4 py-8">
    <!-- Header with Back Button -->
    <div class="mb-6">
      <Button @click="goBack" variant="ghost" class="mb-4">
        <i class="fas fa-arrow-left mr-2"></i>
        Back to Packages
      </Button>
      <div class="flex items-center gap-3">
        <i class="fas fa-box text-3xl text-primary-600"></i>
        <div>
          <h1 class="text-3xl font-bold text-gray-900">{{ packageName }}</h1>
          <div class="flex items-center gap-2 mt-2">
            <Badge :class="getRegistryBadgeClass(registry)">{{ registry }}</Badge>
            <Badge variant="outline" class="font-mono">v{{ version }}</Badge>
          </div>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <i class="fas fa-spinner fa-spin text-4xl text-primary-600"></i>
      <p class="mt-4 text-gray-600">Loading vulnerability details...</p>
    </div>

    <!-- Error State -->
    <Alert v-else-if="error" variant="destructive" class="mb-4">
      <i class="fas fa-exclamation-circle mr-2"></i>
      <AlertDescription>{{ error }}</AlertDescription>
    </Alert>

    <!-- Vulnerability Details -->
    <div v-else-if="vulnerabilities" class="space-y-6">
      <!-- Summary Card -->
      <Card>
        <CardHeader>
          <CardTitle class="flex items-center gap-2">
            <i class="fas fa-shield-virus text-red-600"></i>
            Security Scan Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div class="text-center p-4 bg-red-50 rounded-lg border border-red-200">
              <p class="text-3xl font-bold text-red-600">{{ severityCounts.critical }}</p>
              <p class="text-sm text-gray-600 mt-1">Critical</p>
            </div>
            <div class="text-center p-4 bg-orange-50 rounded-lg border border-orange-200">
              <p class="text-3xl font-bold text-orange-600">{{ severityCounts.high }}</p>
              <p class="text-sm text-gray-600 mt-1">High</p>
            </div>
            <div class="text-center p-4 bg-yellow-50 rounded-lg border border-yellow-200">
              <p class="text-3xl font-bold text-yellow-600">{{ severityCounts.moderate }}</p>
              <p class="text-sm text-gray-600 mt-1">Moderate</p>
            </div>
            <div class="text-center p-4 bg-blue-50 rounded-lg border border-blue-200">
              <p class="text-3xl font-bold text-blue-600">{{ severityCounts.low }}</p>
              <p class="text-sm text-gray-600 mt-1">Low</p>
            </div>
          </div>
          <Separator class="my-4" />
          <div class="flex items-center justify-between text-sm">
            <div class="flex items-center gap-4">
              <span class="text-gray-600">
                <i class="fas fa-search mr-1"></i>
                Scanned: {{ formatDate(vulnerabilities.scanned_at) }}
              </span>
              <span class="text-gray-600">
                <i class="fas fa-cog mr-1"></i>
                Scanner: {{ vulnerabilities.scanner }}
              </span>
            </div>
            <div v-if="bypassedCount > 0" class="flex items-center gap-2 text-green-600">
              <i class="fas fa-check-circle"></i>
              <span>{{ bypassedCount }} bypassed</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- No Vulnerabilities -->
      <Card v-if="vulnerabilityList.length === 0">
        <CardContent class="text-center py-12">
          <i class="fas fa-check-circle text-6xl text-green-500 mb-4"></i>
          <p class="text-xl font-semibold text-gray-900">No Vulnerabilities Found</p>
          <p class="mt-2 text-gray-600">This package is clean and safe to use</p>
        </CardContent>
      </Card>

      <!-- Vulnerability List -->
      <Card v-else>
        <CardHeader>
          <CardTitle class="flex items-center gap-2">
            <i class="fas fa-list text-gray-600"></i>
            Detected Vulnerabilities ({{ vulnerabilityList.length }})
          </CardTitle>
        </CardHeader>
        <CardContent class="p-0">
          <div class="border-t">
            <Table>
              <TableHeader>
                <TableRow class="bg-gray-50 hover:bg-gray-50">
                  <TableHead class="w-[100px]">Severity</TableHead>
                  <TableHead class="w-[180px]">CVE ID</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead class="w-[120px]">Fix Version</TableHead>
                  <TableHead class="w-[100px] text-center">Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <template v-for="(vuln, index) in vulnerabilityList" :key="vuln.id">
                  <!-- Main Row -->
                  <TableRow
                    :class="getRowClass(index, vuln.severity)"
                    @click="toggleRow(index)"
                  >
                    <TableCell>
                      <Badge :class="getSeverityBadgeClass(vuln.severity)">
                        {{ formatSeverityName(vuln.severity) }}
                      </Badge>
                      <span
                        v-if="vuln.bypassed"
                        class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800"
                        title="Bypassed"
                      >
                        <i class="fas fa-unlock text-xs"></i>
                      </span>
                    </TableCell>
                    <TableCell>
                      <span class="font-mono text-sm font-medium">{{ vuln.id }}</span>
                    </TableCell>
                    <TableCell>
                      <p class="text-sm text-gray-900 line-clamp-2">{{ vuln.title || vuln.description }}</p>
                    </TableCell>
                    <TableCell>
                      <span v-if="vuln.fixed_in" class="inline-flex items-center text-sm text-green-700">
                        <i class="fas fa-arrow-up text-xs mr-1"></i>
                        v{{ vuln.fixed_in }}
                      </span>
                      <span v-else class="text-sm text-gray-400">-</span>
                    </TableCell>
                    <TableCell class="text-center">
                      <Button
                        variant="ghost"
                        size="sm"
                        class="h-8 w-8 p-0"
                        @click.stop="toggleRow(index)"
                      >
                        <i
                          :class="[
                            'fas transition-transform',
                            expandedRows.has(index) ? 'fa-chevron-up' : 'fa-chevron-down'
                          ]"
                        ></i>
                      </Button>
                    </TableCell>
                  </TableRow>

                  <!-- Expanded Details Row -->
                  <TableRow v-if="expandedRows.has(index)" class="bg-gray-50 hover:bg-gray-50">
                    <TableCell colspan="5" class="p-0">
                      <div class="px-6 py-4 space-y-3">
                        <!-- Full Description -->
                        <div>
                          <h5 class="font-semibold text-gray-900 mb-2">Description</h5>
                          <div
                            class="text-sm text-gray-700 leading-relaxed prose prose-sm max-w-none"
                            v-html="renderMarkdown(vuln.description)"
                          ></div>
                        </div>

                        <!-- Bypass Information -->
                        <div v-if="vuln.bypassed && vuln.bypass" class="bg-green-50 border border-green-200 rounded-lg p-3">
                          <h5 class="font-semibold text-green-900 mb-2 flex items-center gap-2">
                            <i class="fas fa-info-circle"></i>
                            Bypass Active
                          </h5>
                          <div class="grid grid-cols-3 gap-4 text-sm text-green-800">
                            <div>
                              <span class="font-medium">Reason:</span> {{ vuln.bypass.reason }}
                            </div>
                            <div>
                              <span class="font-medium">By:</span> {{ vuln.bypass.created_by }}
                            </div>
                            <div>
                              <span class="font-medium">Expires:</span> {{ formatDate(vuln.bypass.expires_at) }}
                            </div>
                          </div>
                        </div>

                        <!-- Fix Information -->
                        <div v-if="vuln.fixed_in" class="bg-blue-50 border border-blue-200 rounded-lg p-3">
                          <div class="flex items-center gap-2">
                            <i class="fas fa-wrench text-blue-700"></i>
                            <span class="text-sm text-blue-900">
                              <span class="font-semibold">Fix Available:</span> Upgrade to version <strong>{{ vuln.fixed_in }}</strong> or later
                            </span>
                          </div>
                        </div>

                        <!-- Primary Reference -->
                        <div v-if="vuln.references && vuln.references.length > 0" class="flex items-center gap-2 text-sm">
                          <i class="fas fa-link text-gray-500"></i>
                          <a
                            :href="vuln.references[0]"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="text-blue-600 hover:text-blue-800 hover:underline font-medium"
                          >
                            View Full Advisory
                          </a>
                          <span v-if="vuln.references.length > 1" class="text-gray-500">
                            (+{{ vuln.references.length - 1 }} more)
                          </span>
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                </template>
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import axios from 'axios'
import { marked } from 'marked'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Separator } from '@/components/ui/separator'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

// Configure marked
marked.setOptions({
  breaks: true,
  gfm: true,
})

const router = useRouter()
const route = useRoute()

const registry = computed(() => route.params.registry as string)
const packageName = computed(() => {
  // Handle package names with slashes (e.g., Go packages like github.com/user/repo)
  const nameParam = route.params.name
  if (Array.isArray(nameParam)) {
    return nameParam.join('/')
  }
  return nameParam as string
})
const version = computed(() => route.params.version as string)

interface BypassInfo {
  id: string
  reason: string
  created_by: string
  expires_at: string
}

interface Vulnerability {
  id: string
  severity: string
  title: string
  description: string
  references: string[]
  fixed_in: string
  bypassed: boolean
  bypass?: BypassInfo
}

interface VulnerabilityResponse {
  scanned: boolean
  scanner: string
  scanned_at: string
  status: string
  vulnerabilities: Vulnerability[]
  vulnerability_count: number
  severity_counts: {
    critical: number
    high: number
    moderate: number
    low: number
  }
  bypassed_count: number
}

const loading = ref(false)
const error = ref<string | null>(null)
const vulnerabilities = ref<VulnerabilityResponse | null>(null)
const expandedRows = ref<Set<number>>(new Set())

// Severity order for sorting (higher values = more severe)
const severityOrder: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  MODERATE: 2,  // Treat MODERATE same as MEDIUM
  LOW: 1,
  UNKNOWN: 0,
}

const vulnerabilityList = computed(() => {
  const vulns = vulnerabilities.value?.vulnerabilities || []
  // Sort by severity (most severe first)
  return [...vulns].sort((a, b) => {
    const severityA = severityOrder[a.severity.toUpperCase()] || 0
    const severityB = severityOrder[b.severity.toUpperCase()] || 0
    return severityB - severityA  // Descending order
  })
})

const severityCounts = computed(() => vulnerabilities.value?.severity_counts || { critical: 0, high: 0, moderate: 0, low: 0 })
const bypassedCount = computed(() => vulnerabilities.value?.bypassed_count || 0)

onMounted(() => {
  fetchVulnerabilities()
})

async function fetchVulnerabilities() {
  loading.value = true
  error.value = null
  vulnerabilities.value = null

  try {
    const response = await axios.get(
      `/api/packages/${registry.value}/${packageName.value}/${version.value}/vulnerabilities`
    )
    // API wraps response in {success: true, data: {...}}
    vulnerabilities.value = response.data.data
  } catch (err: any) {
    console.error('Failed to fetch vulnerabilities:', err)
    error.value = err.response?.data?.error?.message || err.message || 'Failed to load vulnerability details'
  } finally {
    loading.value = false
  }
}

function goBack() {
  router.push('/packages')
}

function toggleRow(index: number) {
  if (expandedRows.value.has(index)) {
    expandedRows.value.delete(index)
  } else {
    expandedRows.value.add(index)
  }
}

function getRowClass(index: number, severity: string): string {
  const classes = ['cursor-pointer']
  if (expandedRows.value.has(index)) {
    classes.push('bg-gray-50')
  }
  classes.push(getVulnerabilityBorderClass(severity))
  return classes.join(' ')
}

function getSeverityBadgeClass(severity: string): string {
  const classes: Record<string, string> = {
    CRITICAL: 'bg-red-600 text-white hover:bg-red-700 border-0',
    HIGH: 'bg-orange-500 text-white hover:bg-orange-600 border-0',
    MEDIUM: 'bg-yellow-500 text-white hover:bg-yellow-600 border-0',
    LOW: 'bg-blue-500 text-white hover:bg-blue-600 border-0',
    MODERATE: 'bg-yellow-500 text-white hover:bg-yellow-600 border-0',
  }
  return classes[severity.toUpperCase()] || 'bg-gray-500 text-white hover:bg-gray-600 border-0'
}

function getVulnerabilityBorderClass(severity: string): string {
  const classes: Record<string, string> = {
    CRITICAL: 'border-l-4 border-l-red-600',
    HIGH: 'border-l-4 border-l-orange-500',
    MEDIUM: 'border-l-4 border-l-yellow-500',
    MODERATE: 'border-l-4 border-l-yellow-500',
    LOW: 'border-l-4 border-l-blue-500',
  }
  return classes[severity.toUpperCase()] || 'border-l-4 border-l-gray-500'
}

function getRegistryBadgeClass(registry: string): string {
  const classes: Record<string, string> = {
    npm: 'bg-red-500 text-white border-0',
    pypi: 'bg-blue-500 text-white border-0',
    go: 'bg-cyan-500 text-white border-0',
  }
  return classes[registry] || 'bg-gray-500 text-white border-0'
}

function formatDate(date: string): string {
  return new Date(date).toLocaleString()
}

function renderMarkdown(text: string): string {
  if (!text) return ''
  return marked.parse(text) as string
}

function formatSeverityName(severity: string): string {
  // Convert severity to title case (e.g., "CRITICAL" -> "Critical", "MODERATE" -> "Moderate")
  const normalized = severity.toUpperCase()
  return normalized.charAt(0) + normalized.slice(1).toLowerCase()
}
</script>
