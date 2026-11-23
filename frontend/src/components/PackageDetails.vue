<template>
  <div class="flex flex-col gap-6">
    <PageHeader :title="packageName">
      <template #back>
        <Button variant="ghost" size="sm" :icon-start="faArrowLeft" @click="goBack">Back to packages</Button>
      </template>
      <template #description>
        <span class="flex flex-wrap items-center gap-2">
          <Badge variant="outline">{{ registry }}</Badge>
          <Badge variant="outline" class="font-mono">v{{ version }}</Badge>
        </span>
      </template>
    </PageHeader>

    <LoadingState v-if="loading" variant="card" label="Loading vulnerability details..." />

    <ErrorState
      v-else-if="error"
      variant="card"
      title="Could not load vulnerability details"
      :message="error"
      @retry="fetchVulnerabilities"
    />

    <template v-else-if="vulnerabilities">
      <Card>
        <CardHeader>
          <CardTitle as="h2">Security scan summary</CardTitle>
        </CardHeader>
        <CardContent class="flex flex-col gap-4">
          <SeveritySummary :counts="severityCounts" label="Vulnerabilities by severity" />
          <DescriptionList variant="inline" divided>
            <DescriptionItem term="Scanned">{{ formatDate(vulnerabilities.scanned_at) }}</DescriptionItem>
            <DescriptionItem term="Scanners">
              <span class="flex flex-wrap gap-1">
                <Badge v-for="scanner in scannerList" :key="scanner" variant="secondary">{{ scanner }}</Badge>
              </span>
            </DescriptionItem>
            <DescriptionItem v-if="bypassedCount > 0" term="Bypassed">
              <StatusBadge status="bypassed" :label="`${bypassedCount} bypassed`" :tones="{ bypassed: 'success' }" />
            </DescriptionItem>
          </DescriptionList>
        </CardContent>
      </Card>

      <Card v-if="vulnerabilityList.length === 0">
        <CardContent>
          <EmptyState
            tone="success"
            :icon="faCircleCheck"
            title="No vulnerabilities found"
            description="The scanners reported nothing for this package version."
          />
        </CardContent>
      </Card>

      <Card v-else>
        <CardHeader>
          <CardTitle as="h2">Detected vulnerabilities ({{ vulnerabilityList.length }})</CardTitle>
        </CardHeader>
        <CardContent>
          <Table label="Detected vulnerabilities" layout="cards">
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>CVE ID</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Fix version</TableHead>
                <TableHead align="center">Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <template v-for="(vuln, index) in vulnerabilityList" :key="vuln.id">
                <TableRow class="cursor-pointer" :selected="expandedRows.has(index)" @click="toggleRow(index)">
                  <TableCell label="Severity">
                    <span class="flex flex-wrap items-center gap-2">
                      <StatusBadge
                        :status="vuln.severity"
                        :tones="SEVERITY_TONES"
                        :label="formatSeverityName(vuln.severity)"
                      />
                      <StatusBadge
                        v-if="vuln.bypassed"
                        status="bypassed"
                        label="Bypassed"
                        :tones="{ bypassed: 'success' }"
                      />
                    </span>
                  </TableCell>
                  <TableCell label="CVE ID" class="font-mono font-medium">{{ vuln.id }}</TableCell>
                  <TableCell label="Description">
                    <p class="m-0 line-clamp-2 break-words">{{ vuln.title || vuln.description }}</p>
                  </TableCell>
                  <TableCell label="Fix version">
                    <span v-if="vuln.fixed_in">v{{ vuln.fixed_in }}</span>
                    <span v-else class="text-muted-foreground">-</span>
                  </TableCell>
                  <TableCell label="Details" align="center">
                    <IconButton
                      size="icon-sm"
                      :icon="expandedRows.has(index) ? faChevronUp : faChevronDown"
                      :label="`${expandedRows.has(index) ? 'Hide' : 'Show'} details for ${vuln.id}`"
                      :aria-expanded="expandedRows.has(index)"
                      @click.stop="toggleRow(index)"
                    />
                  </TableCell>
                </TableRow>

                <TableRow v-if="expandedRows.has(index)" :hoverable="false">
                  <TableCell :colspan="5">
                    <div class="flex flex-col gap-4 py-2">
                      <section>
                        <h3 class="mb-2 text-sm font-semibold">Description</h3>
                        <Markdown :source="vuln.description" :heading-offset="3" />
                      </section>

                      <Alert v-if="vuln.bypassed && vuln.bypass" variant="success">
                        <AlertTitle>Bypass active</AlertTitle>
                        <AlertDescription>
                          <DescriptionList variant="grid" :columns="3" size="sm">
                            <DescriptionItem term="Reason">{{ vuln.bypass.reason }}</DescriptionItem>
                            <DescriptionItem term="By">{{ vuln.bypass.created_by }}</DescriptionItem>
                            <DescriptionItem term="Expires">{{ formatDate(vuln.bypass.expires_at) }}</DescriptionItem>
                          </DescriptionList>
                        </AlertDescription>
                      </Alert>

                      <Alert v-if="vuln.fixed_in" variant="info">
                        <AlertTitle>Fix available</AlertTitle>
                        <AlertDescription>
                          Upgrade to version <strong>{{ vuln.fixed_in }}</strong> or later.
                        </AlertDescription>
                      </Alert>

                      <section v-if="vuln.references && vuln.references.length > 0">
                        <h3 class="mb-2 text-sm font-semibold">References ({{ vuln.references.length }})</h3>
                        <ul class="m-0 flex list-none flex-col gap-1 p-0 text-sm">
                          <li v-for="(ref, refIndex) in vuln.references" :key="refIndex" class="break-all">
                            <Link :href="ref" external>{{ ref }}</Link>
                          </li>
                        </ul>
                      </section>
                    </div>
                  </TableCell>
                </TableRow>
              </template>
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import axios from 'axios'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  DescriptionItem,
  DescriptionList,
  EmptyState,
  ErrorState,
  IconButton,
  Link,
  LoadingState,
  Markdown,
  PageHeader,
  StatusBadge,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@perfect-design/ui'
import SeveritySummary from './SeveritySummary.vue'
import { formatDate } from '@/lib/format'
import { faArrowLeft, faChevronDown, faChevronUp, faCircleCheck } from '@/lib/icons'
import { NO_VULNERABILITIES, SEVERITY_TONES, formatSeverityName, severityRank } from '@/lib/severity'

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

const vulnerabilityList = computed(() => {
  const vulns = vulnerabilities.value?.vulnerabilities || []
  // Sort by severity (most severe first)
  return [...vulns].sort((a, b) => {
    return severityRank(b.severity) - severityRank(a.severity)
  })
})

const severityCounts = computed(() => vulnerabilities.value?.severity_counts || NO_VULNERABILITIES)
const bypassedCount = computed(() => vulnerabilities.value?.bypassed_count || 0)

// Parse scanner string into array of scanner names
const scannerList = computed(() => {
  if (!vulnerabilities.value?.scanner) return []
  return vulnerabilities.value.scanner.split('+').map((s: string) => s.trim())
})

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
    // Store the response data
    vulnerabilities.value = response.data
  } catch (err: any) {
    console.error('Failed to fetch vulnerabilities:', err)
    error.value = err.response?.data?.error || err.message || 'Failed to load vulnerability details'
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

</script>
