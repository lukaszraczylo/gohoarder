/**
 * Shared badge styling utilities for consistent UI across the application
 */

/**
 * Get Tailwind CSS classes for severity badges (light theme)
 * @param severity - Severity level (CRITICAL, HIGH, MODERATE/MEDIUM, LOW)
 * @returns Tailwind CSS class string
 */
export function getSeverityBadgeClass(severity: string): string {
  const classes: Record<string, string> = {
    CRITICAL: 'bg-red-100 text-red-800 border-red-300',
    HIGH: 'bg-orange-100 text-orange-800 border-orange-300',
    MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-300',
    MODERATE: 'bg-yellow-100 text-yellow-800 border-yellow-300',
    LOW: 'bg-blue-100 text-blue-800 border-blue-300',
  }
  return classes[severity.toUpperCase()] || 'bg-gray-100 text-gray-800 border-gray-300'
}

/**
 * Get Tailwind CSS classes for registry badges (light theme)
 * @param registry - Registry name (npm, pypi, go)
 * @returns Tailwind CSS class string
 */
export function getRegistryBadgeClass(registry: string): string {
  const classes: Record<string, string> = {
    npm: 'bg-red-100 text-red-800 border-red-300',
    pypi: 'bg-blue-100 text-blue-800 border-blue-300',
    go: 'bg-cyan-100 text-cyan-800 border-cyan-300',
  }
  return classes[registry.toLowerCase()] || 'bg-gray-100 text-gray-800 border-gray-300'
}

/**
 * Get Tailwind CSS classes for vulnerability border indicators
 * @param severity - Severity level (CRITICAL, HIGH, MODERATE/MEDIUM, LOW)
 * @returns Tailwind CSS class string for left border
 */
export function getVulnerabilityBorderClass(severity: string): string {
  const classes: Record<string, string> = {
    CRITICAL: 'border-l-4 border-l-red-600',
    HIGH: 'border-l-4 border-l-orange-500',
    MEDIUM: 'border-l-4 border-l-yellow-500',
    MODERATE: 'border-l-4 border-l-yellow-500',
    LOW: 'border-l-4 border-l-blue-500',
  }
  return classes[severity.toUpperCase()] || 'border-l-4 border-l-gray-500'
}

/**
 * Format severity name for display (title case)
 * @param severity - Severity level (e.g., "CRITICAL", "HIGH")
 * @returns Formatted severity name (e.g., "Critical", "High")
 */
export function formatSeverityName(severity: string): string {
  const normalized = severity.toUpperCase()
  return normalized.charAt(0) + normalized.slice(1).toLowerCase()
}
