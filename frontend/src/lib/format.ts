const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB']
const BYTES_PER_UNIT = 1024

export function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num)
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const i = Math.floor(Math.log(bytes) / Math.log(BYTES_PER_UNIT))
  return Math.round((bytes / Math.pow(BYTES_PER_UNIT, i)) * 100) / 100 + ' ' + BYTE_UNITS[i]
}

const SECONDS_PER_DAY = 86400
const SECONDS_PER_HOUR = 3600
const SECONDS_PER_MINUTE = 60

function plural(n: number, unit: string): string {
  return `${n} ${unit}${n === 1 ? '' : 's'}`
}

/** Whole days, hours or minutes, using the largest unit that divides the span evenly. */
export function formatDuration(seconds: number): string {
  if (seconds % SECONDS_PER_DAY === 0) return plural(seconds / SECONDS_PER_DAY, 'day')
  if (seconds % SECONDS_PER_HOUR === 0) return plural(seconds / SECONDS_PER_HOUR, 'hour')
  return plural(Math.round(seconds / SECONDS_PER_MINUTE), 'minute')
}

export function formatDate(date: string): string {
  if (!date) return 'N/A'
  const parsed = new Date(date)
  return Number.isNaN(parsed.getTime()) ? date : parsed.toLocaleString()
}

/** PyPI rows key on the file name; show the release version when the API sends one. */
export function displayVersion(pkg: { version: string; release_version?: string }): string {
  return pkg.release_version || pkg.version
}

export function withVersionPrefix(version: string): string {
  return version.startsWith('v') ? version : 'v' + version
}
