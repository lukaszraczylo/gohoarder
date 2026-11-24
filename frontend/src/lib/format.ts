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

/** A span in the largest fitting unit, rounded: "40 seconds", "12 minutes", "3 hours". */
export function formatApproxDuration(seconds: number): string {
  if (seconds < SECONDS_PER_MINUTE) return plural(Math.max(1, Math.round(seconds)), 'second')
  if (seconds < 2 * SECONDS_PER_HOUR) return plural(Math.round(seconds / SECONDS_PER_MINUTE), 'minute')
  return plural(Math.round(seconds / SECONDS_PER_HOUR), 'hour')
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

/** Go cache keys end in `/@v/<version>.<ext>`; the module path is what a person recognises. */
export function modulePath(name: string): string {
  const at = name.indexOf('/@v/')
  return at === -1 ? name : name.slice(0, at)
}
