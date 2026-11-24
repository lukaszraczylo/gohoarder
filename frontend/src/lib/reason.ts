import { formatSeverityName } from '@/lib/severity'

/** "1 finding", "2 findings". */
export function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`
}

const THRESHOLD_REASON = /^Package has (\d+) (CRITICAL|HIGH|MODERATE|MEDIUM|LOW) vulnerabilities \(threshold: (-?\d+)\)$/i
const FLOOR_REASON = /^Package has ([A-Za-z, ]+?) vulnerabilities$/

/** Turns the server's hold reason into a sentence a reader can act on. Unknown reasons pass through. */
export function humanReason(reason: string | undefined): string {
  if (!reason) return ''
  const t = THRESHOLD_REASON.exec(reason)
  if (t) {
    const count = Number(t[1])
    const level = t[2].toLowerCase()
    const limit = Number(t[3])
    const rule = limit <= 0 ? `Policy holds any ${level} finding.` : `Policy holds more than ${plural(limit, `${level} finding`)}.`
    return `${plural(count, `${level} finding`)}. ${rule}`
  }
  const f = FLOOR_REASON.exec(reason)
  if (f) {
    const levels = f[1]
      .split(/,\s*(?:or\s+)?|\s+or\s+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => formatSeverityName(s).toLowerCase())
    const named = levels.length > 1 ? `${levels.slice(0, -1).join(', ')} or ${levels[levels.length - 1]}` : levels[0]
    return `Has a ${named} finding. Policy holds a finding at that level.`
  }
  return reason
}
