import type { PackageReport } from '@/lib/report'
import { formatDate, withVersionPrefix } from '@/lib/format'
import { humanReason, plural } from '@/lib/reason'
import { formatSeverityName, severityRank } from '@/lib/severity'

export interface BannerContent {
  type: 'danger' | 'success' | 'note' | 'warning'
  title: string
  body: string
}

const MAX_NAMED = 3

function listIds(ids: readonly string[]): string {
  const shown = ids.slice(0, MAX_NAMED).join(', ')
  return ids.length > MAX_NAMED ? `${shown} and ${ids.length - MAX_NAMED} more` : shown
}

function heldBanner(report: PackageReport, policy: string): BannerContent {
  const live = report.vulnerabilities.filter((v) => !v.bypassed)
  const top = live.reduce((max, v) => Math.max(max, severityRank(v.severity)), 0)
  const blockers = live.filter((v) => severityRank(v.severity) === top)
  const reason = humanReason(report.decision.reason)
  const clients = 'Clients that request this version get a 403.'
  if (blockers.length === 0) {
    return { type: 'danger', title: `Held: ${reason || 'the scan did not complete'}`, body: `${policy} ${clients}`.trim() }
  }
  const verb = blockers.length === 1 ? 'is' : 'are'
  const fixes = [...new Set(blockers.map((b) => b.fixed_in).filter(Boolean))]
  const fix = fixes.length > 0 ? ` Fixed in ${fixes.map(withVersionPrefix).join(', ')}.` : ' No fixed version is listed.'
  return {
    type: 'danger',
    title: `Held: ${listIds(blockers.map((b) => b.id))} ${verb} ${formatSeverityName(blockers[0].severity).toUpperCase()}`,
    body: `${reason || policy} ${clients}${fix}`.replace(/\s+/g, ' ').trim(),
  }
}

/** The sentence at the top of a package page: what the verdict is and why. */
export function verdictBanner(report: PackageReport, policy: string, failClosed: boolean): BannerContent {
  const { verdict, bypass } = report.decision
  switch (verdict) {
    case 'held':
      return heldBanner(report, policy)
    case 'bypassed': {
      const scope = bypass?.type === 'package' ? 'package' : 'advisory'
      return {
        type: 'note',
        title: `Bypassed: ${bypass?.reason ?? 'an admin bypass applies'}`,
        body: bypass
          ? `${bypass.created_by} created this ${scope} bypass on ${formatDate(bypass.created_at)}. It expires on ${formatDate(bypass.expires_at)}. Clients are served this version.`
          : 'Clients are served this version.',
      }
    }
    case 'pending':
      return {
        type: 'warning',
        title: 'Awaiting scan',
        body: failClosed
          ? 'No scanner has reported on this version yet. The policy is fail-closed, so it is held until one does.'
          : 'No scanner has reported on this version yet.',
      }
    default: {
      const n = report.vulnerability_count
      return {
        type: 'success',
        title: 'Cleared: no finding reaches the block policy',
        body: n === 0 ? 'The scanners reported nothing. Clients are served this version.' : `${plural(n, 'finding')} below the block policy. Clients are served this version.`,
      }
    }
  }
}
