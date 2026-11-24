export interface Bypass {
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

export function isExpired(expiresAt: string, now = Date.now()): boolean {
  return Date.parse(expiresAt) < now
}

/** Active and not yet expired. */
export function isLive(bypass: Bypass, now = Date.now()): boolean {
  return bypass.active && !isExpired(bypass.expires_at, now)
}

/** Bypass keys use the module path for Go, where stored rows end in `/@v/<version>.<ext>`. */
function bypassName(registry: string, name: string): string {
  const at = name.indexOf('/@v/')
  return registry === 'go' && at !== -1 ? name.slice(0, at) : name
}

/** The bypasses that cover one package version, by the same keys the server matches. */
export function bypassesFor(
  all: readonly Bypass[],
  pkg: { registry: string; name: string; version: string; releaseVersion?: string },
): Bypass[] {
  const base = `${pkg.registry}/${bypassName(pkg.registry, pkg.name)}`
  const keys = new Set([`${base}@${pkg.version}`, base])
  if (pkg.releaseVersion) keys.add(`${base}@${pkg.releaseVersion}`)
  return all.filter((b) => (b.type === 'package' ? keys.has(b.target) : !b.applies_to || keys.has(b.applies_to)))
}
