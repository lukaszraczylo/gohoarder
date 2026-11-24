import type { RouteLocationRaw } from 'vue-router'
import type { Package } from '@/stores/packages'
import { displayVersion } from '@/lib/format'
import { verdictOf, type Verdict } from '@/lib/verdict'

export interface PackageFilters {
  query: string
  /** Empty means every registry. */
  registries: readonly string[]
  /** Empty means every verdict. */
  verdicts: readonly Verdict[]
}

/** Case-insensitive match on name, version or release version, as the server search does. */
function matchesQuery(pkg: Package, query: string): boolean {
  const needle = query.trim().toLowerCase()
  if (!needle) return true
  return [pkg.name, pkg.version, pkg.release_version ?? ''].some((field) => field.toLowerCase().includes(needle))
}

export function filterPackages(packages: readonly Package[], filters: PackageFilters): Package[] {
  return packages.filter(
    (pkg) =>
      matchesQuery(pkg, filters.query) &&
      (filters.registries.length === 0 || filters.registries.includes(pkg.registry)) &&
      (filters.verdicts.length === 0 || filters.verdicts.includes(verdictOf(pkg))),
  )
}

/** Route of a package's full page. A name with slashes becomes the repeatable `name` segments. */
export function packageRoute(pkg: Pick<Package, 'registry' | 'name' | 'version'>): RouteLocationRaw {
  return { name: 'package-details', params: { registry: pkg.registry, name: pkg.name.split('/'), version: pkg.version } }
}

export function packageLabel(pkg: Package): string {
  return `${pkg.name} ${displayVersion(pkg)}`
}
