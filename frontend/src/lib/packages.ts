import type { RouteLocationRaw } from 'vue-router'
import type { Package } from '@/stores/packages'
import { displayVersion } from '@/lib/format'

/** Route of a package's full page. A name with slashes becomes the repeatable `name` segments. */
export function packageRoute(pkg: Pick<Package, 'registry' | 'name' | 'version'>): RouteLocationRaw {
  return { name: 'package-details', params: { registry: pkg.registry, name: pkg.name.split('/'), version: pkg.version } }
}

export function packageLabel(pkg: Package): string {
  return `${pkg.name} ${displayVersion(pkg)}`
}
