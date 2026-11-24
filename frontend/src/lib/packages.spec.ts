import { describe, expect, it } from 'vitest'
import { filterPackages, packageRoute } from './packages'
import { PACKAGES } from '@/test/fixtures'

const none = { query: '', registries: [], verdicts: [] } as const

describe('filterPackages', () => {
  it('returns every package for an empty filter', () => {
    expect(filterPackages(PACKAGES, none)).toHaveLength(PACKAGES.length)
  })

  it('matches the query on name and version, ignoring case', () => {
    expect(filterPackages(PACKAGES, { ...none, query: 'LEFT-PAD' }).map((p) => p.id)).toEqual(['npm-1', 'npm-2'])
    expect(filterPackages(PACKAGES, { ...none, query: '2.31' }).map((p) => p.id)).toEqual(['pypi-1'])
  })

  it('matches the release version of a PyPI file row', () => {
    const rows = [{ ...PACKAGES[2], version: 'six-1.17.0.whl', release_version: '1.17.0' }]
    expect(filterPackages(rows, { ...none, query: '1.17.0' })).toHaveLength(1)
  })

  it('treats several registries or verdicts as any-of, and the filters as all-of', () => {
    expect(filterPackages(PACKAGES, { ...none, registries: ['npm', 'go'] })).toHaveLength(3)
    expect(filterPackages(PACKAGES, { ...none, verdicts: ['held', 'pending'] }).map((p) => p.id)).toEqual(['npm-1', 'go-1'])
    expect(filterPackages(PACKAGES, { query: 'left', registries: ['npm'], verdicts: ['held'] }).map((p) => p.id)).toEqual(['npm-1'])
  })
})

describe('packageRoute', () => {
  it('splits a name with slashes into route segments', () => {
    expect(packageRoute({ registry: 'go', name: 'github.com/a/b', version: 'v1.0.0' })).toEqual({
      name: 'package-details',
      params: { registry: 'go', name: ['github.com', 'a', 'b'], version: 'v1.0.0' },
    })
  })
})
