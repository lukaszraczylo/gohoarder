import { describe, expect, it } from 'vitest'
import { packageRoute } from './packages'

describe('packageRoute', () => {
  it('splits a name with slashes into route segments', () => {
    expect(packageRoute({ registry: 'go', name: 'github.com/a/b', version: 'v1.0.0' })).toEqual({
      name: 'package-details',
      params: { registry: 'go', name: ['github.com', 'a', 'b'], version: 'v1.0.0' },
    })
  })
})
