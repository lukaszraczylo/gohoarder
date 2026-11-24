import { describe, expect, it } from 'vitest'
import { bypassesFor, isLive, type Bypass } from './bypass'

function bypass(over: Partial<Bypass>): Bypass {
  return {
    id: 'b',
    type: 'package',
    target: 'npm/left-pad',
    reason: 'r',
    created_by: 'a',
    created_at: '2026-01-01T00:00:00Z',
    expires_at: '2099-01-01T00:00:00Z',
    notify_on_expiry: false,
    active: true,
    ...over,
  }
}

describe('bypassesFor', () => {
  const pkg = { registry: 'npm', name: 'left-pad', version: '1.3.0' }

  it('matches a package bypass by name and by name@version', () => {
    const all = [
      bypass({ id: 'any', target: 'npm/left-pad' }),
      bypass({ id: 'pinned', target: 'npm/left-pad@1.3.0' }),
      bypass({ id: 'other-version', target: 'npm/left-pad@1.2.0' }),
      bypass({ id: 'other-package', target: 'npm/lodash' }),
    ]
    expect(bypassesFor(all, pkg).map((b) => b.id)).toEqual(['any', 'pinned'])
  })

  it('matches a CVE bypass with no scope or a scope on this package', () => {
    const all = [
      bypass({ id: 'global', type: 'cve', target: 'CVE-1' }),
      bypass({ id: 'scoped', type: 'cve', target: 'CVE-2', applies_to: 'npm/left-pad@1.3.0' }),
      bypass({ id: 'elsewhere', type: 'cve', target: 'CVE-3', applies_to: 'npm/lodash' }),
    ]
    expect(bypassesFor(all, pkg).map((b) => b.id)).toEqual(['global', 'scoped'])
  })

  it('keys Go packages by module path, not by cache key', () => {
    const go = { registry: 'go', name: 'github.com/a/b/@v/v1.0.0.zip', version: 'v1.0.0' }
    expect(bypassesFor([bypass({ target: 'go/github.com/a/b@v1.0.0' })], go)).toHaveLength(1)
  })

  it('matches a PyPI release version', () => {
    const py = { registry: 'pypi', name: 'six', version: 'six-1.0.tar.gz', releaseVersion: '1.0' }
    expect(bypassesFor([bypass({ target: 'pypi/six@1.0' })], py)).toHaveLength(1)
  })
})

describe('isLive', () => {
  it('requires active and unexpired', () => {
    const now = Date.parse('2026-06-01T00:00:00Z')
    expect(isLive(bypass({}), now)).toBe(true)
    expect(isLive(bypass({ active: false }), now)).toBe(false)
    expect(isLive(bypass({ expires_at: '2026-01-01T00:00:00Z' }), now)).toBe(false)
  })
})
