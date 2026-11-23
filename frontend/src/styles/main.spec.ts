// @vitest-environment node
import { describe, expect, it } from 'vitest'
import css from './main.css?raw'
import { librarySources } from '../../scripts/library-sources.mjs'

const root = new URL('../..', import.meta.url).pathname

describe('main.css', () => {
  it('imports the library theme and the workbench pack', () => {
    expect(css).toContain('@import "@perfect-design/ui/theme.css"')
    expect(css).toContain('@import "@perfect-design/ui/packs/workbench.css"')
  })

  it('scans only the library directories the app imports (run `pnpm sources` after changing imports)', () => {
    const declared = css.split('\n').filter((line: string) => line.startsWith('@source '))
    expect(declared).toEqual(librarySources(root))
    expect(css).not.toMatch(/@source "[^"]*\/dist"/)
  })

  it('loads the Plex faces as Latin woff2 only', () => {
    const urls = [...css.matchAll(/url\("([^"]+)"\)/g)].map((m) => m[1])
    expect(urls.length).toBe(4)
    for (const url of urls) expect(url).toMatch(/-latin-\d{3}-normal\.woff2$/)
  })

  it('shares one header height token with the scroll offset', () => {
    expect(css).toMatch(/--header-h:/)
    expect(css).toMatch(/scroll-padding-top:\s*calc\(var\(--header-h\)/)
  })
})
