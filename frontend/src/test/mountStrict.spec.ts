import { describe, expect, it } from 'vitest'
import { defineComponent, h } from 'vue'
import { Input } from '@perfect-design/ui'
import { mountStrict } from './mountStrict'

describe('mountStrict', () => {
  it('reports a library contract violation, so an empty list in a smoke test means something', async () => {
    const Unnamed = defineComponent({ render: () => h(Input) })
    const { problems, restore } = await mountStrict(Unnamed)
    restore()
    expect(problems.length).toBeGreaterThan(0)
    expect(problems.join(' ')).toMatch(/accessible name/i)
  })
})
