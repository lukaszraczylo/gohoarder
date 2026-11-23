import { configureStrictMode } from '@perfect-design/ui'
import { flushPromises, mount, type ComponentMountingOptions } from '@vue/test-utils'
import { vi } from 'vitest'
import type { Component } from 'vue'

/**
 * Mounts under strict mode 'throw' and returns every Vue warning, Vue error and library ContractError seen,
 * so a smoke test can assert the list is empty. The library runs its contract checks from async onMounted hooks.
 */
export async function mountStrict(component: Component, options: ComponentMountingOptions<any> = {}) {
  configureStrictMode('throw')
  const problems: string[] = []
  const record = (kind: string) => (err: unknown) => {
    problems.push(`${kind}: ${err instanceof Error ? err.message : String(err)}`)
  }
  const warn = vi.spyOn(console, 'warn').mockImplementation((...args) => record('warn')(args.join(' ')))
  const error = vi.spyOn(console, 'error').mockImplementation((...args) => record('error')(args.join(' ')))

  const wrapper = mount(component, {
    attachTo: document.body,
    ...options,
    global: {
      ...options.global,
      config: { errorHandler: record('error'), warnHandler: record('warn') },
    },
  })
  await flushPromises()
  await new Promise((resolve) => setTimeout(resolve, 0))
  await flushPromises()

  const restore = () => {
    wrapper.unmount()
    warn.mockRestore()
    error.mockRestore()
  }
  return { wrapper, problems, restore }
}
