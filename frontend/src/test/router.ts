import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { defineComponent, h } from 'vue'

const Stub = defineComponent({ render: () => h('div') })

export const ROUTE_PATHS = [
  '/',
  '/packages/:registry?',
  '/package/:registry/:name+/:version',
  '/stats',
  '/vulnerable-packages',
  '/blocked-packages',
  '/admin/bypasses',
]

export async function createTestRouter(initial = '/'): Promise<Router> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: ROUTE_PATHS.map((path) => ({ path, component: Stub })),
  })
  await router.push(initial)
  await router.isReady()
  return router
}
