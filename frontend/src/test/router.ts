import { createMemoryHistory } from 'vue-router'
import { createAppRouter } from '@/router'

export async function createTestRouter(initial = '/') {
  const router = createAppRouter(createMemoryHistory())
  await router.push(initial)
  await router.isReady()
  return router
}
