import { createRouter, createWebHistory, type RouteRecordRaw, type RouterHistory } from 'vue-router'

export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'dashboard',
    component: () => import('../components/Dashboard.vue'),
  },
  {
    path: '/packages/:registry?',
    name: 'packages',
    component: () => import('../components/PackageList.vue'),
    props: true,
  },
  {
    // Separate route for package details - supports names with slashes (Go packages)
    path: '/package/:registry/:name+/:version',
    name: 'package-details',
    component: () => import('../components/PackageDetails.vue'),
    props: true,
  },
  {
    path: '/stats',
    name: 'stats',
    component: () => import('../components/Stats.vue'),
  },
  {
    path: '/vulnerable-packages',
    name: 'vulnerable-packages',
    component: () => import('../components/VulnerablePackages.vue'),
  },
  {
    path: '/blocked-packages',
    name: 'blocked-packages',
    component: () => import('../components/VulnerablePackages.vue'),
  },
  {
    path: '/admin/bypasses',
    name: 'bypasses',
    component: () => import('../components/BypassManagementPanel.vue'),
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('../components/NotFound.vue'),
  },
]

export function createAppRouter(history: RouterHistory = createWebHistory()) {
  return createRouter({ history, routes })
}

export default createAppRouter()
