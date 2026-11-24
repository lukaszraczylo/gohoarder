import { createRouter, createWebHistory, type LocationQuery, type RouteRecordRaw, type RouterHistory } from 'vue-router'

/** Keeps the query string of an old URL when it moves to a tab of the Security page. */
function toSecurityTab(tab: string) {
  return (to: { query: LocationQuery }) => ({ path: '/security', query: { ...to.query, tab } })
}

export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    name: 'overview',
    component: () => import('../components/Overview.vue'),
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
    path: '/security',
    name: 'security',
    component: () => import('../components/Security.vue'),
  },
  {
    path: '/vulnerable-packages',
    name: 'vulnerable-packages',
    redirect: toSecurityTab('allowed'),
  },
  {
    path: '/blocked-packages',
    name: 'blocked-packages',
    redirect: toSecurityTab('held'),
  },
  {
    path: '/stats',
    name: 'insights',
    component: () => import('../components/Insights.vue'),
  },
  {
    path: '/admin/bypasses',
    name: 'bypasses',
    component: () => import('../components/BypassManagementPanel.vue'),
  },
  {
    path: '/admin/system',
    name: 'system',
    component: () => import('../components/System.vue'),
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
