import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../components/Dashboard.vue'
import PackageList from '../components/PackageList.vue'
import Stats from '../components/Stats.vue'
import BypassManagementPanel from '../components/BypassManagementPanel.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: Dashboard,
    },
    {
      path: '/packages',
      name: 'packages',
      component: PackageList,
    },
    {
      path: '/stats',
      name: 'stats',
      component: Stats,
    },
    {
      path: '/admin/bypasses',
      name: 'bypasses',
      component: BypassManagementPanel,
    },
  ],
})

export default router
