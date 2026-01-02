import { createRouter, createWebHistory } from 'vue-router'
import Dashboard from '../components/Dashboard.vue'
import PackageList from '../components/PackageList.vue'
import PackageDetails from '../components/PackageDetails.vue'
import Stats from '../components/Stats.vue'
import VulnerablePackages from '../components/VulnerablePackages.vue'
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
      path: '/packages/:registry?',
      name: 'packages',
      component: PackageList,
      props: true,
    },
    {
      // Separate route for package details - supports names with slashes (Go packages)
      path: '/package/:registry/:name+/:version',
      name: 'package-details',
      component: PackageDetails,
      props: true,
    },
    {
      path: '/stats',
      name: 'stats',
      component: Stats,
    },
    {
      path: '/vulnerable-packages',
      name: 'vulnerable-packages',
      component: VulnerablePackages,
    },
    {
      path: '/admin/bypasses',
      name: 'bypasses',
      component: BypassManagementPanel,
    },
  ],
})

export default router
