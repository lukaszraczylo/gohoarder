import { computed, ref } from 'vue'

const STORAGE_KEY = 'admin_api_key'

const key = ref(typeof localStorage === 'undefined' ? '' : (localStorage.getItem(STORAGE_KEY) ?? ''))

/** The admin API key the dashboard sends with admin calls; kept in localStorage. */
export function useAdminKey() {
  function load() {
    key.value = localStorage.getItem(STORAGE_KEY) ?? ''
  }
  function save(value: string) {
    key.value = value
    localStorage.setItem(STORAGE_KEY, value)
  }
  function clear() {
    key.value = ''
    localStorage.removeItem(STORAGE_KEY)
  }
  const headers = computed(() => ({ Authorization: `Bearer ${key.value}` }))
  return { key, headers, load, save, clear }
}
