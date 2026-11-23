import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    // main.spec.ts reads main.css as text; vitest otherwise replaces stylesheets with an empty string.
    css: { include: [/main\.css/] },
  },
  resolve: {
    alias: {
      '@': import.meta.dirname + '/src',
    },
  },
})
