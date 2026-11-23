import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { themeBootScript } from '@perfect-design/ui/stores/theme-boot'

// Get backend URL from environment or use default
const BACKEND_URL = process.env.VITE_BACKEND_URL || 'http://localhost:8080'
const WS_ORIGIN = process.env.VITE_WS_ORIGIN
const FRONTEND_PORT = parseInt(process.env.VITE_PORT || '5173')

// Applies the saved colour mode before first paint so a dark system never flashes light.
function themeBoot(): Plugin {
  return {
    name: 'theme-boot',
    transformIndexHtml: () => [{ tag: 'script', children: themeBootScript, injectTo: 'head' }],
  }
}

export default defineConfig({
  plugins: [vue(), tailwindcss(), themeBoot()],
  resolve: {
    alias: {
      '@': import.meta.dirname + '/src',
    },
  },
  server: {
    port: FRONTEND_PORT,
    proxy: {
      '/api': {
        target: BACKEND_URL,
        changeOrigin: true,
      },
      '/ws': {
        target: BACKEND_URL.replace('http', 'ws'),
        ws: true,
        changeOrigin: true,
        // A backend with an origin allowlist refuses the dev server origin; set this to an allowed one.
        ...(WS_ORIGIN ? { headers: { Origin: WS_ORIGIN } } : {}),
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
})
