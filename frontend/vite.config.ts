import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// `npm run dev` must reproduce the production topology, or the UI works in one
// and not the other. Production is same-origin (nginx proxies /api/ to the
// backend), so dev proxies it too. The alternative -- pointing the client at
// http://localhost:8000 -- is cross-origin, and the backend ships no CORS
// middleware and no OPTIONS preflight, so it cannot work from a browser.
const API_TARGET = process.env.PROOFOPS_API_TARGET ?? 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
