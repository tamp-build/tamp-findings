import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    // host: true makes Vite listen on all interfaces (0.0.0.0) so a
    // remote machine on the LAN can hit the dev SPA. Restrict back to
    // localhost in deployments where exposure isn't intended.
    host: true,
    port: 5173,
    proxy: {
      // Forward API calls to the .NET host during dev. Vite proxies the
      // request server-side, so the browser always sees same-origin —
      // no CORS hop needed for the SPA's own /api/* calls.
      '/api': {
        target: 'http://localhost:5080',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
})
