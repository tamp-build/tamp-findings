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
      //
      // changeOrigin:false preserves the browser's Host header so the
      // OAuth handler builds redirect_uri from the :5173 origin (not
      // :5080). Cookie middleware also scopes the auth cookie to :5173
      // for the same reason, which is what we want — the SPA sees it
      // as same-origin.
      '/api': {
        target: 'http://localhost:5080',
        changeOrigin: false,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
      // /auth/* is the OAuth + session surface. It is proxied without
      // rewrite so the URL the browser sees matches the URL the API
      // listens on — necessary so the OAuth redirect_uri we register
      // with GitHub (http://localhost:5173/auth/github/callback) is
      // the same URL the API actually handles.
      '/auth': {
        target: 'http://localhost:5080',
        changeOrigin: false,
      },
    },
  },
})
