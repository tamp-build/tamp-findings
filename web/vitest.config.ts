import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import path from 'node:path'

// Vitest piggybacks on Vite's transform pipeline — `react()` gives us
// the same JSX/TS handling the dev server uses. Coverage runs via the
// v8 provider (Node's built-in V8 sampler — fast, no instrumentation
// pass). lcov reporter is what build/ ingests into tamp.findings.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts'],
    css: false,
    coverage: {
      provider: 'v8',
      reporter: ['lcov', 'text', 'json-summary'],
      reportsDirectory: '../artifacts/test-results-spa',
      include: ['src/**/*.{ts,tsx}'],
      // Skip generated UI primitives and the entrypoint shim — they're
      // either trivial wrappers or have no logic worth measuring.
      exclude: [
        'src/main.tsx',
        'src/vite-env.d.ts',
        'src/components/ui/**',
        'src/**/*.d.ts',
        'src/**/*.test.{ts,tsx}',
      ],
    },
  },
})
