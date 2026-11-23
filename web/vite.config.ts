import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';
import { integrityPlugin } from './scripts/vite-integrity';

const src = fileURLToPath(new URL('./src', import.meta.url));

// The isolation headers the server sends (design: Security, "Web vault hardening"), so `vite dev`
// and `vite preview` fail on the same things production would. The CSP is left out of the dev
// server: it injects inline scripts for hot reload.
const isolation = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

export default defineConfig(({ mode }) => ({
  plugins: [react(), integrityPlugin()],
  resolve: {
    alias:
      mode === 'test'
        ? [
            // Unit tests run against a deterministic fake of the app's crypto port.
            { find: /^@\/crypto-port$/, replacement: `${src}/test/fake-crypto.ts` },
            // The worker constructors use Vite's `?worker&url`, which only a real build resolves.
            { find: /^@\/(crypto|import)\/spawn$/, replacement: `${src}/test/spawn-stub.ts` },
            { find: /^@\//, replacement: `${src}/` },
          ]
        : [{ find: /^@\//, replacement: `${src}/` }],
  },
  build: {
    target: 'es2023',
    outDir: 'dist',
    emptyOutDir: true,
    // Hashed names under assets/ are Vite's default. None of them may be inlined as a data: URI,
    // because the CSP allows fonts from 'self' only.
    assetsInlineLimit: 0,
    // Route chunks come from the dynamic imports in src/app/router.tsx, one per route.
    cssCodeSplit: true,
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
  server: {
    headers: isolation,
    proxy: { '/kem': { target: 'http://localhost:8000', changeOrigin: false, ws: true } },
  },
  preview: { headers: isolation },
  test: {
    environment: 'jsdom',
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
  },
}));
