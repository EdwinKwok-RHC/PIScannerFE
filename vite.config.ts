/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// Single source of truth for security headers (copied to dist/ by Vite).
import swaConfig from './public/staticwebapp.config.json' with { type: 'json' };

// `vite preview` serves the production build with exactly the same security
// headers as Azure Static Web Apps, so CSP behaviour can be verified locally.
// The dev server intentionally does not apply them (Vite HMR injects inline
// styles and uses a websocket).
const securityHeaders: Record<string, string> = swaConfig.globalHeaders;

export default defineConfig({
  plugins: [react()],
  build: {
    // Never inline assets as data: URIs into JS/CSS; everything ships as files
    // served from 'self'.
    assetsInlineLimit: 0,
    sourcemap: false,
    // Fluent UI accounts for most of the single bundle (~180 kB gzip). One
    // chunk keeps the CSP simple and avoids extra requests.
    chunkSizeWarningLimit: 700,
  },
  preview: {
    headers: securityHeaders,
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
  },
});
