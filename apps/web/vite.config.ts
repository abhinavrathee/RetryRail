import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vitest/config';

const useBladeTestDouble = process.env.VITEST === 'true';
const secureMergeAdapter = fileURLToPath(
  new URL('./src/vendor/secure-deep-merge.ts', import.meta.url),
);

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: [
      {
        find: /^ts-deepmerge$/u,
        replacement: secureMergeAdapter,
      },
      ...(useBladeTestDouble
        ? [
          {
            find: '@razorpay/blade/components',
            replacement: fileURLToPath(new URL('./src/test/blade-components.tsx', import.meta.url)),
          },
          {
            find: '@razorpay/blade/tokens',
            replacement: fileURLToPath(new URL('./src/test/blade-tokens.ts', import.meta.url)),
          },
          ]
        : []),
    ],
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    strictPort: true,
  },
  build: {
    // Blade is lazy-loaded as a separate design-system chunk. The stricter
    // per-chunk and entry budgets run immediately after Vite builds.
    chunkSizeWarningLimit: 800,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      thresholds: {
        lines: 80,
        functions: 80,
        statements: 80,
        branches: 75,
      },
    },
  },
});
