import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/hooks/vitest.setup.js'],
    include: ['src/**/*.test.js', 'src/**/*.test.jsx'],
    testTimeout: 30000, // Increase global timeout to 30 seconds
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
    },
  },
});
