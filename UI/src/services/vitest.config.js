import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    globals: true,
  },
  // Stub out import.meta.env (used by apiClient.js)
  define: {
    'import.meta.env': JSON.stringify({ VITE_API_BASE_URL: 'https://api.example.com' }),
  },
})
