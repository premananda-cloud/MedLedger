// vitest.config.js
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    testTimeout: 60000, // Increase to 60 seconds
    hookTimeout: 60000,
    teardownTimeout: 60000,
    include: ["tests/**/*.test.js"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      include: ["modules/**/*.js", "orchestrator/**/*.js"],
      exclude: ["**/*.test.js", "**/node_modules/**", "tests/**"],
    },
  },
});
