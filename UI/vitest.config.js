//vitest.config.js
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/hooks/vitest.setup.js"],
    include: ["src/**/*.test.js", "src/**/*.test.jsx"],
    testTimeout: 60000, // 60 seconds for PoW tests
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
    },
  },
});
