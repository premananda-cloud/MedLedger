// vite.config.js
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],

  server: {
    port: 3000,
    open: true,
    // SharedWorker requires same-origin — no special headers needed for dev
  },

  build: {
    outDir: "dist",
    sourcemap: true,
    target: "esnext",
  },

  // ── Worker bundling ───────────────────────────────────────────
  // format: "iife" produces a classic script bundle (no ES module syntax).
  // Required because Firefox 89–113 does not support `import` inside Workers.
  // The Worker source can still use ES imports — Vite transforms them.
  // Chrome and Edge handle both "es" and "iife"; Firefox needs "iife".
  worker: {
    format: "iife",
  },

  optimizeDeps: {
    include: ["libsodium-wrappers-sumo"],
    esbuildOptions: {
      target: "esnext",
    },
  },
});
