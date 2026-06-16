//vite.config.js
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    open: true,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    target: "esnext",
  },
  optimizeDeps: {
    include: ["libsodium-wrappers-sumo"],
    esbuildOptions: {
      target: "esnext",
    },
  },
  resolve: {
    // Remove the alias completely or comment it out
    // alias: {
    //   'libsodium-wrappers-sumo': 'libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.js'
    // }
  },
});
