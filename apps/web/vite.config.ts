// Static browser build and cross-origin isolation headers required by Wasm
// pthreads. Development and preview use the same isolation contract.

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Resource-Policy": "same-origin",
      // Vite injects an inline React-refresh preamble and evaluates transformed
      // modules only in development. Production preview below intentionally
      // omits both allowances and is the policy deployed with static assets.
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=(), serial=(), payment=()"
    }
  },
  preview: {
    headers: {
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), usb=(), serial=(), payment=()"
    }
  },
  build: {
    rollupOptions: {
      output: {
        // React Flow and xterm are independent, stable UI subsystems. Splitting
        // them avoids a monolithic startup chunk without changing the rendered
        // layout or moving packet-runtime code onto the UI thread.
        manualChunks(id) {
          if (id.includes("@xyflow") || id.includes("d3-")) return "topology";
          if (id.includes("@xterm")) return "terminal";
          if (id.includes("node_modules/react")) return "react";
          return undefined;
        }
      }
    }
  }
});
