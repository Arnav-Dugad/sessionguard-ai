import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

const backendPort = process.env.VITE_BACKEND_PORT || "8000";
const target = `http://127.0.0.1:${backendPort}`;

// The dev server proxies /api and /ws to FastAPI so the browser treats the app and API as
// same-origin. That keeps session cookies first-party and avoids permissive CORS in the demo.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": { target, changeOrigin: true },
      "/ws": { target, ws: true, changeOrigin: true },
    },
  },
});
