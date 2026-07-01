import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Ports: frontend on 61020, backend on 61020 + 1 = 61021 (keep the +1 convention).
const FRONTEND_PORT = 61020;
const BACKEND_PORT = FRONTEND_PORT + 1;

// The viewer reads the markdown dictionary from the sibling `vuln_search/catalog/`
// directory (one level up). `fs.allow: ['..']` lets Vite read those files; the app
// never writes to them — it only renders them (see ARCHITECTURE.md, "content source").
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: FRONTEND_PORT,
    strictPort: true,
    fs: { allow: [".."] },
    // Future pillar tabs (Agent Console, Defense, Labs) call the backend API here.
    // `/api/runs` on the frontend → `/runs` on the backend.
    proxy: {
      "/api": {
        target: `http://localhost:${BACKEND_PORT}`,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  preview: {
    port: FRONTEND_PORT,
    strictPort: true,
  },
});
