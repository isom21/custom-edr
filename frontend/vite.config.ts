import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    port: 5173,
    // Vite 5+ rejects Host headers it doesn't recognise as a
    // DNS-rebind defense. We host the dev manager on a tailnet
    // (dev.taila4f9bf.ts.net + 100.111.232.7) so any laptop on
    // the tailnet hits us under that hostname, not localhost. List
    // every name we want to accept; for ad-hoc additions on a
    // running box, set VIGIL_VITE_ALLOWED_HOSTS=foo,bar before
    // `make up`.
    allowedHosts: [
      "localhost",
      "127.0.0.1",
      "dev",
      "dev.taila4f9bf.ts.net",
      "100.111.232.7",
      ...(process.env.VIGIL_VITE_ALLOWED_HOSTS?.split(",").map((s) => s.trim()) ?? []),
    ],
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
