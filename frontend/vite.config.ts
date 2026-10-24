import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/health": "http://127.0.0.1:5000",
      "/csrf-token": "http://127.0.0.1:5000",
      "/register": "http://127.0.0.1:5000",
      "/login": "http://127.0.0.1:5000",
      "/forgot-password": "http://127.0.0.1:5000",
      "/reset-password": "http://127.0.0.1:5000",
      "/auth": "http://127.0.0.1:5000",
      "/invites": "http://127.0.0.1:5000",
      "/logout": "http://127.0.0.1:5000",
      "/me": "http://127.0.0.1:5000",
      "/companies": "http://127.0.0.1:5000",
      "/company": "http://127.0.0.1:5000",
      "/documents": "http://127.0.0.1:5000",
      "/admin": "http://127.0.0.1:5000"
    }
  }
});
