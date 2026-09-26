import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// Dev server proxies /api and /health to the FastAPI backend on :8000
// so the frontend never needs the backend URL hardcoded.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // Allow access via public tunnels (Cloudflare/ngrok rewrite the Host header).
    allowedHosts: ['.trycloudflare.com', '.ngrok.io', '.ngrok-free.app', '.ngrok.dev'],
    proxy: {
      '/alerts': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
    },
  },
})