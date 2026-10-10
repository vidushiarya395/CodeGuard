import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// CodeGuard uses ports 8100 (API) and 5180 (web) so it does not clash with other
// local projects that often use 8000 and 5173.
const API_URL = process.env.CODEGUARD_API_URL ?? 'http://127.0.0.1:8100'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    host: '127.0.0.1',
    port: 5180,
    strictPort: true,
    // Send /api calls to the FastAPI backend during development.
    proxy: { '/api': API_URL },
  },
  preview: {
    host: '127.0.0.1',
    port: 5180,
    strictPort: true,
    proxy: { '/api': API_URL },
  },
})
