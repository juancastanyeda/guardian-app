import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Forward /api calls to vercel dev (port 3000) when running locally
      '/api': 'http://localhost:3000',
    },
  },
})
