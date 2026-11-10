import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard calls /api/*; in development Vite forwards that to FastAPI
// (python -m uvicorn stigwatch.api:app). STIGWATCH_API_URL points it elsewhere.
const target = process.env.STIGWATCH_API_URL || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': target } },
  preview: { proxy: { '/api': target } },
})
