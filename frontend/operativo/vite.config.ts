/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// El bundle lo sirve motor-soc (FastAPI StaticFiles) en /operativo, mismo
// origen que la API: sin CORS y con el JWT solo en memoria.
//
// Dev server: SIN proxy por defecto a propósito. Apuntarlo al motor real
// expondría botones que ejecutan bloqueos reales (RESPONSE_MODE=enforce).
// Para probar contra un backend local: VITE_DEV_API_TARGET=http://127.0.0.1:8000
const devTarget = process.env.VITE_DEV_API_TARGET

export default defineConfig({
  base: '/operativo/',
  plugins: [react()],
  build: {
    outDir: '../../motor/static/operativo',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: devTarget ? { proxy: { '/api': { target: devTarget, changeOrigin: true } } } : {},
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
})
