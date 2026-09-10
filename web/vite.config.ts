import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:8000' } },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 2500,
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined
          if (/[\\/](react|react-dom|react-router|react-router-dom|@tanstack|scheduler)[\\/]/.test(id)) return 'react'
          if (/[\\/](recharts|victory-vendor|d3-[a-z-]+|decimal\.js-light|es-toolkit)[\\/]/.test(id)) return 'charts'
          if (/[\\/]@nivo[\\/]|[\\/]@react-spring[\\/]/.test(id)) return 'nivo'
          return undefined
        },
      },
    },
  },
})
