import { resolve } from 'node:path';
import { defineConfig } from 'vite';

const projectRoot = process.cwd();

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: false,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    sourcemap: false,
    lib: {
      entry: resolve(projectRoot, 'src', 'adbTerminalRuntime.ts'),
      name: 'PixelFlasherTerminalRuntime',
      formats: ['iife'],
      fileName: () => 'adb-terminal.js',
      cssFileName: 'adb-terminal',
    },
    rollupOptions: {
      output: {
        entryFileNames: 'assets/adb-terminal.js',
        assetFileNames: (assetInfo) => assetInfo.name?.endsWith('.css')
          ? 'assets/adb-terminal.css'
          : 'assets/[name][extname]',
      },
    },
  },
});
