import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vitest/config';

const projectRoot = process.cwd();

function readCatalogs() {
  const catalogDirectory = resolve(projectRoot, 'public', 'i18n');
  if (!existsSync(catalogDirectory)) return {};
  return Object.fromEntries(
    readdirSync(catalogDirectory)
      .filter((name) => /^(en|es|fr|it|zh_CN|zh_TW)\.json$/.test(name))
      .map((name) => [name.replace(/\.json$/, ''), JSON.parse(readFileSync(resolve(catalogDirectory, name), 'utf8'))]),
  );
}

function staticWebViewShell(): Plugin {
  return {
    name: 'pixelflasher-static-webview-shell',
    apply: 'build',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'index.html',
        source: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <meta name="theme-color" content="#080d18">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'">
    <title>PixelFlasher</title>
    <link rel="stylesheet" href="./assets/pixelflasher.css">
  </head>
  <body>
    <div id="root"></div>
    <script src="./assets/pixelflasher.js"></script>
  </body>
</html>
`,
      });
    },
  };
}

export default defineConfig(({ command }) => ({
  base: './',
  plugins: [react(), ...(command === 'build' ? [staticWebViewShell()] : [])],
  define: {
    __PIXELFLASHER_CATALOGS__: JSON.stringify(readCatalogs()),
    'process.env.NODE_ENV': JSON.stringify(command === 'build' ? 'production' : 'development'),
  },
  server: {
    host: '0.0.0.0',
    allowedHosts: ['terminal.local', 'localhost'],
  },
  preview: {
    host: '0.0.0.0',
    allowedHosts: ['terminal.local', 'localhost'],
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    sourcemap: false,
    lib: {
      entry: resolve(projectRoot, 'src', 'main.tsx'),
      name: 'PixelFlasherWeb',
      formats: ['iife'],
      fileName: () => 'pixelflasher.js',
      cssFileName: 'pixelflasher',
    },
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
        entryFileNames: 'assets/pixelflasher.js',
        assetFileNames: (assetInfo) => assetInfo.name?.endsWith('.css')
          ? 'assets/pixelflasher.css'
          : 'assets/[name][extname]',
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
    restoreMocks: true,
  },
}));
