import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { JSDOM, VirtualConsole } from 'jsdom';

const root = process.cwd();
const htmlPath = resolve(root, 'dist', 'index.html');
const scriptPath = resolve(root, 'dist', 'assets', 'pixelflasher.js');
const cssPath = resolve(root, 'dist', 'assets', 'pixelflasher.css');
const terminalScriptPath = resolve(root, 'dist', 'assets', 'adb-terminal.js');
const terminalCssPath = resolve(root, 'dist', 'assets', 'adb-terminal.css');

for (const path of [htmlPath, scriptPath, cssPath, terminalScriptPath, terminalCssPath]) {
  if (!existsSync(path)) throw new Error(`Static WebView artifact missing: ${path}`);
}

const html = readFileSync(htmlPath, 'utf8');
const script = readFileSync(scriptPath, 'utf8');
if (script.includes('PixelFlasherTerminalRuntime=')) {
  throw new Error('The initial WebView bundle must not inline the on-demand ADB terminal runtime.');
}

const forbiddenDevelopmentBridgeMarkers = [
  'MOCK_COMMAND_ERROR',
  'C:\\\\mock\\\\Magisk.apk',
];

for (const marker of forbiddenDevelopmentBridgeMarkers) {
  if (script.includes(marker)) {
    throw new Error(`Production WebView bundle contains the development bridge marker: ${marker}`);
  }
}

if (/type\s*=\s*["']module["']/i.test(html)) {
  throw new Error('dist/index.html must use a classic script for file:// WebView loading.');
}
if (/\bimport\.meta\b/.test(html) || /\bimport\.meta\b/.test(script)) {
  throw new Error('The static WebView bundle must not contain import.meta.');
}
if (/\bprocess\.(?:env|cwd|platform)\b/.test(script)) {
  throw new Error('The static WebView bundle must not depend on the Node.js process global.');
}
if (!/<script\s+src=["']\.\/assets\/pixelflasher\.js["']><\/script>/i.test(html)) {
  throw new Error('dist/index.html does not reference the expected classic IIFE bundle.');
}
if (!/<link\s+rel=["']stylesheet["']\s+href=["']\.\/assets\/pixelflasher\.css["']>/i.test(html)) {
  throw new Error('dist/index.html does not reference the static stylesheet.');
}
const csp = html.match(/<meta\s+http-equiv=["']Content-Security-Policy["'][^>]*>/i)?.[0];
if (!csp || !/\bconnect-src\s+'none'(?:\s*;|\s*["'])/i.test(csp)) {
  throw new Error("Production WebView CSP must disable browser networking with connect-src 'none'.");
}

const browserErrors = [];
const virtualConsole = new VirtualConsole();
virtualConsole.on('jsdomError', (error) => browserErrors.push(error));
virtualConsole.on('error', (error) => browserErrors.push(error instanceof Error ? error : new Error(String(error))));

const dom = await JSDOM.fromFile(htmlPath, {
  resources: 'usable',
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  virtualConsole,
  beforeParse(window) {
    window.structuredClone = globalThis.structuredClone;
  },
});

await new Promise((resolveLoad, rejectLoad) => {
  const timeout = setTimeout(() => rejectLoad(new Error('Timed out executing the classic WebView bundle.')), 5_000);
  const finish = () => {
    clearTimeout(timeout);
    resolveLoad();
  };
  if (dom.window.document.readyState === 'complete') finish();
  else dom.window.addEventListener('load', finish, { once: true });
});

await new Promise((resolveRender) => setTimeout(resolveRender, 75));
const heading = dom.window.document.querySelector('#root h1');
if (!heading || !heading.textContent?.trim()) {
  const detail = browserErrors.map((error) => error.stack || error.message).join('\n');
  throw new Error(`Classic WebView bundle executed without rendering the React shell.\n${detail}`);
}
if (browserErrors.length) {
  const detail = browserErrors.map((error) => error.stack || error.message).join('\n');
  throw new Error(`Classic WebView runtime emitted errors.\n${detail}`);
}
dom.window.close();

process.stdout.write(`Static WebView dist contract passed; rendered “${heading.textContent.trim()}”.\n`);
