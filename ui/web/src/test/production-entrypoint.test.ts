import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const sourceRoot = resolve(process.cwd(), 'src');
const importPattern = /(?:import|export)\s+(?:[^'";]*?\sfrom\s*)?['"](?<static>\.[^'"]+)['"]|import\s*\(\s*['"](?<dynamic>\.[^'"]+)['"]\s*\)/g;

function resolveModule(importer: string, specifier: string): string | null {
  const base = resolve(dirname(importer), specifier);
  for (const candidate of [
    base,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.js`,
    `${base}.jsx`,
    resolve(base, 'index.ts'),
    resolve(base, 'index.tsx'),
  ]) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  return null;
}

function dependencyGraph(entrypoint: string): Set<string> {
  const pending = [resolve(sourceRoot, entrypoint)];
  const visited = new Set<string>();

  while (pending.length) {
    const source = pending.pop()!;
    if (visited.has(source)) continue;
    visited.add(source);

    const contents = readFileSync(source, 'utf8');
    for (const match of contents.matchAll(importPattern)) {
      const specifier = match.groups?.static ?? match.groups?.dynamic;
      if (!specifier) continue;
      const dependency = resolveModule(source, specifier);
      if (dependency && dependency.startsWith(sourceRoot)) pending.push(dependency);
    }
  }

  return new Set([...visited].map((path) => relative(sourceRoot, path).replaceAll('\\', '/')));
}

describe('frontend entrypoint isolation', () => {
  it('keeps the development bridge out of the production dependency graph', () => {
    const production = dependencyGraph('main.tsx');

    expect(production).toContain('bridge.ts');
    expect(production).not.toContain('mockBridge.ts');
  });

  it('installs the development bridge only through the explicit local entrypoint', () => {
    const development = dependencyGraph('main.dev.tsx');
    const source = readFileSync(resolve(sourceRoot, 'main.dev.tsx'), 'utf8');

    expect(development).toContain('mockBridge.ts');
    expect(source).toContain("import { installDevelopmentBridge } from './mockBridge'");
    expect(source).toContain('installDevelopmentBridge();');
  });
});
