import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ts from 'typescript';

const webRoot = process.cwd();
const sourcePath = resolve(webRoot, 'src', 'i18n.tsx');
const catalogRoot = resolve(webRoot, 'public', 'i18n');
const locales = ['en', 'es', 'fr', 'it', 'zh_CN', 'zh_TW'];

const source = readFileSync(sourcePath, 'utf8');
const tree = ts.createSourceFile(sourcePath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const messages = new Map();

function visit(node) {
  const initializer = node.initializer && ts.isAsExpression(node.initializer) ? node.initializer.expression : node.initializer;
  if (ts.isVariableDeclaration(node) && node.name.getText(tree) === 'sourceMessages' && initializer && ts.isObjectLiteralExpression(initializer)) {
    for (const property of initializer.properties) {
      if (!ts.isPropertyAssignment(property) || !ts.isStringLiteral(property.name) || !ts.isStringLiteral(property.initializer)) continue;
      messages.set(property.name.text, property.initializer.text);
    }
  }
  ts.forEachChild(node, visit);
}
visit(tree);

if (!messages.size) throw new Error('No React sourceMessages were found for gettext verification.');

const failures = [];
for (const locale of locales) {
  const path = resolve(catalogRoot, `${locale}.json`);
  if (!existsSync(path)) {
    failures.push(`${locale}:catalog missing`);
    continue;
  }
  const catalog = JSON.parse(readFileSync(path, 'utf8'));
  for (const [key, msgid] of messages) {
    const contextual = `web.${key}\u0004${msgid}`;
    const compactContext = `${key}\u0004${msgid}`;
    if (!(msgid in catalog) && !(contextual in catalog) && !(compactContext in catalog)) {
      failures.push(`${locale}:${key}:${msgid}`);
    }
  }
}

if (failures.length) {
  const sample = failures.slice(0, 20).map((entry) => `  - ${entry}`).join('\n');
  throw new Error(`React gettext coverage is incomplete (${failures.length} missing entries):\n${sample}`);
}

process.stdout.write(`React gettext coverage passed: ${messages.size} msgids across ${locales.length} locales.\n`);
