import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const webRoot = process.cwd();
const repositoryRoot = resolve(webRoot, '..', '..');
const exporter = resolve(repositoryRoot, 'scripts', 'export_gettext_json.py');
const output = resolve(webRoot, 'public', 'i18n');

if (!existsSync(exporter)) {
  throw new Error(`Gettext exporter is missing: ${exporter}`);
}

const configuredPython = process.env.PIXELFLASHER_PYTHON || process.env.PYTHON;
const candidates = [
  configuredPython ? { command: configuredPython, prefix: [] } : null,
  { command: resolve(repositoryRoot, '.venv', 'Scripts', 'python.exe'), prefix: [] },
  { command: resolve(repositoryRoot, '.venv', 'bin', 'python'), prefix: [] },
  { command: 'python3', prefix: [] },
  { command: 'python', prefix: [] },
  { command: 'py', prefix: ['-3'] },
].filter(Boolean);

let lastError = '';
for (const candidate of candidates) {
  if (candidate.command.includes(resolve(repositoryRoot, '.venv')) && !existsSync(candidate.command)) continue;
  const result = spawnSync(
    candidate.command,
    [...candidate.prefix, exporter, '--locale-dir', resolve(repositoryRoot, 'locale'), '--output-dir', output],
    { cwd: repositoryRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (!result.error && result.status === 0) {
    process.stdout.write(result.stdout || `Exported gettext catalogs to ${output}\n`);
    process.exit(0);
  }
  lastError = result.error?.message || result.stderr || `exit ${result.status}`;
}

throw new Error(`Unable to export gettext catalogs. Configure PIXELFLASHER_PYTHON. ${lastError}`);
