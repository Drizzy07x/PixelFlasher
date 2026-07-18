# Gettext catalogs for the React build

PixelFlasher's gettext PO files remain the translation source of truth. The
React asset export is deterministic and deliberately generated rather than
hand-maintained.

```bash
python scripts/export_gettext_json.py --output-dir build/react-i18n
python scripts/export_gettext_json.py --output-dir build/react-i18n --check
```

The current export contains `en`, `es`, `fr`, `it`, `zh_CN` and `zh_TW`.
Each locale file is a flat UTF-8 JSON object mapping the original `msgid`, or
GNU gettext's `context\u0004msgid` key, to its translation. React-only strings
use the stable context `web.<sourceMessages key>`; no translated strings live
in TypeScript. Empty and fuzzy translations use the source `msgid`, which
matches the fallback behavior of the Python UI. `manifest.json` records the
schema version, fallback locale, message/translation counts and SHA-256 of each
locale file. Per-locale `webMessageCount` and `webTranslatedCount` make key
coverage distinct from real translation coverage.

The current React contract contains 205 messages: 189 use `web.*` context and
16 reuse existing non-contextual gettext entries. Spanish, French, Italian,
Simplified Chinese and Traditional Chinese resolve all 205 to real, non-fuzzy
translations; English is the source/fallback language. Tests require every
`web.*` translation to be non-empty in those five locales and require the exact
same named placeholders (for example `{count}` and `{confirmation}`) as the
English msgid.

The exporter guarantees stable locale/key ordering, LF newlines, no timestamps
and no absolute source paths. It also rejects missing locale keys, duplicates
and plural entries until an explicit plural schema is introduced. That makes a
schema change visible instead of silently losing gettext semantics.

The default output is `build/react-i18n`. A frontend build can generate into a
temporary or bundled asset directory with `--output-dir`; generated artifacts
should not replace the PO sources.

`pnpm build` in `ui/web` runs the exporter and then checks every React msgid
against all six generated catalogs before typechecking or invoking Vite. When
new `sourceMessages` are introduced, maintainers can audit or append empty
fallback entries without touching translations already present:

```bash
python scripts/sync_react_gettext.py
python scripts/sync_react_gettext.py --write
```

Desktop packaging workflows export into `ui/web/public/i18n` before Vite runs,
verify the byte-identical copies in `ui/web/dist/i18n`, and then inspect the
final PyInstaller archive for `index.html`, the manifest and all six locale
files. They also reject module scripts, `import.meta`, remote assets and missing
local references before PyInstaller runs. A successful Vite invocation alone
is therefore not enough to publish an artifact with missing translations or a
bundle that cannot boot from a desktop `file://` WebView.
