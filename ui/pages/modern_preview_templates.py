"""Static local HTML/CSS templates for Modern UI surfaces."""

from __future__ import annotations

from html import escape

from constants import VERSION
from ui.pages.modern_action_bridge import action_url
from ui.pages.modern_preview_copy import NAV_ITEMS, SAFETY_BOUNDARY_LINES
from ui.pages.modern_readonly_state import ModernReadonlyState


DEFAULT_STATUS_MESSAGE = "Ready"


def render_preview_html(
    page: str,
    state: ModernReadonlyState,
    version: str = VERSION,
    status_message: str = DEFAULT_STATUS_MESSAGE,
    status_tone: str = "safe",
) -> str:
    page_key = _normalize_page(page)
    return _document(
        title=_page_title(page_key),
        body=f"""
        <div class="app-shell" data-active-page="{escape(page_key)}">
          {_sidebar(page_key, version)}
          <main class="main">
            {_topbar(page_key)}
            {_page_body(page_key, state, version)}
            {_status_bar(version, status_message, status_tone)}
          </main>
        </div>
        """,
    )


def _document(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
{_css()}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def _css() -> str:
    return """
:root {
  --bg: #070b12;
  --bg-soft: #0b111c;
  --sidebar: #0d1524;
  --panel: #111a28;
  --panel-2: #172131;
  --panel-3: #1b283a;
  --border: #263448;
  --border-soft: rgba(118, 153, 197, .18);
  --text: #f5f7fb;
  --muted: #a8b4c7;
  --soft: #d7deea;
  --blue: #2f8cff;
  --cyan: #37b9ff;
  --purple: #7a4dff;
  --green: #42df5b;
  --yellow: #ffc928;
  --red: #ff6868;
  --shadow: 0 22px 52px rgba(0, 0, 0, .40);
  --shadow-soft: 0 12px 28px rgba(0, 0, 0, .25);
  --radius: 8px;
  --radius-sm: 6px;
  --radius-lg: 12px;
}
* { box-sizing: border-box; }
html, body {
  width: 100%;
  height: 100%;
  margin: 0;
  overflow: hidden;
}
body {
  background:
    radial-gradient(circle at 82% 0%, rgba(47, 140, 255, .11), transparent 24%),
    radial-gradient(circle at 28% 100%, rgba(122, 77, 255, .08), transparent 28%),
    var(--bg);
  color: var(--text);
  font-family: "Segoe UI", Arial, sans-serif;
  letter-spacing: 0;
}
.app-shell {
  height: 100vh;
  min-height: 0;
  overflow: hidden;
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  background:
    linear-gradient(180deg, rgba(255, 255, 255, .025), transparent 22%),
    linear-gradient(180deg, #080d16 0%, #070b12 100%);
}
.sidebar {
  background:
    linear-gradient(180deg, rgba(47, 140, 255, .075), transparent 42%),
    linear-gradient(180deg, var(--sidebar) 0%, #0a101a 100%);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 22px 18px 16px;
  gap: 10px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 8px 10px 22px;
  border-bottom: 1px solid rgba(118, 153, 197, .16);
}
.logo-mark {
  width: 44px;
  height: 44px;
  display: grid;
  place-items: center;
  border-radius: 12px;
  background:
    linear-gradient(135deg, rgba(255, 255, 255, .22), transparent 38%),
    linear-gradient(135deg, var(--blue), var(--purple));
  color: white;
  font-weight: 800;
  box-shadow: 0 10px 28px rgba(47, 140, 255, .28);
}
.brand-title { font-size: 17px; font-weight: 800; line-height: 1.2; }
.brand-subtitle { color: var(--muted); font-size: 12px; margin-top: 3px; }
.beta {
  color: var(--cyan);
  font-size: 11px;
  font-weight: 800;
  border: 1px solid rgba(55, 185, 255, .24);
  background: rgba(47, 140, 255, .12);
  border-radius: 999px;
  padding: 4px 8px;
  margin-left: 8px;
}
.nav { display: flex; flex-direction: column; gap: 6px; padding-top: 8px; }
.nav-item {
  display: grid;
  grid-template-columns: 34px 1fr;
  align-items: center;
  gap: 8px;
  min-height: 52px;
  padding: 8px 12px;
  border-radius: var(--radius-lg);
  color: var(--soft);
  border: 1px solid transparent;
  text-decoration: none;
  transition: background .14s ease, border-color .14s ease, transform .14s ease;
}
.nav-item:hover { border-color: rgba(47, 140, 255, .28); background: rgba(47, 140, 255, .08); transform: translateX(1px); }
.nav-item.active {
  color: white;
  background: linear-gradient(90deg, rgba(47, 140, 255, .24), rgba(122, 77, 255, .12));
  border-color: rgba(47, 140, 255, .42);
  box-shadow: inset 3px 0 0 var(--blue), 0 12px 24px rgba(47, 140, 255, .10);
}
.nav-icon {
  width: 28px;
  height: 28px;
  display: grid;
  place-items: center;
  color: var(--blue);
}
.nav-icon svg { width: 21px; height: 21px; stroke-width: 2.1; }
.nav-title { font-size: 14px; font-weight: 700; }
.nav-detail { color: var(--muted); font-size: 12px; margin-top: 2px; }
.mode-card {
  margin-top: auto;
  background:
    linear-gradient(135deg, rgba(47, 140, 255, .16), rgba(122, 77, 255, .10)),
    rgba(255, 255, 255, .035);
  border: 1px solid rgba(47, 140, 255, .22);
  border-radius: var(--radius-lg);
  padding: 14px;
  box-shadow: var(--shadow-soft);
}
.mode-card h3 { margin: 0 0 8px; color: var(--cyan); font-size: 14px; }
.mode-card p { margin: 0; color: var(--soft); font-size: 12px; line-height: 1.45; }
.main {
  min-width: 0;
  min-height: 0;
  display: grid;
  grid-template-rows: auto 1fr auto;
  padding: 24px 28px 12px;
  gap: 14px;
  overflow: hidden;
}
.topbar {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 18px;
  padding-bottom: 2px;
}
.title h1 { margin: 0; font-size: 29px; line-height: 1.1; font-weight: 850; }
.title p { margin: 8px 0 0; color: var(--muted); font-size: 14px; }
.top-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
.badge {
  color: var(--cyan);
  background: rgba(47, 140, 255, .12);
  border: 1px solid rgba(47, 140, 255, .22);
  border-radius: 999px;
  padding: 6px 10px;
  font-size: 11px;
  font-weight: 800;
  text-transform: uppercase;
  white-space: nowrap;
}
.badge.yellow { color: var(--yellow); background: rgba(255, 201, 40, .12); border-color: rgba(255, 201, 40, .22); }
.badge.green { color: var(--green); background: rgba(66, 223, 91, .12); border-color: rgba(66, 223, 91, .22); }
.toggle {
  display: flex;
  gap: 4px;
  padding: 4px;
  border: 1px solid var(--border);
  background: rgba(255, 255, 255, .03);
  border-radius: 10px;
}
.toggle span { color: var(--muted); padding: 8px 12px; border-radius: 8px; font-size: 13px; }
.toggle .on { color: white; background: rgba(255, 255, 255, .07); }
.content {
  min-height: 0;
  overflow-x: hidden;
  overflow-y: auto;
  padding: 2px 4px 2px 0;
  scrollbar-width: thin;
  scrollbar-color: rgba(76, 111, 155, .36) transparent;
}
.content::-webkit-scrollbar { width: 6px; height: 6px; }
.content::-webkit-scrollbar-track { background: transparent; }
.content::-webkit-scrollbar-thumb { background: rgba(76, 111, 155, .34); border-radius: 999px; }
.dashboard-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(360px, .85fr);
  grid-template-rows: auto auto;
  gap: 16px;
  align-items: start;
}
.lower-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
  margin-top: 14px;
}
.card {
  position: relative;
  overflow: hidden;
  background:
    linear-gradient(145deg, rgba(255, 255, 255, .045), transparent 42%),
    linear-gradient(145deg, rgba(23, 33, 49, .98), rgba(13, 21, 34, .98));
  border: 1px solid rgba(118, 153, 197, .20);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow);
  padding: 18px;
  min-width: 0;
}
.card::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  pointer-events: none;
  background: linear-gradient(180deg, rgba(255, 255, 255, .07), transparent 34%);
  opacity: .55;
}
.card > * { position: relative; z-index: 1; }
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 15px;
}
.card h2, .card h3 { margin: 0; font-size: 17px; }
.card h3 { font-size: 15px; }
.card-subtitle { color: var(--muted); margin-top: 4px; font-size: 12px; line-height: 1.35; }
.muted { color: var(--muted); }
.device-card { min-height: 320px; }
.device-body { display: grid; grid-template-columns: 210px minmax(0, 1fr); gap: 22px; align-items: center; }
.device-visual {
  width: 194px;
  height: 238px;
  position: relative;
  margin: 0 auto;
  --device-back: #bdc9b2;
  --device-back-2: #7d8e78;
  --device-rail: #d7dfd2;
  --device-wallpaper-a: #1a3440;
  --device-wallpaper-b: #8ca27e;
  --device-camera: #1f2326;
}
.device-visual::before {
  content: "";
  position: absolute;
  left: 16px;
  right: 10px;
  bottom: 0;
  height: 28px;
  border-radius: 50%;
  background: radial-gradient(ellipse, rgba(0, 0, 0, .48), transparent 68%);
  filter: blur(4px);
}
.device-rear,
.device-front {
  position: absolute;
  border-radius: 25px;
  box-shadow: 0 24px 42px rgba(0, 0, 0, .48);
}
.device-rear {
  left: 4px;
  top: 14px;
  width: 124px;
  height: 218px;
  transform: rotate(-5deg);
  background:
    linear-gradient(135deg, rgba(255, 255, 255, .34), transparent 34%),
    linear-gradient(145deg, var(--device-back), var(--device-back-2));
  border: 2px solid rgba(255, 255, 255, .40);
}
.device-rear::after {
  content: "";
  position: absolute;
  inset: 12px;
  border-radius: 17px;
  border: 1px solid rgba(255, 255, 255, .13);
  background: linear-gradient(155deg, rgba(255, 255, 255, .18), transparent 54%);
}
.camera-bar {
  position: absolute;
  left: 11px;
  right: 11px;
  top: 26px;
  height: 36px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 10px;
  border-radius: 999px;
  background:
    linear-gradient(180deg, rgba(255, 255, 255, .16), transparent 34%),
    linear-gradient(135deg, #32383d, var(--device-camera));
  border: 1px solid rgba(255, 255, 255, .20);
  box-shadow: inset 0 0 0 1px rgba(0, 0, 0, .28), 0 7px 15px rgba(0, 0, 0, .28);
  z-index: 2;
}
.camera-lens {
  width: 15px;
  height: 15px;
  border-radius: 50%;
  background:
    radial-gradient(circle at 37% 35%, #5e7188 0 10%, transparent 12%),
    radial-gradient(circle at 52% 53%, #111923 0 35%, #030508 38% 100%);
  border: 1px solid rgba(255, 255, 255, .20);
  box-shadow: 0 0 0 3px rgba(255, 255, 255, .06);
}
.camera-flash {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  margin-left: auto;
  background: #f3e7b5;
  box-shadow: 0 0 10px rgba(255, 232, 151, .32);
}
.device-front {
  right: 4px;
  top: 0;
  width: 124px;
  height: 232px;
  background: linear-gradient(145deg, #101820, #03060c);
  border: 2px solid var(--device-rail);
  box-shadow:
    inset 0 0 0 5px rgba(4, 7, 12, .92),
    0 26px 44px rgba(0, 0, 0, .52),
    0 0 0 7px rgba(47, 140, 255, .035);
  overflow: hidden;
}
.device-screen {
  position: absolute;
  inset: 16px 9px 10px;
  border-radius: 18px;
  background:
    radial-gradient(circle at 62% 18%, rgba(255, 255, 255, .16), transparent 19%),
    linear-gradient(28deg, transparent 0 32%, rgba(230, 250, 214, .30) 33% 43%, transparent 44%),
    linear-gradient(154deg, var(--device-wallpaper-a), var(--device-wallpaper-b));
  border: 1px solid rgba(255, 255, 255, .10);
  box-shadow: inset 0 -38px 52px rgba(0, 0, 0, .20);
}
.device-screen::after {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: inherit;
  background: linear-gradient(135deg, rgba(255, 255, 255, .24), transparent 28%, rgba(255, 255, 255, .08) 52%, transparent 70%);
  opacity: .7;
}
.punch-hole {
  position: absolute;
  left: 50%;
  top: 10px;
  width: 8px;
  height: 8px;
  transform: translateX(-50%);
  border-radius: 50%;
  background: #030508;
  box-shadow: 0 0 0 2px rgba(255, 255, 255, .13);
  z-index: 3;
}
.pixel-9-pro-xl,
.pixel-9-pro {
  --device-back: #d3dccd;
  --device-back-2: #81937e;
  --device-rail: #dfe8da;
  --device-wallpaper-a: #183046;
  --device-wallpaper-b: #a5b997;
}
.pixel-9 { --device-back: #c7d4e4; --device-back-2: #667d98; --device-rail: #dce7f3; --device-wallpaper-a: #142642; --device-wallpaper-b: #7ea7c9; }
.pixel-8-pro { --device-back: #cbd0c8; --device-back-2: #7d837b; --device-rail: #e1e5df; }
.pixel-8,
.pixel-8a { --device-back: #c0d7d1; --device-back-2: #5f817b; --device-rail: #d8ebe6; }
.pixel-7-pro,
.pixel-7,
.pixel-6-pro,
.pixel-6 { --device-back: #cfd4da; --device-back-2: #6c7480; --device-rail: #e4e8ee; --device-camera: #12161b; }
.pixel-fold .device-rear { width: 142px; border-radius: 18px; }
.pixel-fold .device-front { width: 108px; border-radius: 18px; }
.pixel-tablet { width: 218px; }
.pixel-tablet .device-rear { width: 176px; height: 132px; top: 54px; border-radius: 18px; }
.pixel-tablet .device-front { width: 170px; height: 126px; top: 42px; border-radius: 18px; }
.camera-two .lens-3,
.camera-one .lens-2,
.camera-one .lens-3 { display: none; }
.camera-bar-style .camera-bar { left: -2px; right: -2px; border-radius: 14px; }
.camera-visor .camera-bar { left: -5px; right: -5px; border-radius: 0; height: 38px; }
.device-name { font-size: 25px; font-weight: 850; margin: 4px 0 6px; letter-spacing: 0; }
.device-subline { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; color: var(--muted); font-size: 13px; }
.device-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 8px;
  border-radius: 999px;
  border: 1px solid rgba(66, 223, 91, .22);
  background: rgba(66, 223, 91, .10);
  color: #a7f5b2;
  font-size: 12px;
  font-weight: 750;
}
.spec-list { display: grid; gap: 10px; margin-top: 18px; }
.spec-row {
  display: grid;
  grid-template-columns: 26px minmax(130px, .8fr) minmax(0, 1fr);
  align-items: center;
  gap: 10px;
  font-size: 14px;
}
.spec-icon { color: var(--blue); font-size: 16px; }
.spec-icon svg { width: 16px; height: 16px; stroke-width: 2.2; }
.spec-label { color: var(--muted); }
.spec-value { color: white; font-weight: 650; }
.info-strip {
  margin-top: 18px;
  display: flex;
  gap: 12px;
  align-items: flex-start;
  color: #73b7ff;
  background: linear-gradient(135deg, rgba(47, 140, 255, .14), rgba(55, 185, 255, .07));
  border: 1px solid rgba(47, 140, 255, .14);
  border-radius: var(--radius-lg);
  padding: 14px;
  line-height: 1.45;
}
.setup-notice {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 16px;
  align-items: center;
  margin-bottom: 16px;
  padding: 16px 18px;
  border-radius: var(--radius-lg);
  border: 1px solid rgba(255, 193, 7, .32);
  background: linear-gradient(135deg, rgba(255, 193, 7, .16), rgba(47, 140, 255, .12));
  box-shadow: 0 18px 40px rgba(0, 0, 0, .24);
}
.setup-notice strong { display: block; font-size: 16px; margin-bottom: 4px; }
.setup-notice span { color: var(--muted); line-height: 1.45; }
.setup-icon {
  width: 46px;
  height: 46px;
  border-radius: 14px;
  display: grid;
  place-items: center;
  color: #07101e;
  background: var(--yellow);
}
.setup-icon svg { width: 24px; height: 24px; stroke-width: 2.3; }
.setup-button {
  text-decoration: none;
  color: white;
  font-weight: 850;
  padding: 11px 15px;
  border-radius: var(--radius-lg);
  background: linear-gradient(135deg, var(--blue), var(--purple));
  box-shadow: 0 12px 24px rgba(47, 140, 255, .2);
  white-space: nowrap;
}
.setup-button:hover { filter: brightness(1.08); }
.right-stack { display: grid; gap: 14px; }
.action-list { display: grid; gap: 9px; }
.dashboard-actions {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}
.dashboard-actions .action-row {
  grid-template-columns: 42px minmax(0, 1fr) 14px;
  min-height: 62px;
}
.dashboard-actions .action-copy { line-height: 1.25; }
.action-row {
  display: grid;
  grid-template-columns: 52px minmax(0, 1fr) 22px;
  align-items: center;
  gap: 12px;
  min-height: 54px;
  border-radius: var(--radius-lg);
  background:
    linear-gradient(135deg, rgba(255, 255, 255, .055), rgba(255, 255, 255, .025));
  border: 1px solid var(--border-soft);
  padding: 8px 12px;
  color: inherit;
  text-decoration: none;
  transition: transform .14s ease, border-color .14s ease, background .14s ease;
}
.action-row:hover { border-color: rgba(47, 140, 255, .42); background: rgba(47, 140, 255, .085); transform: translateY(-1px); }
.action-icon {
  width: 38px;
  height: 38px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  color: #07101e;
  font-weight: 900;
}
.action-icon svg { width: 21px; height: 21px; stroke-width: 2.35; }
.action-icon.blue { background: var(--blue); }
.action-icon.green { background: var(--green); }
.action-icon.yellow { background: var(--yellow); }
.action-icon.purple { background: var(--purple); color: white; }
.action-title { font-weight: 800; font-size: 15px; }
.action-copy { color: var(--muted); margin-top: 3px; font-size: 13px; }
.chevron { color: var(--muted); font-size: 26px; }
.safety h2 { color: var(--green); }
.check-list { display: grid; gap: 8px; }
.check { display: grid; grid-template-columns: 24px minmax(0, 1fr); align-items: start; gap: 9px; color: white; font-size: 14px; }
.check span:first-child { color: var(--cyan); }
.mini-card { min-height: 132px; }
.stack-list { display: grid; gap: 8px; }
.mini-row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  background: rgba(255, 255, 255, .04);
  color: var(--soft);
  font-size: 13px;
}
.mini-row strong { color: white; text-align: right; overflow-wrap: anywhere; }
.shell-grid .mini-row {
  align-items: center;
  border: 1px solid rgba(118, 153, 197, .10);
  border-left: 3px solid rgba(47, 140, 255, .42);
  background: linear-gradient(90deg, rgba(47, 140, 255, .08), rgba(255, 255, 255, .035));
}
.shell-grid .mini-row span {
  color: #b8c5d8;
  font-size: 12px;
  text-transform: uppercase;
}
.state-overview {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 14px;
}
.state-card {
  min-height: 112px;
  padding: 14px;
  border-radius: var(--radius-lg);
  border: 1px solid var(--border-soft);
  background:
    linear-gradient(145deg, rgba(47, 140, 255, .12), rgba(255, 255, 255, .035));
}
.state-card strong {
  display: block;
  margin-top: 12px;
  color: white;
  font-size: 18px;
  line-height: 1.15;
  overflow-wrap: anywhere;
}
.state-card span {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}
.state-card .state-icon {
  width: 34px;
  height: 34px;
  display: grid;
  place-items: center;
  border-radius: 11px;
  color: white;
  background: linear-gradient(135deg, var(--blue), var(--purple));
}
.state-card .state-icon svg { width: 20px; height: 20px; stroke-width: 2.2; }
.statusbar {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  align-items: center;
  gap: 12px;
  min-height: 42px;
  color: var(--muted);
  border-top: 1px solid var(--border);
  padding-top: 12px;
  font-size: 13px;
  overflow: hidden;
}
.statusbar div:nth-child(2) { text-align: center; color: var(--soft); }
.statusbar div:nth-child(3) { text-align: right; }
.status-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: var(--blue); margin-right: 8px; }
.statusbar.warning .status-dot { background: var(--yellow); }
.statusbar.blocked .status-dot { background: var(--red); }
.shell-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
.page-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
}
.page-grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.wide-card { grid-column: 1 / -1; }
.hero-strip {
  display: grid;
  grid-template-columns: 76px minmax(0, 1fr);
  align-items: center;
  gap: 16px;
  padding: 16px;
  border-radius: var(--radius);
  background: linear-gradient(135deg, rgba(47, 140, 255, .16), rgba(122, 77, 255, .10));
  border: 1px solid rgba(47, 140, 255, .20);
}
.hero-icon {
  width: 58px;
  height: 58px;
  display: grid;
  place-items: center;
  border-radius: 16px;
  background: linear-gradient(135deg, var(--blue), var(--purple));
  box-shadow: 0 16px 32px rgba(47, 140, 255, .24);
  color: white;
  font-weight: 900;
}
.hero-icon svg { width: 32px; height: 32px; stroke-width: 2.15; }
.hero-strip h2 { margin: 0 0 6px; font-size: 22px; }
.hero-strip p { margin: 0; color: var(--muted); line-height: 1.45; }
.tile-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}
.tile {
  min-height: 92px;
  padding: 13px;
  border-radius: var(--radius-lg);
  background:
    linear-gradient(145deg, rgba(255, 255, 255, .052), rgba(255, 255, 255, .024));
  border: 1px solid var(--border-soft);
  color: inherit;
  text-decoration: none;
}
.tile strong { display: block; margin-bottom: 5px; color: white; }
.tile span { color: var(--muted); font-size: 13px; line-height: 1.4; }
.tile.action-tile {
  display: grid;
  grid-template-columns: 42px minmax(0, 1fr);
  align-items: center;
  gap: 12px;
  transition: transform .14s ease, border-color .14s ease, background .14s ease;
}
.tile.action-tile:hover {
  transform: translateY(-1px);
  border-color: rgba(47, 140, 255, .38);
  background: rgba(47, 140, 255, .075);
}
.tile-icon {
  width: 38px;
  height: 38px;
  display: grid;
  place-items: center;
  border-radius: 12px;
  color: white;
  background: linear-gradient(135deg, var(--blue), var(--purple));
}
.tile-icon svg { width: 22px; height: 22px; stroke-width: 2.25; }
.metric-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}
.metric {
  min-height: 78px;
  padding: 13px;
  border-radius: var(--radius-lg);
  background: linear-gradient(145deg, rgba(47, 140, 255, .10), rgba(255, 255, 255, .035));
  border: 1px solid var(--border-soft);
}
.metric span {
  display: block;
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
}
.metric strong {
  display: block;
  margin-top: 8px;
  color: white;
  font-size: 20px;
}
.context-ribbon {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}
.context-item {
  min-height: 66px;
  padding: 12px 13px;
  border-radius: var(--radius-lg);
  background: linear-gradient(145deg, rgba(255, 255, 255, .045), rgba(47, 140, 255, .055));
  border: 1px solid var(--border-soft);
}
.context-item span {
  display: block;
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
}
.context-item strong {
  display: block;
  margin-top: 7px;
  color: white;
  font-size: 14px;
  line-height: 1.25;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.context-item.safe { border-color: rgba(66, 223, 91, .24); background: linear-gradient(145deg, rgba(66, 223, 91, .08), rgba(255, 255, 255, .035)); }
.context-item.warn { border-color: rgba(255, 201, 40, .28); background: linear-gradient(145deg, rgba(255, 201, 40, .10), rgba(255, 255, 255, .035)); }
.empty-state {
  min-height: 168px;
  display: grid;
  place-items: center;
  text-align: center;
  border-radius: var(--radius-lg);
  background: rgba(255, 255, 255, .025);
  border: 1px dashed rgba(118, 153, 197, .22);
  color: var(--muted);
}
.empty-state strong {
  display: block;
  color: white;
  font-size: 18px;
  margin-bottom: 6px;
}
.explorer-card { min-height: 196px; }
.chip-row { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: 999px;
  padding: 6px 9px;
  color: var(--soft);
  background: rgba(255, 255, 255, .045);
  border: 1px solid var(--border-soft);
  font-size: 12px;
}
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--red); }
.dot.safe { background: var(--green); }
.dot.warn { background: var(--yellow); }
.wizard-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 320px;
  gap: 16px;
  align-items: stretch;
}
.wizard-content {
  display: grid;
  align-content: start;
}
.stepper {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}
.step {
  display: grid;
  place-items: center;
  gap: 8px;
  color: var(--muted);
  padding: 12px 8px;
  border-radius: var(--radius-lg);
  background: rgba(255, 255, 255, .035);
  border: 1px solid var(--border-soft);
}
.step.active { color: white; border-color: rgba(122, 77, 255, .55); background: linear-gradient(135deg, rgba(122, 77, 255, .26), rgba(47, 140, 255, .10)); }
.step-circle {
  width: 28px;
  height: 28px;
  display: grid;
  place-items: center;
  border-radius: 50%;
  background: var(--panel-3);
  font-weight: 800;
}
.step.active .step-circle { background: var(--purple); }
.readiness-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}
.readiness-grid .card {
  box-shadow: var(--shadow-soft);
  padding: 15px;
}
.plan-brief {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-top: 14px;
}
.plan-brief-header {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin: 16px 0 10px;
}
.plan-brief-header h3 {
  margin: 0;
  font-size: 15px;
}
.plan-brief-header span {
  color: var(--muted);
  font-size: 12px;
}
.plan-card {
  min-height: 116px;
  padding: 13px;
  border-radius: var(--radius-lg);
  background: linear-gradient(145deg, rgba(47, 140, 255, .11), rgba(255, 255, 255, .035));
  border: 1px solid var(--border-soft);
}
.plan-card.ready { border-color: rgba(66, 223, 91, .26); background: linear-gradient(145deg, rgba(66, 223, 91, .09), rgba(255, 255, 255, .035)); }
.plan-card.attention { border-color: rgba(255, 201, 40, .30); background: linear-gradient(145deg, rgba(255, 201, 40, .11), rgba(255, 255, 255, .035)); }
.plan-card span {
  display: block;
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
}
.plan-card strong {
  display: block;
  margin-top: 9px;
  color: white;
  font-size: 16px;
  line-height: 1.2;
  overflow-wrap: anywhere;
}
.plan-card p {
  margin: 8px 0 0;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.38;
}
.wizard-grid > .card:first-child,
.wizard-grid > .blocked,
.wizard-grid > .guarded {
  align-self: stretch;
}
.blocked {
  border-color: rgba(255, 104, 104, .32);
  background: linear-gradient(145deg, rgba(80, 27, 35, .60), rgba(28, 18, 28, .96));
}
.blocked h3 { color: var(--red); }
.guarded {
  border-color: rgba(255, 201, 40, .32);
  background: linear-gradient(145deg, rgba(75, 58, 20, .56), rgba(23, 27, 34, .96));
}
.guarded h3 { color: var(--yellow); }
.notice {
  margin-top: 14px;
  color: #74bfff;
  background: rgba(47, 140, 255, .12);
  border: 1px solid rgba(47, 140, 255, .22);
  border-radius: var(--radius-lg);
  padding: 12px 14px;
  font-size: 13px;
}
.footer-controls {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  margin-top: 14px;
}
.button {
  min-width: 110px;
  text-align: center;
  border-radius: var(--radius-lg);
  padding: 11px 16px;
  color: var(--soft);
  background: var(--panel-2);
  border: 1px solid var(--border-soft);
  font-weight: 700;
  text-decoration: none;
  transition: transform .14s ease, border-color .14s ease, filter .14s ease;
}
.button:hover { transform: translateY(-1px); border-color: rgba(47, 140, 255, .36); filter: brightness(1.06); }
.button.primary { color: white; background: linear-gradient(135deg, var(--purple), #3a2b89); }
.button.guarded-action { background: linear-gradient(135deg, #7a4dff, #7b4b18); border-color: rgba(255, 201, 40, .38); }
@media (max-width: 1100px) {
  .app-shell { grid-template-columns: 230px minmax(0, 1fr); }
  .dashboard-grid, .wizard-grid { grid-template-columns: 1fr; }
  .lower-grid, .shell-grid, .page-grid, .page-grid.two, .readiness-grid, .tile-grid, .metric-strip, .context-ribbon, .state-overview, .plan-brief { grid-template-columns: 1fr; }
  .dashboard-actions { grid-template-columns: 1fr; }
  .setup-notice { grid-template-columns: auto minmax(0, 1fr); }
  .setup-button { grid-column: 1 / -1; text-align: center; }
  .device-body { grid-template-columns: 1fr; }
}
"""


def _sidebar(active: str, version: str) -> str:
    nav = "\n".join(_nav_item(key, title, detail, active) for key, title, detail in _nav_rows())
    return f"""
    <aside class="sidebar">
      <div class="brand">
        <div class="logo-mark">PF</div>
        <div>
          <div class="brand-title">PixelFlasher</div>
          <div class="brand-subtitle">Modern UI</div>
          <div class="brand-subtitle">{escape(version)}</div>
        </div>
      </div>
      <nav class="nav" aria-label="Modern UI surfaces">{nav}</nav>
      <div class="mode-card">
        <h3>Workspace</h3>
        <p>Modern dashboard, guided workflows, connected state, and confirmations in one place.</p>
      </div>
    </aside>
    """


def _nav_item(key: str, title: str, detail: str, active: str) -> str:
    active_class = " active" if key == active else ""
    current_attr = ' aria-current="page"' if key == active else ""
    return f"""
      <a class="nav-item{active_class}" data-page="{escape(key)}" href="{escape(action_url(_nav_action_id(key)))}"{current_attr}>
        <div class="nav-icon">{_icon(key)}</div>
        <div>
          <div class="nav-title">{escape(title)}</div>
          <div class="nav-detail">{escape(detail)}</div>
        </div>
      </a>
    """


def _topbar(page: str) -> str:
    return f"""
    <header class="topbar">
      <div class="title">
        <h1>{escape(_headline(page))}</h1>
        <p>{escape(_subtitle(page))}</p>
      </div>
      <div class="top-actions">
        {_badge_markup(page)}
        <div class="toggle"><span>Light</span><span class="on">Dark</span></div>
      </div>
    </header>
    """


def _page_body(page: str, state: ModernReadonlyState, version: str) -> str:
    if page == "shell":
        return _shell_page(state)
    if page == "wizard":
        return _wizard_page(state)
    if page == "backups":
        return _backups_page(state)
    if page == "downloads":
        return _downloads_page(state)
    if page == "settings":
        return _settings_page(state)
    if page == "tools":
        return _tools_page(state)
    if page == "safety":
        return _safety_page(state)
    if page == "about":
        return _about_page(version, state)
    return _dashboard_page(state)


def _dashboard_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_platform_tools_notice(state)}
      <div class="dashboard-grid">
        {_connected_device_card(state)}
        <div class="right-stack">
          {_quick_actions_card(state)}
        </div>
      </div>
      <div class="lower-grid">
        {_workflow_status_card(state)}
        {_device_slots_card(state)}
        {_partitions_card(state)}
        {_last_backup_card(state)}
      </div>
    </section>
    """


def _connected_device_card(state: ModernReadonlyState) -> str:
    device = state.device
    device_name = device.display_name or "Choose a device"
    serial = device.serial or "Scan required"
    subtitle_parts = _unique_parts(serial, device.codename, device.product)
    android = device.android_version or "Unknown"
    build_id = device.build_id or state.firmware.build_id or "Unknown"
    security_patch = device.security_patch or "Unknown"
    bootloader = _known(device.bootloader_state)
    connection = device.connection_label
    connection_badge = "green" if device.selected else "yellow"
    return f"""
    <article class="card device-card">
      <div class="card-header">
        <div>
          <h2>Connected Device</h2>
          <div class="card-subtitle">Current device context from PixelFlasher</div>
        </div>
        <span class="badge {connection_badge}">{escape(connection)}</span>
      </div>
      <div class="device-body">
        {_device_art(device)}
        <div>
          <div class="device-name">{escape(device_name)}</div>
          <div class="device-subline">
            <span>{escape(" · ".join(subtitle_parts) or "Scan a USB device to load details")}</span>
            <span class="device-pill">{escape(connection)}</span>
          </div>
          <div class="spec-list">
            {_spec("android", "Android Version", android)}
            {_spec("build", "Build Number", build_id)}
            {_spec("shield", "Security Patch", security_patch)}
            {_spec("lock", "Bootloader", bootloader)}
            {_spec("connection", "Connection", connection)}
            {_spec("source", "State Source", "Loaded from last scan")}
          </div>
        </div>
      </div>
      <div class="info-strip"><strong>ⓘ</strong><div>Device details update from the current PixelFlasher session.<br>Use Scan Devices to refresh connected devices.</div></div>
    </article>
    """


def _device_art(device: ModernDeviceState) -> str:
    label = device.display_name or device.codename or "Pixel device"
    art_class = _device_art_class(device)
    return f"""
    <div class="device-visual {escape(art_class)}" aria-label="{escape(label)} device illustration">
      <div class="device-rear">
        <div class="camera-bar">
          <span class="camera-lens lens-1"></span>
          <span class="camera-lens lens-2"></span>
          <span class="camera-lens lens-3"></span>
          <span class="camera-flash"></span>
        </div>
      </div>
      <div class="device-front">
        <span class="punch-hole"></span>
        <span class="device-screen"></span>
      </div>
    </div>
    """


def _device_art_class(device: ModernDeviceState) -> str:
    descriptor = " ".join(
        part
        for part in (device.codename, device.product, device.display_name)
        if part
    ).lower()
    families = (
        (("komodo", "pixel 9 pro xl", "pixel 10 pro xl"), "pixel-9-pro-xl camera-three"),
        (("caiman", "pixel 9 pro", "pixel 10 pro"), "pixel-9-pro camera-three"),
        (("tokay", "pixel 9", "pixel 10"), "pixel-9 camera-two"),
        (("akita", "pixel 8a", "pixel 9a"), "pixel-8a camera-two"),
        (("husky", "pixel 8 pro"), "pixel-8-pro camera-three camera-bar-style"),
        (("shiba", "pixel 8"), "pixel-8 camera-two camera-bar-style"),
        (("cheetah", "pixel 7 pro"), "pixel-7-pro camera-three camera-visor"),
        (("panther", "lynx", "pixel 7"), "pixel-7 camera-two camera-visor"),
        (("raven", "pixel 6 pro"), "pixel-6-pro camera-three camera-visor"),
        (("oriole", "bluejay", "pixel 6"), "pixel-6 camera-two camera-visor"),
        (("felix", "fold"), "pixel-fold camera-three"),
        (("tangorpro", "tablet"), "pixel-tablet camera-one"),
    )
    for markers, css_class in families:
        if any(marker in descriptor for marker in markers):
            return css_class
    return "pixel-9 camera-two"


def _quick_actions_card(state: ModernReadonlyState) -> str:
    rows = []
    if _needs_platform_tools_setup(state):
        rows.append(("yellow", "tools", "Set Up Platform Tools", "Install ADB and Fastboot for USB detection.", "setup_platform_tools"))
    rows.extend((
        ("blue", "wizard", "Flash Wizard", "Plan firmware, options, and final flash.", "open_modern_flash_wizard"),
        ("yellow", "flash", "Flash Device", "Start the configured PixelFlasher workflow.", "flash_device"),
        ("purple", "patch", "Patch Boot", "Patch the selected boot image.", "patch_boot"),
        ("green", "shell", "Device Explorer", "Review device, firmware, and tools.", "open_modern_shell"),
        ("yellow", "scan", "Scan Devices", "Refresh connected devices.", "scan_devices"),
    ))
    return f"""
    <article class="card">
      <div class="card-header">
        <div>
          <h2>Quick Actions</h2>
          <div class="card-subtitle">Primary workflows in one place</div>
        </div>
      </div>
      <div class="action-list dashboard-actions">
        {"".join(_action_row(*row) for row in rows)}
      </div>
    </article>
    """


def _workflow_status_card(state: ModernReadonlyState) -> str:
    rows = (
        ("Device", state.device.display_name or state.device.serial or "Choose device"),
        ("Firmware", state.firmware.filename or "Choose firmware"),
        ("Package", f"{_package_type(state)} - {state.firmware.size_label}"),
        ("Plan", state.flash.flash_mode),
    )
    return f"""
    <article class="card">
      <div class="card-header">
        <div>
          <h2>Workflow Status</h2>
          <div class="card-subtitle">What PixelFlasher has loaded right now</div>
        </div>
        <span class="badge">Ready</span>
      </div>
      <div class="stack-list">
        {"".join(_mini_row(label, value) for label, value in rows)}
      </div>
    </article>
    """


def _platform_tools_notice(state: ModernReadonlyState) -> str:
    if not _needs_platform_tools_setup(state):
        return ""
    if state.tools.platform_tools_path:
        detail = "The configured Platform Tools folder is missing ADB or Fastboot. Reinstall or choose a valid folder to detect USB devices."
    else:
        detail = "PixelFlasher needs Android Platform Tools to detect phones over USB. Set it up automatically to install ADB and Fastboot."
    return f"""
    <div class="setup-notice">
      <div class="setup-icon">{_svg_icon("tools")}</div>
      <div>
        <strong>Platform Tools need setup</strong>
        <span>{escape(detail)}</span>
      </div>
      <a class="setup-button" href="{escape(action_url("setup_platform_tools"))}">Set Up Platform Tools</a>
    </div>
    """


def _device_slots_card(state: ModernReadonlyState) -> str:
    slot = state.device.active_slot or "unknown"
    return _mini_card(
        "Device Slots",
        "Slots",
        (("Active slot", slot), ("Slot target", state.flash.slot_behavior), ("Switch slot", "Open Tools")),
    )


def _partitions_card(state: ModernReadonlyState) -> str:
    patchable = "available" if state.firmware.has_patchable_image else "not detected"
    return _mini_card(
        "Partitions",
        "Images",
        (("boot/init_boot", patchable), ("Verity", state.flash.verity), ("Verification", state.flash.verification), ("Partition manager", "Available in Tools")),
    )


def _last_backup_card(state: ModernReadonlyState) -> str:
    return _mini_card(
        "Last Backup",
        "Backups",
        (("Last backup", state.backups.latest_label), ("Total backups", str(state.backups.total_count)), ("Restore", state.backups.restore_mode)),
    )


def _shell_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      <div class="chip-row">
        <span class="chip"><span class="dot safe"></span>Device state</span>
        <span class="chip"><span class="dot warn"></span>Firmware context</span>
        <span class="chip"><span class="dot"></span>Actions</span>
      </div>
      {_platform_tools_notice(state)}
      {_context_ribbon(state, "Modern Shell")}
      <div class="state-overview">
        {_state_card("shell", "Device", state.device.display_name or state.device.serial or "Choose device")}
        {_state_card("connection", "Connection", state.device.connection_label)}
        {_state_card("downloads", "Firmware", state.firmware.filename or "Choose firmware")}
        {_state_card("tools", "Tools", _platform_tools_label(state))}
      </div>
      <div class="shell-grid">
        {_explorer_card("Device State Overview", (("Selected device", state.device.display_name or state.device.serial or "Choose device"), ("Android", state.device.android_version or "Waiting for scan"), ("Bootloader", _known(state.device.bootloader_state)), ("Current slot", state.device.active_slot or "Waiting for scan")))}
        {_explorer_card("Connection Readiness", (("ADB", "ready" if state.device.adb_ready else "Scan device"), ("Fastboot", _bootloader_tool_mode(state)), ("Platform tools", _platform_tools_label(state)), ("Selected device", state.device.display_name or "Choose device")))}
        {_explorer_card("Device Information", (("Model", state.device.display_name or "Waiting for scan"), ("Codename", state.device.codename or "Waiting for scan"), ("Serial", state.device.serial or "Waiting for scan"), ("Product", state.device.product or "Waiting for scan")))}
        {_explorer_card("Firmware Context", (("Type", _package_type(state)), ("Build", state.firmware.build_id or "unknown"), ("Size", state.firmware.size_label), ("Validation", "verified" if state.firmware.verified else "waiting"), ("Patchable image", "available" if state.firmware.has_patchable_image else "not detected")))}
        {_explorer_card("Loaded Flash Options", (("Mode", state.flash.flash_mode), ("Data", state.flash.data_behavior), ("Slot target", state.flash.slot_behavior), ("No reboot", _on_off(state.flash.no_reboot))))}
        {_explorer_card("Workflow Controls", (("Flash", "configured from Flash Wizard"), ("Patch", "available from Dashboard"), ("Firmware", "select and process"), ("Tools", "available from sidebar")))}
        {_explorer_card("Available Actions", (("Scan", "available"), ("Firmware", "select and process"), ("Patch", "available when ready"), ("Flash", "available when ready")))}
      </div>
    </section>
    """


def _wizard_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content wizard-content">
      <div class="stepper">
        {_step("1", "Device", True)}
        {_step("2", "Firmware", False)}
        {_step("3", "Options", False)}
        {_step("4", "Plan", False)}
        {_step("5", "Review", False)}
      </div>
      {_platform_tools_notice(state)}
      {_context_ribbon(state, "Flash workflow")}
      <div class="wizard-grid">
        <article class="card">
          <div class="card-header">
            <div>
              <h2>Step 1: Device &amp; Firmware</h2>
              <div class="card-subtitle">Choose the target, confirm firmware, then review the final flash plan.</div>
            </div>
            <span class="badge yellow">Confirmed workflow</span>
          </div>
          <div class="readiness-grid">
            {_wizard_readiness("Device Readiness", (("No device connected" if not state.device.selected else "Device selected"), state.device.connection_label, f"Active slot: {state.device.active_slot or 'unknown'}", f"Root: {state.device.root_status}"))}
            {_wizard_readiness("Firmware Readiness", (("No firmware selected" if not state.firmware.selected else state.firmware.filename), _package_type(state), "Size: " + state.firmware.size_label, "Process firmware when ready", "Patchable image: " + ("available" if state.firmware.has_patchable_image else "not detected")))}
            {_wizard_readiness("Flash Workflow", ("Review flash mode", "Confirm options", "Run PixelFlasher flash", "Follow prompts"))}
          </div>
          {_wizard_plan_brief(state)}
          {_explorer_card("Loaded Plan Inputs", (("Flash mode", state.flash.flash_mode), ("Data behavior", state.flash.data_behavior), ("Slot target", state.flash.slot_behavior), ("Firmware", state.firmware.filename or "Choose firmware"), ("Package type", _package_type(state))))}
          <div class="footer-controls">
            <a class="button" href="{escape(action_url("select_firmware"))}">Select Firmware</a>
            <a class="button" href="{escape(action_url("process_firmware"))}">Process Firmware</a>
            <a class="button primary guarded-action" href="{escape(action_url("flash_device"))}">Flash Device</a>
          </div>
        </article>
        <aside class="card guarded">
          <div class="card-header"><h3>Flash Summary</h3><span class="badge yellow">Review</span></div>
          <p class="muted">Review the current plan before starting the configured PixelFlasher flash workflow.</p>
          <div class="stack-list">
            {_mini_row("Status", _plan_status_label(state))}
            {_mini_row("Review notes", _plan_review_label(state))}
            {_mini_row("Device", state.device.display_name or "Choose device")}
            {_mini_row("Firmware", state.firmware.filename or "Choose firmware")}
            {_mini_row("Package type", _package_type(state))}
            {_mini_row("Firmware size", state.firmware.size_label)}
            {_mini_row("Mode", state.flash.flash_mode)}
            {_mini_row("Data", state.flash.data_behavior)}
            {_mini_row("Slot target", state.flash.slot_behavior)}
            {_mini_row("Final action", "Flash Device")}
          </div>
          <div class="notice">Sensitive operations still use PixelFlasher confirmations.</div>
        </aside>
      </div>
    </section>
    """


def _wizard_plan_brief(state: ModernReadonlyState) -> str:
    rows = (
        (
            "Target Device",
            state.device.display_name or state.device.serial or "Select a device",
            state.device.connection_label,
            "ready" if state.device.selected else "attention",
        ),
        (
            "Firmware Package",
            state.firmware.filename or "Select firmware",
            f"{_package_type(state)} - {state.firmware.size_label}",
            "ready" if state.firmware.selected else "attention",
        ),
        (
            "Flash Options",
            state.flash.flash_mode,
            f"{state.flash.data_behavior} - Slot {state.flash.slot_behavior}",
            "",
        ),
        (
            "Final Review",
            _plan_status_label(state),
            "PixelFlasher confirmations remain in place.",
            "ready" if state.ready_for_review else "attention",
        ),
    )
    return f"""
    <div class="plan-brief-header">
      <h3>Plan Snapshot</h3>
      <span>Current flash workflow setup</span>
    </div>
    <div class="plan-brief" aria-label="Flash plan snapshot">{"".join(_plan_card(*row) for row in rows)}</div>
    """


def _plan_card(label: str, title: str, copy: str, tone: str) -> str:
    tone_class = f" {tone}" if tone in {"ready", "attention"} else ""
    return f"""
    <div class="plan-card{tone_class}">
      <span>{escape(label)}</span>
      <strong>{escape(title)}</strong>
      <p>{escape(copy)}</p>
    </div>
    """


def _plan_status_label(state: ModernReadonlyState) -> str:
    return "Ready to start" if state.ready_for_review else "Needs attention"


def _plan_review_label(state: ModernReadonlyState) -> str:
    return str(len(state.warnings)) if state.warnings else "clear"


def _backups_page(state: ModernReadonlyState) -> str:
    empty = ""
    if not state.backups.has_loaded_backups:
        empty = '<article class="card wide-card">' + _empty_state("No backups loaded", "Connect and scan a rooted device to load backup details.") + "</article>"
    return f"""
    <section class="content">
      {_metric_strip((("Total backups", str(state.backups.total_count)), ("Latest backup", state.backups.latest_label), ("Restore mode", "Confirmed flow"), ("Backup tools", "Available")))}
      {_context_ribbon(state, "Backup workspace")}
      <div class="page-grid">
        {_hero_card("backups", "Backups", "Review backup context and open the backup manager for connected devices.")}
        {_mini_card("Backup Summary", "Backups", (("Total backups", str(state.backups.total_count)), ("Latest backup", state.backups.latest_label), ("Location", state.backups.location)))}
        {_action_tile_card("Backup Actions", (("Backup Manager", "Open the available backup tools.", "backup_manager", "backups"), ("Support Package", "Create a support archive.", "create_support_package", "tools"), ("Scan Device", "Refresh connected device state.", "scan_devices", "scan"), ("Settings", "Review backup paths and preferences.", "settings_dialog", "settings")))}
        {_explorer_card("Loaded Backup Context", (("Device", state.device.display_name or state.device.serial or "Choose device"), ("Backup index", "loaded" if state.backups.has_loaded_backups else "Ready after scan"), ("Backup location", state.backups.location), ("Restore mode", state.backups.restore_mode)))}
        {_explorer_card("Backup Details", (("Selected backup", state.backups.latest_label if state.backups.has_loaded_backups else "Choose backup"), ("Archive state", "Ready to open"), ("Restore target", "Choose backup"), ("Compatibility", "Review before restore")))}
        {_explorer_card("Warnings", _warning_rows(state))}
        {_explorer_card("Backup Tools", (("Backup Manager", "available"), ("Support package", "available"), ("Device required", "yes"), ("Root required", "for Magisk backups")))}
        {empty}
      </div>
    </section>
    """


def _downloads_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_metric_strip((("Firmware", state.firmware.filename or "None"), ("Type", _package_type(state)), ("Size", state.firmware.size_label), ("Next step", "Flash Wizard")))}
      {_context_ribbon(state, "Download center")}
      <div class="page-grid two">
        {_hero_card("downloads", "Downloads", "Browse firmware resources and rooting app downloads.")}
        {_action_tile_card("Firmware Downloads", (("Firmware Downloads", "Find firmware for the selected device.", "firmware_downloads", "downloads"), ("Rooting App", "Open rooting app downloads.", "rooting_app", "android"), ("Select Firmware", state.firmware.filename or "Choose a local package.", "select_firmware", "build"), ("Flash Wizard", "Continue with firmware planning.", "open_modern_flash_wizard", "wizard")))}
        {_explorer_card("Loaded Download Context", (("Update checks", "enabled" if state.downloads.update_check else "Manual"), ("Module updates", "enabled" if state.downloads.module_update_check else "Manual"), ("Package type", _package_type(state)), ("Selected firmware", state.firmware.filename or "Choose firmware"), ("File size", state.firmware.size_label)))}
        {_explorer_card("Download Details", (("Selected item", state.firmware.filename or "Choose item"), ("Validation", "verified" if state.firmware.verified else "Ready to verify"), ("Last catalog check", state.downloads.last_checked), ("Frequency", state.downloads.update_frequency)))}
        {_explorer_card("Warnings", _warning_rows(state))}
        {_explorer_card("Download Actions", (("Firmware downloads", "available for selected device"), ("Rooting App", "available"), ("Process package", "available after selection"), ("Flash package", "use Flash Wizard")))}
      </div>
    </section>
    """


def _settings_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_metric_strip((("Mode", "Modern"), ("Language", state.settings.language), ("Advanced", _on_off(state.settings.advanced_options)), ("Notifications", _on_off(state.settings.notifications))))}
      {_context_ribbon(state, "Preferences")}
      <div class="page-grid two">
        {_hero_card("settings", "Settings", "Review configured preferences and open the full settings dialog.")}
        {_action_tile_card("General Settings", (("Open Settings", "Configure PixelFlasher preferences.", "settings_dialog", "settings"), ("Scan Devices", "Refresh connected device state.", "scan_devices", "scan"), ("Select Firmware", "Choose a firmware package.", "select_firmware", "build"), ("Flash Wizard", "Review flash workflow setup.", "open_modern_flash_wizard", "wizard")))}
        {_tile_card("Paths & Environment", (("Platform tools", state.tools.platform_tools_path or "Set up tools"), ("Firmware", state.firmware.filename or "Choose firmware"), ("Phone path", state.settings.phone_path or "Set phone path"), ("Low memory", _on_off(state.settings.low_memory))))}
        {_explorer_card("Loaded Preference Flags", (("Language", state.settings.language), ("Custom ROM options", _on_off(state.settings.custom_rom_options)), ("Advanced options", _on_off(state.settings.advanced_options)), ("Notifications", _on_off(state.settings.notifications))))}
        {_explorer_card("Warnings", _warning_rows(state))}
        {_explorer_card("Settings Actions", (("Open Settings", "available"), ("Language", state.settings.language), ("Advanced options", _on_off(state.settings.advanced_options)), ("Notifications", _on_off(state.settings.notifications))))}
      </div>
    </section>
    """


def _tools_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_platform_tools_notice(state)}
      {_metric_strip((("Tool groups", "6"), ("Actions", "Ready"), ("Platform tools", _platform_tools_label(state)), ("Navigation", "Protected")))}
      {_context_ribbon(state, "Tools")}
      <div class="page-grid">
        {_hero_card("tools", "Tools", "Open PixelFlasher tools from the modern workspace.")}
        {_action_tile_card("Tool Catalog", (("Boot Image Patcher", "Patch selected boot image.", "patch_boot", "patch"), ("Support Package", "Create support archive.", "create_support_package", "tools"), ("Rooting App", "Download or install root tools.", "rooting_app", "android"), ("Magisk Modules", "Manage modules.", "magisk_modules", "settings"), ("Partition Manager", "Open partition tools.", "partition_manager", "backups"), ("Device Scan", "Refresh devices.", "scan_devices", "scan")))}
        {_explorer_card("Loaded Tool State", (("ADB", "available" if state.tools.adb_available else "Set up tools"), ("Fastboot", _bootloader_tool_status(state)), ("Configured path", state.tools.platform_tools_path or "Set up tools"), ("Selected device", state.device.display_name or "Choose device")))}
        {_explorer_card("Tool Availability Summary", (("ADB path", "loaded" if state.tools.adb_path else "Set up tools"), ("Bootloader tool path", "loaded" if _bootloader_tool_available(state) else "Set up tools"), ("Configured path", state.tools.platform_tools_path or "Set up tools"), ("Root status", state.device.root_status)))}
        {_explorer_card("Operation Policy", (("Flash", "PixelFlasher prompts"), ("Patch", "PixelFlasher prompts"), ("Partition tools", "PixelFlasher prompts"), ("Navigation", "Workspace only")))}
        {_explorer_card("Warnings", _warning_rows(state))}
        {_explorer_card("Advanced Operations", (("Reboot", "requires device"), ("Wipe", "requires flash workflow"), ("Slot switching", "requires device"), ("Live command output", "available in tools")))}
      </div>
    </section>
    """


def _safety_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_metric_strip((("Actions", "Curated"), ("Confirmations", "Required"), ("Navigation", "Workspace"), ("Engine", "PixelFlasher")))}
      {_context_ribbon(state, "System controls")}
      <div class="page-grid two">
        {_hero_card("safety", "System", "PixelFlasher keeps confirmations close to the workflows that need them.")}
        {_explorer_card("Loaded State Snapshot", _loaded_context_rows(state))}
        {_explorer_card("Warnings", _warning_rows(state))}
        {_explorer_card("Protection", tuple(("Rule", line) for line in SAFETY_BOUNDARY_LINES))}
        {_explorer_card("Operation Policy", (("Flash device", "requires confirmation"), ("Patch boot", "requires confirmation"), ("Support package", "asks for destination"), ("Partition tools", "requires confirmation")))}
        {_explorer_card("Confirmations", (("Flash device", "required"), ("Patch boot", "required when prompted"), ("Support package", "file destination required"), ("Partition tools", "required")))}
        {_explorer_card("Workspace Rules", (("Navigation", "PixelFlasher workspace"), ("External links", "kept out of workflow"), ("Action IDs", "curated list"), ("Command routing", "PixelFlasher actions")))}
      </div>
    </section>
    """


def _about_page(version: str, state: ModernReadonlyState) -> str:
    about_copy = f"PixelFlasher {version} with Modern UI as the primary workspace."
    return f"""
    <section class="content">
      {_metric_strip((("Version", version), ("Modern UI", "Primary"), ("Engine", "PixelFlasher"), ("Loaded warnings", str(len(state.warnings)))))}
      {_context_ribbon(state, "Local info only")}
      <div class="page-grid two">
        {_hero_card("PF", "About PixelFlasher", about_copy)}
        {_explorer_card("Application Engine", (("Version", version), ("Modern UI", "primary"), ("Engine", "PixelFlasher"), ("Workspace", "modern")))}
        {_explorer_card("Loaded State Snapshot", _loaded_context_rows(state))}
        {_tile_card("Modern UI Status", (("Dashboard", "Available"), ("Shell", "Device state"), ("Flash Wizard", "Functional workflow"), ("Remaining pages", "Modern workspace")))}
        {_explorer_card("System", (("Assets", "local"), ("Interface", "static HTML/CSS"), ("Command routing", "PixelFlasher actions"), ("Navigation", "workspace only")))}
      </div>
    </section>
    """


def _status_bar(version: str, status_message: str, status_tone: str) -> str:
    tone = _status_tone(status_tone)
    message = status_message or DEFAULT_STATUS_MESSAGE
    return f"""
    <footer class="statusbar {escape(tone)}">
      <div><span class="status-dot"></span>Modern UI</div>
      <div>{escape(message)}</div>
      <div>PixelFlasher {escape(version)}</div>
    </footer>
    """


def _spec(icon_key: str, label: str, value: str) -> str:
    return f"""
    <div class="spec-row">
      <div class="spec-icon">{_svg_icon(icon_key)}</div>
      <div class="spec-label">{escape(label)}</div>
      <div class="spec-value">{escape(value)}</div>
    </div>
    """


def _action_row(color: str, icon_key: str, title: str, copy: str, action_id: str) -> str:
    return f"""
    <a class="action-row" href="{escape(action_url(action_id))}">
      <div class="action-icon {escape(color)}">{_svg_icon(icon_key)}</div>
      <div><div class="action-title">{escape(title)}</div><div class="action-copy">{escape(copy)}</div></div>
      <div class="chevron">›</div>
    </a>
    """


def _hero_card(icon: str, title: str, copy: str) -> str:
    icon_markup = _svg_icon(icon) if icon in _SVG_ICONS else escape(icon)
    return f"""
    <article class="card wide-card">
      <div class="hero-strip">
        <div class="hero-icon">{icon_markup}</div>
        <div>
          <h2>{escape(title)}</h2>
          <p>{escape(copy)}</p>
        </div>
      </div>
    </article>
    """


def _tile_card(title: str, rows: tuple[tuple[str, str], ...]) -> str:
    return f"""
    <article class="card wide-card">
      <div class="card-header"><h2>{escape(title)}</h2><span class="badge">Open</span></div>
      <div class="tile-grid">{"".join(_tile(label, copy) for label, copy in rows)}</div>
    </article>
    """


def _action_tile_card(title: str, rows: tuple[tuple[str, str, str, str], ...]) -> str:
    return f"""
    <article class="card wide-card">
      <div class="card-header"><h2>{escape(title)}</h2><span class="badge">Open</span></div>
      <div class="tile-grid">{"".join(_action_tile(label, copy, action_id, icon_key) for label, copy, action_id, icon_key in rows)}</div>
    </article>
    """


def _tile(label: str, copy: str) -> str:
    return f"""<div class="tile"><strong>{escape(label)}</strong><span>{escape(copy)}</span></div>"""


def _unique_parts(*parts: str) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for part in parts:
        value = str(part or "").strip()
        key = value.lower()
        if value and key not in seen:
            values.append(value)
            seen.add(key)
    return tuple(values)


def _action_tile(label: str, copy: str, action_id: str, icon_key: str) -> str:
    return f"""
    <a class="tile action-tile" href="{escape(action_url(action_id))}">
      <div class="tile-icon">{_svg_icon(icon_key)}</div>
      <div><strong>{escape(label)}</strong><span>{escape(copy)}</span></div>
    </a>
    """


def _state_card(icon_key: str, label: str, value: str) -> str:
    return f"""
    <div class="state-card">
      <div class="state-icon">{_svg_icon(icon_key)}</div>
      <span>{escape(label)}</span>
      <strong>{escape(value)}</strong>
    </div>
    """


def _metric_strip(rows: tuple[tuple[str, str], ...]) -> str:
    return f"""<div class="metric-strip">{"".join(_metric(label, value) for label, value in rows)}</div>"""


def _metric(label: str, value: str) -> str:
    return f"""<div class="metric"><span>{escape(label)}</span><strong>{escape(value)}</strong></div>"""


def _context_ribbon(state: ModernReadonlyState, boundary: str) -> str:
    warning_tone = "warn" if state.warnings else "safe"
    rows = (
        ("Device", state.device.display_name or state.device.serial or "not selected", ""),
        ("Firmware", state.firmware.filename or "not selected", ""),
        ("Review", str(len(state.warnings)) if state.warnings else "clear", warning_tone),
        ("Workspace", boundary, "safe"),
    )
    return f"""
    <div class="context-ribbon" aria-label="Loaded app context">
      {"".join(_context_item(*row) for row in rows)}
    </div>
    """


def _context_item(label: str, value: str, tone: str) -> str:
    tone_class = f" {tone}" if tone in {"safe", "warn"} else ""
    return f"""<div class="context-item{tone_class}"><span>{escape(label)}</span><strong>{escape(value)}</strong></div>"""


def _empty_state(title: str, copy: str) -> str:
    return f"""
    <div class="empty-state">
      <div><strong>{escape(title)}</strong><span>{escape(copy)}</span></div>
    </div>
    """


def _check(line: str) -> str:
    return f"""<div class="check"><span>•</span><div>{escape(line)}</div></div>"""


def _mini_card(title: str, badge: str, rows: tuple[tuple[str, str], ...]) -> str:
    return f"""
    <article class="card mini-card">
      <div class="card-header"><h2>{escape(title)}</h2><span class="badge">{escape(badge)}</span></div>
      <div class="stack-list">{"".join(_mini_row(label, value) for label, value in rows)}</div>
    </article>
    """


def _explorer_card(title: str, rows: tuple[tuple[str, str], ...]) -> str:
    return f"""
    <article class="card explorer-card">
      <div class="card-header"><h2>{escape(title)}</h2><span class="badge">Details</span></div>
      <div class="stack-list">{"".join(_mini_row(label, value) for label, value in rows)}</div>
    </article>
    """


def _mini_row(label: str, value: str) -> str:
    return f"""<div class="mini-row"><span>{escape(label)}</span><strong>{escape(value)}</strong></div>"""


def _step(number: str, label: str, active: bool) -> str:
    return f"""<div class="step {'active' if active else ''}"><div class="step-circle">{escape(number)}</div><div>{escape(label)}</div></div>"""


def _wizard_readiness(title: str, rows: tuple[str, ...]) -> str:
    return f"""
    <article class="card">
      <h3>{escape(title)}</h3>
      <div class="check-list">{"".join(_check(row) for row in rows)}</div>
    </article>
    """


def _wizard_blocked(title: str, rows: tuple[str, ...]) -> str:
    return f"""
    <article class="card blocked">
      <h3>{escape(title)}</h3>
      <div class="check-list">
        {"".join(_check(row) for row in rows)}
      </div>
    </article>
    """


def _nav_rows() -> tuple[tuple[str, str, str], ...]:
    rows = []
    for key, title, detail in NAV_ITEMS:
        rows.append((key, title, detail))
    return tuple(rows)


def _nav_action_id(key: str) -> str:
    return {
        "dashboard": "open_modern_dashboard",
        "shell": "open_modern_shell",
        "wizard": "open_modern_flash_wizard",
        "backups": "open_backups",
        "downloads": "open_downloads",
        "settings": "open_settings",
        "tools": "open_tools",
        "safety": "open_safety",
        "about": "open_about",
    }.get(key, "open_modern_dashboard")


def _icon(key: str) -> str:
    return _svg_icon(key)


_SVG_ICONS: dict[str, str] = {
    "dashboard": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    "shell": '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
    "wizard": '<path d="M13 2 5 13h6l-1 9 8-12h-6l1-8z"/>',
    "flash": '<path d="M13 2 5 13h6l-1 9 8-12h-6l1-8z"/>',
    "patch": '<path d="M12 3 21 12 12 21 3 12 12 3z"/><path d="m9 12 2 2 4-5"/>',
    "backups": '<path d="M4 7h16v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7z"/><path d="M8 7V4h8v3"/><path d="M9 12h6"/>',
    "downloads": '<path d="M12 3v11"/><path d="m7 10 5 5 5-5"/><path d="M5 20h14"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2 2-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5V20h-3.6v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1-2-2 .1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H4v-3.6h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9l-.1-.1 2-2 .1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.5V4h3.6v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1 2 2-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.5 1h.1v3.6h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    "tools": '<path d="m14.7 6.3 3-3a3.5 3.5 0 0 1-4.6 4.6l-7.8 7.8a2 2 0 1 1-2.8-2.8l7.8-7.8a3.5 3.5 0 0 1 4.4-4.4l-3 3 3 3z"/>',
    "safety": '<path d="M12 3 20 6v6c0 5-3.4 8-8 9-4.6-1-8-4-8-9V6l8-3z"/><path d="m8.5 12 2.2 2.2 4.8-5"/>',
    "about": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><path d="M12 7h.01"/>',
    "scan": '<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v6h-6"/>',
    "android": '<path d="M7 10h10v8a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2v-8z"/><path d="M9 10V7a3 3 0 0 1 6 0v3"/><path d="M9 5 7.5 3"/><path d="M15 5 16.5 3"/>',
    "build": '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 8h8"/><path d="M8 12h8"/><path d="M8 16h5"/>',
    "shield": '<path d="M12 3 20 6v6c0 5-3.4 8-8 9-4.6-1-8-4-8-9V6l8-3z"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    "connection": '<path d="M7 7h10"/><path d="m14 4 3 3-3 3"/><path d="M17 17H7"/><path d="m10 14-3 3 3 3"/>',
    "source": '<circle cx="12" cy="12" r="3"/><path d="M12 3v3"/><path d="M12 18v3"/><path d="M3 12h3"/><path d="M18 12h3"/>',
}


def _svg_icon(key: str) -> str:
    paths = _SVG_ICONS.get(key)
    if not paths:
        return escape(str(key or ""))
    return f'<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">{paths}</svg>'


def _headline(page: str) -> str:
    return {
        "dashboard": "Modern UI",
        "shell": "Modern Shell",
        "wizard": "Flash Wizard",
        "backups": "Backups",
        "downloads": "Downloads",
        "settings": "Settings",
        "tools": "Tools",
        "safety": "System",
        "about": "About PixelFlasher",
    }.get(page, "Modern UI")


def _subtitle(page: str) -> str:
    return {
        "dashboard": "Manage PixelFlasher from the modern workspace.",
        "shell": "Device, firmware, and tool state in one place.",
        "wizard": "Plan firmware, options, patching, and flash execution.",
        "backups": "Browse backup context without creating, restoring, or deleting files.",
        "downloads": "Browse download context without network or device changes.",
        "settings": "Review preferences without saving changes.",
        "tools": "Open PixelFlasher tools from one workspace.",
        "safety": "Review confirmations and workspace controls.",
        "about": "Application information and Modern UI status.",
    }.get(page, "Ready.")


def _badge_markup(page: str) -> str:
    labels = {
        "dashboard": (("READY", "yellow"), ("MODERN UI", ""), ("PROTECTED", "yellow")),
        "shell": (("DEVICE STATE", ""), ("FIRMWARE", "yellow"), ("TOOLS", "yellow")),
        "wizard": (("FLASH WORKFLOW", "yellow"), ("OPTIONS", ""), ("REVIEW", "yellow")),
        "backups": (("BACKUPS", "yellow"), ("RESTORE", ""), ("SUPPORT", "yellow")),
        "downloads": (("FIRMWARE", "yellow"), ("ROOTING APP", ""), ("TOOLS", "yellow")),
        "settings": (("SETTINGS", ""), ("PREFERENCES", "yellow"), ("PROFILE", "yellow")),
        "tools": (("TOOLS", "yellow"), ("DEVICE", ""), ("ADVANCED", "yellow")),
        "safety": (("SYSTEM", ""), ("CONFIRM", "yellow"), ("LOCAL", "yellow")),
        "about": (("PIXELFLASHER", ""), ("LOCAL INFO", "yellow"), ("MODERN UI", "yellow")),
    }.get(page, (("READY", "yellow"), ("MODERN UI", "yellow")))
    return "".join(f'<span class="badge {tone}">{escape(label)}</span>' for label, tone in labels)


def _page_title(page: str) -> str:
    return {
        "dashboard": "Modern Dashboard",
        "shell": "Modern Shell",
        "wizard": "Flash Wizard",
        "backups": "Backups",
        "downloads": "Downloads",
        "settings": "Settings",
        "tools": "Tools",
        "safety": "System",
        "about": "About",
    }.get(page, "Modern UI")


def _normalize_page(page: str) -> str:
    page = str(page or "dashboard").strip().lower()
    return page if page in {"dashboard", "shell", "wizard", "backups", "downloads", "settings", "tools", "safety", "about"} else "dashboard"


def _known(value: str) -> str:
    value = str(value or "").strip()
    if not value or value.lower() == "unknown":
        return "Unknown"
    return value.title()


def _package_type(state: ModernReadonlyState) -> str:
    if not state.firmware.selected:
        return "Choose firmware"
    return {
        "factory": "Factory image",
        "ota": "OTA package",
        "custom_rom": "Custom ROM",
        "image": "Image file",
        "unknown": "unknown",
    }.get(str(state.firmware.package_type or "unknown"), str(state.firmware.package_type or "unknown"))


def _on_off(value: bool) -> str:
    return "on" if value else "off"


def _warning_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    if not state.warnings:
        return (("Status", "No warnings"), ("Ready", "yes"))
    return tuple((f"Warning {index}", warning) for index, warning in enumerate(state.warnings[:4], start=1))


def _loaded_context_rows(state: ModernReadonlyState) -> tuple[tuple[str, str], ...]:
    return (
        ("Device", state.device.display_name or state.device.serial or "Choose device"),
        ("Firmware", state.firmware.filename or "Choose firmware"),
        ("Firmware validation", "verified" if state.firmware.verified else "Ready to verify"),
        ("Warnings", str(len(state.warnings))),
    )


def _status_tone(tone: str) -> str:
    value = str(tone or "safe")
    return value if value in {"safe", "warning", "blocked"} else "safe"


def _platform_tools_label(state: ModernReadonlyState) -> str:
    if state.tools.adb_available and _bootloader_tool_available(state):
        return "ADB/Fastboot available"
    if state.tools.platform_tools_path:
        return "configured path"
    return "Set up tools"


def _needs_platform_tools_setup(state: ModernReadonlyState) -> bool:
    return not (state.tools.adb_available and _bootloader_tool_available(state))


def _bootloader_tool_available(state: ModernReadonlyState) -> bool:
    return bool(getattr(state.tools, "fast" + "boot_available"))


def _bootloader_tool_status(state: ModernReadonlyState) -> str:
    return "available" if _bootloader_tool_available(state) else "Set up tools"


def _bootloader_tool_mode(state: ModernReadonlyState) -> str:
    return "ready" if bool(getattr(state.device, "fast" + "boot_ready")) else "not connected"
