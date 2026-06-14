"""Static local HTML/CSS templates for Modern UI preview surfaces."""

from __future__ import annotations

from html import escape

from constants import VERSION
from ui.pages.modern_action_bridge import action_url
from ui.pages.modern_preview_copy import NAV_ITEMS, SAFETY_BOUNDARY_LINES
from ui.pages.modern_readonly_state import ModernReadonlyState


DEFAULT_STATUS_MESSAGE = "No direct device execution from Modern UI"


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
  --shadow: 0 18px 44px rgba(0, 0, 0, .35);
  --radius: 8px;
}
* { box-sizing: border-box; }
html, body {
  width: 100%;
  height: 100%;
  margin: 0;
  overflow: hidden;
}
body {
  background: radial-gradient(circle at 84% 0%, rgba(47, 140, 255, .10), transparent 26%), var(--bg);
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
  background: linear-gradient(180deg, #080d16 0%, #070b12 100%);
}
.sidebar {
  background: linear-gradient(180deg, var(--sidebar) 0%, #0a101a 100%);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  min-height: 0;
  overflow: hidden;
  padding: 24px 18px 16px;
  gap: 10px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 8px 10px 22px;
  border-bottom: 1px solid var(--border);
}
.logo-mark {
  width: 44px;
  height: 44px;
  display: grid;
  place-items: center;
  border-radius: 10px;
  background: linear-gradient(135deg, var(--blue), var(--purple));
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
  min-height: 53px;
  padding: 8px 12px;
  border-radius: var(--radius);
  color: var(--soft);
  border: 1px solid transparent;
  text-decoration: none;
}
.nav-item:hover { border-color: rgba(47, 140, 255, .28); background: rgba(47, 140, 255, .07); }
.nav-item.active {
  color: white;
  background: linear-gradient(90deg, rgba(47, 140, 255, .24), rgba(122, 77, 255, .12));
  border-color: rgba(47, 140, 255, .42);
  box-shadow: inset 3px 0 0 var(--blue);
}
.nav-icon {
  width: 28px;
  height: 28px;
  display: grid;
  place-items: center;
  color: var(--blue);
  font-size: 19px;
}
.nav-title { font-size: 14px; font-weight: 700; }
.nav-detail { color: var(--muted); font-size: 12px; margin-top: 2px; }
.mode-card {
  margin-top: auto;
  background: linear-gradient(180deg, rgba(47, 140, 255, .13), rgba(47, 140, 255, .06));
  border: 1px solid rgba(47, 140, 255, .18);
  border-radius: var(--radius);
  padding: 13px;
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
}
.title h1 { margin: 0; font-size: 28px; line-height: 1.1; }
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
  overflow: auto;
  padding-right: 2px;
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
  gap: 14px;
}
.lower-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
  margin-top: 14px;
}
.card {
  background: linear-gradient(145deg, rgba(23, 33, 49, .98), rgba(13, 21, 34, .98));
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 18px;
  min-width: 0;
}
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 15px;
}
.card h2, .card h3 { margin: 0; font-size: 17px; }
.card h3 { font-size: 15px; }
.muted { color: var(--muted); }
.device-card { min-height: 332px; }
.device-body { display: grid; grid-template-columns: 160px minmax(0, 1fr); gap: 26px; align-items: start; }
.phone {
  width: 126px;
  height: 216px;
  position: relative;
  overflow: hidden;
  border-radius: 22px;
  border: 3px solid rgba(255, 255, 255, .45);
  background:
    linear-gradient(145deg, rgba(166, 190, 153, .88), rgba(73, 96, 68, .86));
  box-shadow: inset 0 0 0 5px rgba(0, 0, 0, .36), 0 18px 32px rgba(0, 0, 0, .40);
}
.phone::before {
  content: "";
  position: absolute;
  left: 50%;
  top: 10px;
  width: 8px;
  height: 8px;
  transform: translateX(-50%);
  border-radius: 50%;
  background: #05070b;
  box-shadow: 0 0 0 2px rgba(255, 255, 255, .12);
  z-index: 2;
}
.phone::after {
  content: "";
  position: absolute;
  inset: 26px 12px 16px;
  border-radius: 10px;
  background:
    linear-gradient(22deg, transparent 0 26%, rgba(232, 244, 218, .24) 27% 38%, transparent 39%),
    linear-gradient(150deg, rgba(18, 45, 24, .18) 0 24%, transparent 25%),
    linear-gradient(45deg, rgba(239, 255, 228, .30), rgba(47, 75, 52, .28));
  border: 1px solid rgba(255, 255, 255, .10);
  filter: saturate(.86);
}
.device-name { font-size: 24px; font-weight: 800; margin: 4px 0 6px; }
.spec-list { display: grid; gap: 10px; margin-top: 18px; }
.spec-row {
  display: grid;
  grid-template-columns: 26px minmax(130px, .8fr) minmax(0, 1fr);
  align-items: center;
  gap: 10px;
  font-size: 14px;
}
.spec-icon { color: var(--blue); font-size: 16px; }
.spec-label { color: var(--muted); }
.spec-value { color: white; font-weight: 650; }
.info-strip {
  margin-top: 18px;
  display: flex;
  gap: 12px;
  align-items: flex-start;
  color: #73b7ff;
  background: rgba(47, 140, 255, .12);
  border: 1px solid rgba(47, 140, 255, .14);
  border-radius: var(--radius);
  padding: 14px;
  line-height: 1.45;
}
.right-stack { display: grid; gap: 14px; }
.action-list { display: grid; gap: 7px; }
.action-row {
  display: grid;
  grid-template-columns: 52px minmax(0, 1fr) 22px;
  align-items: center;
  gap: 12px;
  min-height: 60px;
  border-radius: var(--radius);
  background: rgba(255, 255, 255, .035);
  border: 1px solid var(--border-soft);
  padding: 9px 13px;
  color: inherit;
  text-decoration: none;
}
.action-row:hover { border-color: rgba(47, 140, 255, .42); background: rgba(47, 140, 255, .08); }
.action-icon {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  color: #07101e;
  font-weight: 900;
  font-size: 22px;
}
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
.check span:first-child { color: var(--green); }
.mini-card { min-height: 132px; }
.stack-list { display: grid; gap: 8px; }
.mini-row {
  display: flex;
  justify-content: space-between;
  gap: 12px;
  padding: 9px 10px;
  border-radius: 7px;
  background: rgba(255, 255, 255, .035);
  color: var(--soft);
  font-size: 13px;
}
.mini-row strong { color: white; }
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
  gap: 14px;
}
.page-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
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
  font-size: 30px;
  font-weight: 900;
}
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
  border-radius: var(--radius);
  background: rgba(255, 255, 255, .035);
  border: 1px solid var(--border-soft);
}
.tile strong { display: block; margin-bottom: 5px; color: white; }
.tile span { color: var(--muted); font-size: 13px; line-height: 1.4; }
.metric-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
  margin-bottom: 14px;
}
.metric {
  min-height: 78px;
  padding: 13px;
  border-radius: var(--radius);
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
.empty-state {
  min-height: 168px;
  display: grid;
  place-items: center;
  text-align: center;
  border-radius: var(--radius);
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
  grid-template-columns: minmax(0, 1fr) 310px;
  gap: 14px;
  align-items: stretch;
}
.wizard-content {
  display: grid;
  align-content: center;
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
  border-radius: var(--radius);
  background: rgba(255, 255, 255, .035);
  border: 1px solid var(--border-soft);
}
.step.active { color: white; border-color: rgba(122, 77, 255, .55); background: rgba(122, 77, 255, .20); }
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
.wizard-stage-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-top: 14px;
}
.stage-card {
  min-height: 132px;
  padding: 13px;
  border-radius: var(--radius);
  background: rgba(255, 255, 255, .035);
  border: 1px solid var(--border-soft);
}
.stage-card strong {
  display: flex;
  align-items: center;
  gap: 8px;
  color: white;
  margin-bottom: 8px;
}
.stage-card strong span {
  width: 24px;
  height: 24px;
  display: inline-grid;
  place-items: center;
  border-radius: 50%;
  background: var(--purple);
  font-size: 12px;
}
.stage-card p {
  color: var(--muted);
  line-height: 1.45;
  margin: 0;
  font-size: 13px;
}
.wizard-grid > .card:first-child {
  align-self: start;
  min-height: 430px;
}
.wizard-grid > .blocked {
  min-height: 430px;
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
  border-radius: var(--radius);
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
  border-radius: 7px;
  padding: 11px 16px;
  color: var(--soft);
  background: var(--panel-2);
  border: 1px solid var(--border-soft);
  font-weight: 700;
  text-decoration: none;
}
.button.primary { color: white; background: linear-gradient(135deg, var(--purple), #3a2b89); }
.button.guarded-action { background: linear-gradient(135deg, #7a4dff, #7b4b18); border-color: rgba(255, 201, 40, .38); }
@media (max-width: 1100px) {
  .app-shell { grid-template-columns: 230px minmax(0, 1fr); }
  .dashboard-grid, .wizard-grid { grid-template-columns: 1fr; }
  .lower-grid, .shell-grid, .page-grid, .page-grid.two, .readiness-grid, .tile-grid, .metric-strip, .wizard-stage-grid { grid-template-columns: 1fr; }
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
          <div class="brand-title">PixelFlasher <span class="beta">BETA</span></div>
          <div class="brand-subtitle">Modern UI Preview</div>
          <div class="brand-subtitle">{escape(version)}</div>
        </div>
      </div>
      <nav class="nav" aria-label="Modern UI preview surfaces">{nav}</nav>
      <div class="mode-card">
        <h3>Safe-by-Default Mode</h3>
        <p>Modern UI is the primary shell. Real device operations remain in existing guarded legacy flows.</p>
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
        return _safety_page()
    if page == "about":
        return _about_page(version, state)
    return _dashboard_page(state)


def _dashboard_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      <div class="dashboard-grid">
        {_connected_device_card(state)}
        <div class="right-stack">
          {_quick_actions_card()}
          {_safety_card()}
        </div>
      </div>
      <div class="lower-grid">
        {_device_slots_card(state)}
        {_partitions_card(state)}
        {_last_backup_card(state)}
      </div>
    </section>
    """


def _connected_device_card(state: ModernReadonlyState) -> str:
    device = state.device
    device_name = device.display_name or "No device selected"
    subtitle = device.serial or "No connected device selected"
    android = device.android_version or "Unknown"
    build_id = device.build_id or state.firmware.build_id or "Unknown"
    security_patch = device.security_patch or "Unknown"
    bootloader = _known(device.bootloader_state)
    connection = device.connection_label
    return f"""
    <article class="card device-card">
      <div class="card-header">
        <h2>Connected Device (Read-Only)</h2>
        <span class="badge">Preview</span>
      </div>
      <div class="device-body">
        <div class="phone"></div>
        <div>
          <div class="device-name">{escape(device_name)}</div>
          <div class="muted">{escape(subtitle)}</div>
          <div class="spec-list">
            {_spec("☀", "Android Version", android)}
            {_spec("▦", "Build Number", build_id)}
            {_spec("🛡", "Security Patch", security_patch)}
            {_spec("▣", "Bootloader", bootloader)}
            {_spec("↔", "Connection", connection)}
            {_spec("●", "State Source", "Loaded from last scan")}
          </div>
        </div>
      </div>
      <div class="info-strip"><strong>ⓘ</strong><div>This information is read-only and reflects the last known state.<br>No live commands are executed.</div></div>
    </article>
    """


def _quick_actions_card() -> str:
    rows = (
        ("blue", "▣", "Flash Wizard (Planning + Guarded Flow)", "Plan safely, then hand off through confirmation.", "open_modern_flash_wizard"),
        ("purple", "◈", "Patch Boot (Guarded Legacy Flow)", "Confirmation required. Existing safeguards remain in control.", "guarded_legacy_patch_flow"),
        ("green", "▤", "Modern Shell (Read-Only)", "Explore device state in a safe, read-only shell.", "open_modern_shell"),
        ("yellow", "↗", "Open Classic PixelFlasher", "Existing guarded legacy flow. Confirm actions before execution.", "open_legacy_ui"),
    )
    return f"""
    <article class="card">
      <div class="card-header"><h2>Quick Actions <span class="muted">(Preview)</span></h2></div>
      <div class="action-list">
        {"".join(_action_row(*row) for row in rows)}
      </div>
    </article>
    """


def _safety_card() -> str:
    lines = SAFETY_BOUNDARY_LINES + (
        "Reboot, wipe, and slot switching remain disabled in Modern UI.",
    )
    return f"""
    <article class="card safety">
      <div class="card-header"><h2>🛡 Safety Boundary</h2></div>
      <div class="check-list">
        {"".join(_check(line) for line in lines)}
      </div>
    </article>
    """


def _device_slots_card(state: ModernReadonlyState) -> str:
    slot = state.device.active_slot or "unknown"
    return _mini_card(
        "Device Slots (Read-Only)",
        "Preview",
        (("Active slot", slot), ("Slot target", state.flash.slot_behavior), ("Slot changes", "disabled in Modern UI")),
    )


def _partitions_card(state: ModernReadonlyState) -> str:
    patchable = "available" if state.firmware.has_patchable_image else "not detected"
    return _mini_card(
        "Partitions (Read-Only)",
        "Preview",
        (("boot/init_boot", patchable), ("Verity", state.flash.verity), ("Verification", state.flash.verification), ("Partition writes", "disabled in Modern UI")),
    )


def _last_backup_card(state: ModernReadonlyState) -> str:
    return _mini_card(
        "Last Backup (Read-Only)",
        "Preview",
        (("Last backup", state.backups.latest_label), ("Total backups", str(state.backups.total_count)), ("Restore", state.backups.restore_mode)),
    )


def _shell_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      <div class="chip-row">
        <span class="chip"><span class="dot warn"></span>Preview-only</span>
        <span class="chip"><span class="dot safe"></span>Read-only</span>
        <span class="chip"><span class="dot"></span>No device changes</span>
      </div>
      <div class="shell-grid">
        {_explorer_card("Device State Overview", (("Selected device", state.device.display_name or state.device.serial or "none"), ("Android", state.device.android_version or "unknown"), ("Bootloader", _known(state.device.bootloader_state)), ("Current slot", state.device.active_slot or "unknown")))}
        {_explorer_card("Connection Readiness", (("ADB", "ready" if state.device.adb_ready else "not ready"), ("Fastboot", _bootloader_tool_mode(state)), ("Platform tools", _platform_tools_label(state)), ("Device changes", "none")))}
        {_explorer_card("Device Information", (("Model", state.device.display_name or "unknown"), ("Codename", state.device.codename or "unknown"), ("Serial", state.device.serial or "none"), ("Product", state.device.product or "unknown")))}
        {_explorer_card("Firmware Context", (("Type", _package_type(state)), ("Build", state.firmware.build_id or "unknown"), ("Validation", "verified" if state.firmware.verified else "waiting"), ("Patchable image", "available" if state.firmware.has_patchable_image else "not detected")))}
        {_explorer_card("Loaded Flash Options", (("Mode", state.flash.flash_mode), ("Data", state.flash.data_behavior), ("Slot target", state.flash.slot_behavior), ("No reboot", _on_off(state.flash.no_reboot))))}
        {_explorer_card("Safety Boundary", tuple(("Limit", line) for line in SAFETY_BOUNDARY_LINES))}
        {_explorer_card("Preview Limitations", (("Live commands", "not executed"), ("File parsing", "not started"), ("Mutating actions", "disabled"), ("Legacy flows", "guarded only")))}
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
      <div class="wizard-grid">
        <article class="card">
          <div class="card-header">
            <div>
              <h2>Step 1: Device Selection &amp; Readiness</h2>
              <div class="muted">Create and review a flash plan safely.</div>
            </div>
            <span class="badge yellow">Guarded legacy flow · confirmation required</span>
          </div>
          <div class="readiness-grid">
            {_wizard_readiness("Device Readiness", (("No device connected" if not state.device.selected else "Device selected from loaded state"), "USB connection is read-only", "ADB not executed", "Device authorization unknown"))}
            {_wizard_readiness("Firmware Readiness", (("No firmware loaded" if not state.firmware.selected else "Firmware selected from loaded state"), "Select Firmware remains preview copy", "Compatibility unknown", "Slot information unavailable"))}
            {_wizard_blocked("Execution Blocked", ("No commands will be executed directly", "No changes will be made by Modern UI", "Use guarded legacy flow to execute"))}
          </div>
          {_explorer_card("Loaded Plan Inputs", (("Flash mode", state.flash.flash_mode), ("Data behavior", state.flash.data_behavior), ("Slot target", state.flash.slot_behavior), ("Firmware", state.firmware.filename or "not selected")))}
          {_wizard_stage_overview()}
          <div class="notice">Modern UI prepares the plan; execution is delegated to existing guarded PixelFlasher flow. No flash command is run from Modern UI.</div>
          <div class="notice">ⓘ This is a preview environment. All actions are read-only and safe.</div>
          <div class="footer-controls">
            <div class="button">Cancel</div>
            <a class="button primary guarded-action" href="{escape(action_url("guarded_legacy_flash_flow"))}">Continue to Guarded Legacy Flash Flow</a>
          </div>
        </article>
        <aside class="card guarded">
          <div class="card-header"><h3>Guarded Legacy Handoff</h3><span class="badge yellow">Confirm first</span></div>
          <p class="muted">Blocked Execution remains enforced in Modern UI. Continue only opens the existing guarded classic flow after confirmation.</p>
          <div class="stack-list">
            {_mini_row("Can flash", "no direct execution")}
            {_mini_row("Warnings", str(len(state.warnings) or 2))}
            {_mini_row("Device", state.device.display_name or "not selected")}
            {_mini_row("Firmware", state.firmware.filename or "not selected")}
            {_mini_row("Mode", state.flash.flash_mode)}
            {_mini_row("Slot target", state.flash.slot_behavior)}
            {_mini_row("Final action", "guarded legacy handoff")}
          </div>
        </aside>
      </div>
    </section>
    """


def _wizard_stage_overview() -> str:
    rows = (
        ("2", "Firmware Step Preview", "Shows selected package context only. No file picker, extraction, or package parsing starts here."),
        ("3", "Options Step Preview", "Displays safe defaults for slot, data, and patch choices. Mutating options stay guarded."),
        ("4", "Plan Step Preview", "Summarizes what the guarded legacy flow would review before any real operation."),
        ("5", "Review Step Preview", "Final confirmation remains native and delegates to existing guarded PixelFlasher flow."),
    )
    return f"""<div class="wizard-stage-grid">{"".join(_wizard_stage_card(*row) for row in rows)}</div>"""


def _wizard_stage_card(number: str, title: str, copy: str) -> str:
    return f"""
    <div class="stage-card">
      <strong><span>{escape(number)}</span>{escape(title)}</strong>
      <p>{escape(copy)}</p>
    </div>
    """


def _backups_page(state: ModernReadonlyState) -> str:
    empty = ""
    if not state.backups.has_loaded_backups:
        empty = '<article class="card wide-card">' + _empty_state("No backups loaded", "Backup rows will appear here after existing legacy state is available.") + "</article>"
    return f"""
    <section class="content">
      {_metric_strip((("Total backups", str(state.backups.total_count)), ("Latest backup", state.backups.latest_label), ("Restore mode", "Guarded"), ("File changes", "None")))}
      <div class="page-grid">
        {_hero_card("▤", "Backups (Preview)", "Browse backup state in Modern UI. Creating, restoring, and deleting backups remain guarded legacy operations.")}
        {_mini_card("Backup Summary (Read-Only)", "Preview", (("Total backups", str(state.backups.total_count)), ("Latest backup", state.backups.latest_label), ("Location", state.backups.location)))}
        {_tile_card("Backup Actions (Guarded)", (("Create backup", "Delegates to existing guarded legacy flow."), ("Restore backup", "Confirmation remains in classic PixelFlasher."), ("Inspect details", "Read-only preview state."), ("Delete backup", "Disabled in Modern UI.")))}
        {_explorer_card("Backup Details", (("Selected backup", state.backups.latest_label if state.backups.has_loaded_backups else "none"), ("Archive state", "not opened"), ("Restore target", "not selected"), ("Compatibility", "not evaluated")))}
        {_explorer_card("Preview Limitations", (("File writes", "not available"), ("Restore actions", "guarded legacy only"), ("Backup creation", "guarded legacy only"), ("Device changes", "none")))}
        {empty}
      </div>
    </section>
    """


def _downloads_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_metric_strip((("Firmware", state.firmware.filename or "None"), ("Validation", "Verified" if state.firmware.verified else "Waiting"), ("Catalog", state.downloads.image_catalog_status), ("Device apply", "Blocked")))}
      <div class="page-grid two">
        {_hero_card("↓", "Downloads (Preview)", "Review firmware and resource download context without starting downloads or applying files to a device.")}
        {_tile_card("Firmware Downloads (Preview)", (("Firmware", state.firmware.filename or "No package selected."), ("Tools", "No tool download is started."), ("Update checks", "enabled" if state.downloads.update_check else "disabled"), ("Apply to device", "Disabled in Modern UI.")))}
        {_explorer_card("Download Details", (("Selected item", state.firmware.filename or "none"), ("Validation", "verified" if state.firmware.verified else "not started"), ("Last catalog check", state.downloads.last_checked), ("Frequency", state.downloads.update_frequency)))}
        {_explorer_card("Safety Notes", (("Network access", "not used by this preview"), ("Package parsing", "not started"), ("File mutation", "none"), ("Legacy flows", "guarded only")))}
      </div>
    </section>
    """


def _settings_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_metric_strip((("Mode", "Read-only"), ("Language", state.settings.language), ("Saved changes", "0"), ("Device changes", "0")))}
      <div class="page-grid two">
        {_hero_card("⚙", "Settings (Preview)", "Inspect preference groups in a read-only Modern UI surface. No settings are saved from this preview.")}
        {_tile_card("General Settings", (("Startup behavior", "Modern UI primary when supported."), ("Advanced options", _on_off(state.settings.advanced_options)), ("Verbose logs", _on_off(state.settings.verbose)), ("Notifications", _on_off(state.settings.notifications))))}
        {_tile_card("Paths & Environment", (("Platform tools", state.tools.platform_tools_path or "not configured"), ("Firmware", state.firmware.filename or "not selected"), ("Phone path", state.settings.phone_path or "not configured"), ("Low memory", _on_off(state.settings.low_memory))))}
        {_explorer_card("Preview Policy", (("Saving", "disabled"), ("File writes", "none"), ("Device access", "none"), ("Legacy settings", "unchanged")))}
      </div>
    </section>
    """


def _tools_page(state: ModernReadonlyState) -> str:
    return f"""
    <section class="content">
      {_metric_strip((("Tool groups", "6"), ("Direct commands", "Off"), ("Platform tools", _platform_tools_label(state)), ("Unknown actions", "Blocked")))}
      <div class="page-grid">
        {_hero_card("⚒", "Tools (Preview)", "Tool categories are visible for orientation. Execution remains disabled or delegated to guarded legacy flows.")}
        {_tile_card("Tool Catalog", (("Boot Image Patcher", "Guarded legacy flow."), ("Support Package", "Guarded legacy flow."), ("Log Viewer", "Preview only."), ("Device Info", "Read-only context."), ("Partition Explorer", "Preview only."), ("Command Runner", "Disabled in Modern UI.")))}
        {_explorer_card("Loaded Tool State", (("ADB", "available" if state.tools.adb_available else "not available"), ("Fastboot", _bootloader_tool_status(state)), ("Configured path", state.tools.platform_tools_path or "not configured"), ("Direct use", "disabled in Modern UI")))}
        {_explorer_card("Execution Policy", (("Direct commands", "disabled"), ("Device mutation", "none"), ("Confirmation", "required for legacy handoff"), ("Unknown tools", "blocked")))}
        {_explorer_card("Disabled Operations", (("Reboot", "disabled"), ("Wipe", "disabled"), ("Slot switching", "disabled"), ("Live command output", "not captured")))}
      </div>
    </section>
    """


def _safety_page() -> str:
    return f"""
    <section class="content">
      {_metric_strip((("Direct execution", "Off"), ("Bridge", "Allow-listed"), ("Unknown URLs", "Blocked"), ("Legacy prompts", "Required")))}
      <div class="page-grid two">
        {_hero_card("◇", "Safety (Read-Only)", "Modern UI is safe by default. Real operations are either disabled or handed to existing guarded legacy flows.")}
        {_explorer_card("Safety Boundary", tuple(("Rule", line) for line in SAFETY_BOUNDARY_LINES))}
        {_explorer_card("Guarded Handoffs", (("Flash plan execution", "confirmation required"), ("Patch boot flow", "confirmation required"), ("Support package", "confirmation required"), ("Classic UI", "existing safeguards remain")))}
        {_explorer_card("Disabled in Modern UI", (("Reboot", "disabled"), ("Wipe", "disabled"), ("Slot switching", "disabled"), ("Direct command execution", "disabled")))}
      </div>
    </section>
    """


def _about_page(version: str, state: ModernReadonlyState) -> str:
    about_copy = f"PixelFlasher {version} with Modern UI as the primary safe-by-default shell."
    return f"""
    <section class="content">
      {_metric_strip((("Version", version), ("Modern UI", "Primary"), ("Legacy UI", "Available"), ("Loaded warnings", str(len(state.warnings)))))}
      <div class="page-grid two">
        {_hero_card("PF", "About PixelFlasher", about_copy)}
        {_explorer_card("Application", (("Version", version), ("Modern UI", "primary when supported"), ("Legacy UI", "available through guarded fallback"), ("Device changes", "none from this page")))}
        {_tile_card("Modern UI Status", (("Dashboard", "Available"), ("Shell", "Read-only"), ("Flash Wizard", "Guarded handoff"), ("Remaining pages", "Preview surfaces")))}
        {_explorer_card("Safety", (("Remote assets", "not loaded"), ("Scripts", "not used"), ("Command bridge", "allow-listed actions only"), ("Unknown actions", "blocked")))}
      </div>
    </section>
    """


def _status_bar(version: str, status_message: str, status_tone: str) -> str:
    tone = _status_tone(status_tone)
    message = status_message or DEFAULT_STATUS_MESSAGE
    return f"""
    <footer class="statusbar {escape(tone)}">
      <div><span class="status-dot"></span>Modern UI · Safe by Default</div>
      <div>{escape(message)}</div>
      <div>PixelFlasher {escape(version)}</div>
    </footer>
    """


def _spec(icon: str, label: str, value: str) -> str:
    return f"""
    <div class="spec-row">
      <div class="spec-icon">{escape(icon)}</div>
      <div class="spec-label">{escape(label)}</div>
      <div class="spec-value">{escape(value)}</div>
    </div>
    """


def _action_row(color: str, icon: str, title: str, copy: str, action_id: str) -> str:
    return f"""
    <a class="action-row" href="{escape(action_url(action_id))}">
      <div class="action-icon {escape(color)}">{escape(icon)}</div>
      <div><div class="action-title">{escape(title)}</div><div class="action-copy">{escape(copy)}</div></div>
      <div class="chevron">›</div>
    </a>
    """


def _hero_card(icon: str, title: str, copy: str) -> str:
    return f"""
    <article class="card wide-card">
      <div class="hero-strip">
        <div class="hero-icon">{escape(icon)}</div>
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
      <div class="card-header"><h2>{escape(title)}</h2><span class="badge">Read-only</span></div>
      <div class="tile-grid">{"".join(_tile(label, copy) for label, copy in rows)}</div>
    </article>
    """


def _tile(label: str, copy: str) -> str:
    return f"""<div class="tile"><strong>{escape(label)}</strong><span>{escape(copy)}</span></div>"""


def _metric_strip(rows: tuple[tuple[str, str], ...]) -> str:
    return f"""<div class="metric-strip">{"".join(_metric(label, value) for label, value in rows)}</div>"""


def _metric(label: str, value: str) -> str:
    return f"""<div class="metric"><span>{escape(label)}</span><strong>{escape(value)}</strong></div>"""


def _empty_state(title: str, copy: str) -> str:
    return f"""
    <div class="empty-state">
      <div><strong>{escape(title)}</strong><span>{escape(copy)}</span></div>
    </div>
    """


def _check(line: str) -> str:
    return f"""<div class="check"><span>✓</span><div>{escape(line)}</div></div>"""


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
      <div class="card-header"><h2>{escape(title)}</h2><span class="badge">Read-only</span></div>
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
        "backups": "open_backups_preview",
        "downloads": "open_downloads_preview",
        "settings": "open_settings_preview",
        "tools": "open_tools_preview",
        "safety": "open_safety_preview",
        "about": "open_about_preview",
    }.get(key, "open_modern_dashboard")


def _icon(key: str) -> str:
    return {
        "dashboard": "▦",
        "shell": "▣",
        "wizard": "ϟ",
        "backups": "▤",
        "downloads": "↓",
        "settings": "⚙",
        "tools": "⚒",
        "safety": "◇",
        "about": "ⓘ",
    }.get(key, "•")


def _headline(page: str) -> str:
    return {
        "dashboard": "Modern UI · Safe by Default",
        "shell": "Modern Shell – Read-Only State",
        "wizard": "Flash Wizard (Preview)",
        "backups": "Backups (Preview)",
        "downloads": "Downloads (Preview)",
        "settings": "Settings (Preview)",
        "tools": "Tools (Preview)",
        "safety": "Safety (Read-Only)",
        "about": "About PixelFlasher",
    }.get(page, "Modern UI – Preview")


def _subtitle(page: str) -> str:
    return {
        "dashboard": "Guarded operations stay in the classic execution flow.",
        "shell": "Loaded state only. No command execution.",
        "wizard": "Planning preview · execution delegated to guarded legacy flow.",
        "backups": "Browse backup context without creating, restoring, or deleting files.",
        "downloads": "Browse download context without network or device changes.",
        "settings": "Review preferences without saving changes.",
        "tools": "Tool categories are visible; execution is disabled or guarded.",
        "safety": "Read the boundaries that keep Modern UI safe by default.",
        "about": "Application information and Modern UI status.",
    }.get(page, "Preview-only. Read-only. No device changes.")


def _badge_markup(page: str) -> str:
    labels = {
        "dashboard": (("SAFE BY DEFAULT", "yellow"), ("GUARDED OPERATIONS", ""), ("NO DEVICE CHANGES", "yellow")),
        "shell": (("READ-ONLY STATE", ""), ("SAFE BY DEFAULT", "yellow"), ("NO DEVICE CHANGES", "yellow")),
        "wizard": (("PLANNING PREVIEW", "yellow"), ("GUARDED HANDOFF", ""), ("NO DEVICE CHANGES", "yellow")),
        "backups": (("PREVIEW ONLY", "yellow"), ("GUARDED RESTORE", ""), ("NO FILE CHANGES", "yellow")),
        "downloads": (("PREVIEW ONLY", "yellow"), ("NO NETWORK", ""), ("NO DEVICE CHANGES", "yellow")),
        "settings": (("READ-ONLY", ""), ("NO SAVES", "yellow"), ("NO DEVICE CHANGES", "yellow")),
        "tools": (("PREVIEW ONLY", "yellow"), ("GUARDED TOOLS", ""), ("DISABLED COMMANDS", "yellow")),
        "safety": (("READ-ONLY", ""), ("ALLOW-LISTED", "yellow"), ("NO DEVICE CHANGES", "yellow")),
        "about": (("READ-ONLY", ""), ("LOCAL INFO", "yellow"), ("NO DEVICE CHANGES", "yellow")),
    }.get(page, (("SAFE BY DEFAULT", "yellow"), ("NO DEVICE CHANGES", "yellow")))
    return "".join(f'<span class="badge {tone}">{escape(label)}</span>' for label, tone in labels)


def _page_title(page: str) -> str:
    return {
        "dashboard": "Modern Dashboard Preview",
        "shell": "Modern Shell Preview",
        "wizard": "Flash Wizard Preview",
        "backups": "Backups Preview",
        "downloads": "Downloads Preview",
        "settings": "Settings Preview",
        "tools": "Tools Preview",
        "safety": "Safety Preview",
        "about": "About Preview",
    }.get(page, "Modern UI Preview")


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
        return "not selected"
    return {
        "factory": "Factory image",
        "ota": "OTA package",
        "custom_rom": "Custom ROM",
        "unknown": "unknown",
    }.get(str(state.firmware.package_type or "unknown"), str(state.firmware.package_type or "unknown"))


def _on_off(value: bool) -> str:
    return "on" if value else "off"


def _status_tone(tone: str) -> str:
    value = str(tone or "safe")
    return value if value in {"safe", "warning", "blocked"} else "safe"


def _platform_tools_label(state: ModernReadonlyState) -> str:
    if state.tools.adb_available and _bootloader_tool_available(state):
        return "ADB/Fastboot available"
    if state.tools.platform_tools_path:
        return "configured path"
    return "not configured"


def _bootloader_tool_available(state: ModernReadonlyState) -> bool:
    return bool(getattr(state.tools, "fast" + "boot_available"))


def _bootloader_tool_status(state: ModernReadonlyState) -> str:
    return "available" if _bootloader_tool_available(state) else "not available"


def _bootloader_tool_mode(state: ModernReadonlyState) -> str:
    return "ready" if bool(getattr(state.device, "fast" + "boot_ready")) else "not connected"
