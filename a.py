"""
Confluence Device Table Viewer
=====================================
Fetches the device table from Confluence and serves it locally at http://localhost:8080

Usage:
  1. Set your credentials below (or use environment variables)
  2. Run:  python a.py
  3. Open:  http://localhost:8080
"""

import os
import re
import json
import base64
import platform
import threading
import subprocess
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import requests
from requests.auth import HTTPBasicAuth
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# ── Load credentials from /etc/a-app.env ─────────────────────────────────────
ENV_FILE = "/etc/a-app.env"


def load_env_file(path: str) -> None:
    """Read a simple KEY=VALUE file and load it into os.environ.

    Ignores blank lines and comments (#). Surrounding quotes on the value
    are stripped. Missing file is not fatal — os.getenv just returns None.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                # allow shell-style "export KEY=VALUE" lines
                if key.startswith("export "):
                    key = key[len("export "):].strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except FileNotFoundError:
        print(f"⚠️  Env file not found: {path}")
    except Exception as e:
        print(f"⚠️  Could not read env file {path}: {e}")


load_env_file(ENV_FILE)

# ── Configuration ────────────────────────────────────────────────────────────
CONFLUENCE_BASE = os.getenv("CONFLUENCE_BASE", "https://your-domain.atlassian.net/wiki")
PAGE_ID = os.getenv("CONFLUENCE_PAGE_ID", "35527991917")
EMAIL = os.getenv("ATLASSIAN_EMAIL")
API_TOKEN = os.getenv("ATLASSIAN_API_TOKEN")
PORT = 8080
PING_TIMEOUT_MS = 800
SCAN_HOST_TIMEOUT = "90s"   # nmap gives up on a single host after this
SCAN_PROC_TIMEOUT = 150     # hard kill for the whole nmap process (seconds)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
# ─────────────────────────────────────────────────────────────────────────────


def is_valid_ipv4(ip: str) -> bool:
    """Strictly validate a dotted-quad IPv4 address before it ever reaches subprocess."""
    match = IPV4_RE.match(ip)
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def ping_host(ip: str) -> bool:
    """Ping a single host once and return True if it responded."""
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, PING_TIMEOUT_MS // 1000)), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(PING_TIMEOUT_MS / 1000) + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def run_port_scan(ip: str) -> dict:
    """Run an nmap TCP connect scan over the top-1000 most common ports.

    Uses -sT (connect scan) so it needs no root, and -Pn so devices that
    don't answer ping are still probed. Returns a dict with
    an "ports" list of {port, proto, service} or an "error" string.
    """
    cmd = [
        "nmap",
        "-sT",                              # TCP connect scan — no root needed
        "-T4",                              # faster timing template
        "-Pn",                              # skip host discovery / ping
        "--open",                           # only report open ports
        "--host-timeout", SCAN_HOST_TIMEOUT,
        "-oG", "-",                         # grepable output to stdout
        ip,
    ]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SCAN_PROC_TIMEOUT,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return {"error": "scan timed out"}
    except FileNotFoundError:
        return {"error": "nmap is not installed on the server"}
    except Exception as e:
        return {"error": str(e)}

    ports = []
    for line in result.stdout.splitlines():
        if "Ports:" not in line:
            continue
        segment = line.split("Ports:", 1)[1].split("Ignored State:", 1)[0]
        for token in segment.split(","):
            fields = token.strip().split("/")
            # fields: port / state / proto / owner / service / rpc / version
            if len(fields) < 3 or fields[1] != "open":
                continue
            ports.append({
                "port": fields[0],
                "proto": fields[2],
                "service": fields[4] if len(fields) > 4 and fields[4] else "—",
            })
    return {"ports": ports}


def fetch_page_html() -> str:
    """Fetch the rendered HTML body of the Confluence page."""
    url = f"{CONFLUENCE_BASE}/rest/api/content/{PAGE_ID}?expand=body.export_view"
    resp = requests.get(
        url,
        auth=HTTPBasicAuth(EMAIL, API_TOKEN),
        headers={"Accept": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["body"]["export_view"]["value"]


def extract_tables(html: str) -> str:
    """Pull every <table>…</table> block out of the page HTML."""
    tables = re.findall(r"<table[\s\S]*?</table>", html, re.IGNORECASE)
    if not tables:
        return "<p style='color:#888;'>No tables found on this page.</p>"
    return "\n".join(tables)


def load_logo_base64() -> str:
    """Load the logo as a base64 data URI, or return empty string."""
    logo_path = os.path.join(SCRIPT_DIR, "logo.png")
    try:
        with open(logo_path, "rb") as f:
            data = base64.b64encode(f.read()).decode("utf-8")
        return f"data:image/png;base64,{data}"
    except Exception:
        return ""


def build_full_page(table_html: str, logo_data_uri: str, fetched_at: str) -> str:
    """Wrap the raw table HTML in a styled, responsive page with dark/light mode toggle."""
    logo_tag = (
        f'<img src="{logo_data_uri}" alt="Logo" class="logo">'
        if logo_data_uri else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Device Table Viewer</title>
  <style>
    /* ── Theme tokens ─────────────────────────────────────── */
    :root {{
      --bg:         #eef2f7;
      --bg2:        #ffffff;
      --bg2-rgb:    255,255,255;
      --border:     #d8dfea;
      --text:       #172b4d;
      --text2:      #5e6c84;
      --th-bg:      linear-gradient(100deg, #0047b3 0%, #0091ff 100%);
      --th-text:    #ffffff;
      --hover:      #e3f0ff;
      --input-bg:   #ffffff;
      --input-bd:   #c3d0e3;
      --shadow:     rgba(30,64,175,0.12);
      --badge-bg:   #dbeafe;
      --badge-tx:   #1e40af;
      --toggle-bg:  #c3d0e3;
      --link:       #0057d9;
      --stripe:     #f4f8ff;
      --accent:     #0066ff;
      --accent2:    #22c55e;
      --scrollbar:  #b9c6db;
    }}
    [data-theme="dark"] {{
      --bg:         #0a0e17;
      --bg2:        #141a26;
      --bg2-rgb:    20,26,38;
      --border:     #263047;
      --text:       #e6edf3;
      --text2:      #8b98a8;
      --th-bg:      linear-gradient(100deg, #123a7a 0%, #1c5cd6 100%);
      --th-text:    #eef4ff;
      --hover:      #1b2740;
      --input-bg:   #141a26;
      --input-bd:   #34405c;
      --shadow:     rgba(0,0,0,0.55);
      --badge-bg:   #0f2a4a;
      --badge-tx:   #7fc8ff;
      --toggle-bg:  #34405c;
      --link:       #34d399;
      --stripe:     #101623;
      --accent:     #3b82f6;
      --accent2:    #34d399;
      --scrollbar:  #34405c;
    }}

    /* ── Reset ───────────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    html {{ scroll-behavior: smooth; }}

    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 26px 28px 44px;
      min-height: 100vh;
      transition: background 0.3s, color 0.3s;
      position: relative;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }}

    /* ── Matrix rain background ────────────────────────────── */
    #matrix-bg {{
      position: fixed;
      inset: 0;
      z-index: -1;
      width: 100%;
      height: 100%;
      display: block;
      pointer-events: none;
    }}
    /* Keep it subtle so it never competes with the content */
    [data-theme="light"] #matrix-bg {{ opacity: 0.10; }}
    [data-theme="dark"]  #matrix-bg {{ opacity: 0.22; }}

    @keyframes fadeUp {{
      from {{ opacity: 0; transform: translateY(6px); }}
      to   {{ opacity: 1; transform: translateY(0); }}
    }}

    /* ── Header ─────────────────────────────────────────── */
    header {{
      max-width: 1600px;
      margin: 0 auto 20px;
      display: flex;
      align-items: center;
      gap: 18px;
      flex-wrap: wrap;
      background: rgba(var(--bg2-rgb), 0.75);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 18px 26px;
      box-shadow: 0 8px 28px var(--shadow);
      position: sticky;
      top: 14px;
      z-index: 10;
      animation: fadeUp 0.4s ease both;
    }}
    .logo {{
      height: 44px;
      width: auto;
      object-fit: contain;
      flex-shrink: 0;
      filter: drop-shadow(0 2px 6px rgba(0,0,0,0.15));
    }}
    .header-text {{ flex: 1; min-width: 200px; }}
    header h1 {{
      font-size: 1.65rem;
      font-weight: 800;
      line-height: 1.2;
      letter-spacing: -0.4px;
      background: linear-gradient(100deg, var(--text) 40%, var(--accent) 100%);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    header p {{
      font-size: 0.82rem;
      color: var(--text2);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 7px;
    }}
    .live-dot {{
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--accent2);
      box-shadow: 0 0 0 0 rgba(34,197,94,0.6);
      animation: pulse 2s infinite;
      flex-shrink: 0;
    }}
    @keyframes pulse {{
      0%   {{ box-shadow: 0 0 0 0 rgba(34,197,94,0.55); }}
      70%  {{ box-shadow: 0 0 0 7px rgba(34,197,94,0); }}
      100% {{ box-shadow: 0 0 0 0 rgba(34,197,94,0); }}
    }}

    /* ── Header actions (status check + theme toggle) ─────── */
    .header-actions {{
      display: flex;
      align-items: center;
      gap: 14px;
      margin-left: auto;
      flex-shrink: 0;
    }}

    /* ── Dark/Light toggle ──────────────────────────────── */
    .theme-toggle {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-shrink: 0;
    }}
    .toggle-switch {{
      position: relative;
      width: 54px;
      height: 28px;
      cursor: pointer;
    }}
    .toggle-switch input {{ display: none; }}
    .toggle-track {{
      position: absolute;
      inset: 0;
      background: var(--toggle-bg);
      border-radius: 999px;
      transition: background 0.3s;
      overflow: hidden;
    }}
    .toggle-track::before {{
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(100deg, var(--accent), var(--accent2));
      opacity: 0;
      transition: opacity 0.3s;
    }}
    input:checked ~ .toggle-track::before {{ opacity: 1; }}
    .toggle-thumb {{
      position: absolute;
      top: 3px;
      left: 3px;
      width: 22px;
      height: 22px;
      background: #fff;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      transition: transform 0.3s cubic-bezier(.4,1.4,.6,1);
      box-shadow: 0 1px 4px rgba(0,0,0,0.3);
      z-index: 1;
    }}
    input:checked ~ .toggle-thumb {{ transform: translateX(26px); }}

    /* ── Toolbar ────────────────────────────────────────── */
    .toolbar {{
      max-width: 1600px;
      margin: 0 auto 16px;
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
      animation: fadeUp 0.45s ease both;
    }}
    .search-wrap {{
      position: relative;
      flex: 1;
      min-width: 240px;
      max-width: 440px;
    }}
    .search-wrap svg {{
      position: absolute;
      left: 13px;
      top: 50%;
      transform: translateY(-50%);
      width: 15px;
      height: 15px;
      color: var(--text2);
      pointer-events: none;
    }}
    #search {{
      width: 100%;
      padding: 10px 14px 10px 36px;
      background: var(--input-bg);
      border: 1.5px solid var(--input-bd);
      border-radius: 10px;
      color: var(--text);
      font-size: 0.92rem;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }}
    #search:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 4px rgba(59,130,246,0.16);
    }}
    #search::placeholder {{ color: var(--text2); }}
    .row-count {{
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text2);
      background: var(--bg2);
      border: 1px solid var(--border);
      padding: 7px 14px;
      border-radius: 999px;
      white-space: nowrap;
    }}
    .row-count b {{ color: var(--accent); font-weight: 700; }}

    .refresh-btn {{
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text);
      background: var(--bg2);
      border: 1px solid var(--input-bd);
      padding: 8px 16px;
      border-radius: 999px;
      white-space: nowrap;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      transition: border-color 0.2s, transform 0.15s, background 0.2s;
    }}
    .refresh-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
    .refresh-btn:active {{ transform: scale(0.96); }}
    .refresh-btn svg {{ width: 14px; height: 14px; transition: transform 0.5s; }}
    .refresh-btn.spinning svg {{ animation: spin 0.7s linear infinite; }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}

    /* ── Online/offline status dot ─────────────────────────── */
    .status-dot {{
      display: inline-block;
      width: 9px;
      height: 9px;
      border-radius: 50%;
      margin-right: 8px;
      vertical-align: middle;
      cursor: pointer;
      background: var(--text2);
      box-shadow: 0 0 0 rgba(0,0,0,0);
      transition: background 0.2s, box-shadow 0.2s;
    }}
    .status-dot.checking {{
      background: #f59e0b;
      animation: dot-pulse 0.9s ease-in-out infinite;
    }}
    .status-dot.online {{
      background: #22c55e;
      box-shadow: 0 0 7px rgba(34,197,94,0.8);
    }}
    .status-dot.offline {{
      background: #ef4444;
      box-shadow: 0 0 7px rgba(239,68,68,0.7);
    }}
    @keyframes dot-pulse {{
      0%, 100% {{ opacity: 1; transform: scale(1); }}
      50%      {{ opacity: 0.4; transform: scale(0.75); }}
    }}

    /* ── Table container ────────────────────────────────── */
    .table-wrapper {{
      max-width: 1600px;
      margin: 0 auto;
      overflow: auto;
      max-height: calc(100vh - 250px);
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 14px;
      box-shadow: 0 10px 30px var(--shadow);
      animation: fadeUp 0.5s ease both;
    }}
    .table-wrapper::-webkit-scrollbar {{ width: 10px; height: 10px; }}
    .table-wrapper::-webkit-scrollbar-track {{ background: transparent; }}
    .table-wrapper::-webkit-scrollbar-thumb {{
      background: var(--scrollbar);
      border-radius: 999px;
      border: 2px solid var(--bg2);
    }}

    /* ── Note banner ────────────────────────────────────── */
    .note-banner {{
      max-width: 1600px;
      margin: 0 auto 16px;
      padding: 13px 18px;
      background: var(--badge-bg);
      color: var(--badge-tx);
      border: 1px solid transparent;
      border-left: 3px solid var(--accent);
      border-radius: 10px;
      font-size: 0.83rem;
      line-height: 1.5;
      display: flex;
      gap: 10px;
      align-items: flex-start;
      animation: fadeUp 0.42s ease both;
    }}
    .note-banner svg {{ flex-shrink: 0; margin-top: 2px; width: 16px; height: 16px; }}

    /* ── Table ──────────────────────────────────────────── */
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.87rem;
    }}
    th, td {{
      text-align: left;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
      vertical-align: top;
    }}
    td {{ white-space: normal; word-break: break-word; min-width: 100px; line-height: 1.5; }}
    th {{
      background: var(--th-bg);
      color: var(--th-text);
      font-size: 0.76rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      position: sticky;
      top: 0;
      z-index: 2;
      box-shadow: 0 1px 0 rgba(0,0,0,0.08);
    }}
    tbody tr {{ transition: background 0.15s; }}
    tbody tr:nth-child(even) td {{ background: var(--stripe); }}
    tbody tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover td {{ background: var(--hover) !important; }}

    /* links from Confluence content */
    td a, td a:visited {{
      color: var(--link);
      text-decoration: underline;
      text-underline-offset: 2px;
    }}
    td a:hover {{ opacity: 0.8; }}

    /* click-to-copy cells */
    td.copyable {{
      cursor: pointer;
      position: relative;
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    }}
    td.copyable:hover {{
      color: var(--accent);
      text-decoration: underline dotted;
    }}

    /* toast */
    #toast {{
      position: fixed;
      bottom: 26px;
      left: 50%;
      transform: translateX(-50%) translateY(20px);
      background: var(--bg2);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 10px 18px;
      border-radius: 10px;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 10px 30px var(--shadow);
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.25s, transform 0.25s;
      z-index: 100;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    #toast.show {{
      opacity: 1;
      transform: translateX(-50%) translateY(0);
    }}
    #toast .dot {{
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--accent2);
      flex-shrink: 0;
    }}

    /* ── Scan ports button (per IP cell) ───────────────────── */
    .scan-btn {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
      height: 22px;
      margin-left: 8px;
      padding: 0 9px;
      vertical-align: middle;
      border: 1px solid var(--input-bd);
      border-radius: 999px;
      background: var(--bg2);
      color: var(--text2);
      font-size: 0.72rem;
      font-weight: 700;
      font-family: 'SFMono-Regular', Consolas, monospace;
      letter-spacing: 0.3px;
      cursor: pointer;
      transition: color 0.15s, border-color 0.15s, transform 0.12s;
    }}
    .scan-btn:hover {{ color: var(--accent); border-color: var(--accent); }}
    .scan-btn:active {{ transform: scale(0.94); }}
    .scan-btn svg {{ width: 12px; height: 12px; flex-shrink: 0; }}

    /* ── Scan modal ────────────────────────────────────────── */
    .scan-modal {{
      position: fixed;
      inset: 0;
      z-index: 200;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(0,0,0,0.55);
      backdrop-filter: blur(3px);
      -webkit-backdrop-filter: blur(3px);
      padding: 20px;
      animation: fadeUp 0.2s ease both;
    }}
    .scan-card {{
      width: 100%;
      max-width: 460px;
      max-height: 80vh;
      display: flex;
      flex-direction: column;
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 14px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      overflow: hidden;
    }}
    .scan-head {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      padding: 18px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--th-bg);
      color: var(--th-text);
    }}
    .scan-head h3 {{ font-size: 1.05rem; font-weight: 700; }}
    .scan-head p {{
      font-size: 0.85rem;
      opacity: 0.9;
      margin-top: 2px;
      font-family: 'SFMono-Regular', Consolas, monospace;
    }}
    .scan-close {{
      background: rgba(255,255,255,0.15);
      border: none;
      color: var(--th-text);
      width: 28px;
      height: 28px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.9rem;
      flex-shrink: 0;
      transition: background 0.15s;
    }}
    .scan-close:hover {{ background: rgba(255,255,255,0.3); }}
    .scan-body {{ padding: 18px 20px; overflow: auto; }}
    .scan-loading {{
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 0.9rem;
      color: var(--text2);
      padding: 10px 0;
    }}
    .scan-spinner {{
      width: 18px;
      height: 18px;
      border: 2.5px solid var(--border);
      border-top-color: var(--accent);
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
      flex-shrink: 0;
    }}
    .scan-empty {{ font-size: 0.9rem; color: var(--text2); padding: 10px 0; }}
    .scan-summary {{
      font-size: 0.82rem;
      font-weight: 600;
      color: var(--accent);
      margin-bottom: 12px;
    }}
    .scan-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    .scan-table th {{
      position: static;
      background: transparent;
      color: var(--text2);
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.5px;
      box-shadow: none;
      padding: 6px 10px;
      border-bottom: 1px solid var(--border);
    }}
    .scan-table td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }}
    .scan-table tr:last-child td {{ border-bottom: none; }}
    .scan-port {{
      font-family: 'SFMono-Regular', Consolas, monospace;
      font-weight: 600;
      color: var(--accent2);
    }}

    .hidden {{ display: none !important; }}
  </style>
</head>
<body>
  <canvas id="matrix-bg"></canvas>

  <header>
    {logo_tag}
    <div class="header-text">
      <h1>Device Table &middot; Viewer</h1>
      <p><span class="live-dot"></span> Live from Confluence &middot; fetched <span id="fetchedAt">{fetched_at}</span></p>
    </div>
    <div class="header-actions">
      <button class="refresh-btn" id="refreshData" title="Re-fetch the table from Confluence">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
        Refresh data
      </button>
      <button class="refresh-btn" id="refreshStatus" title="Re-check all device status">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
        Check status
      </button>
      <div class="theme-toggle">
        <label class="toggle-switch" title="Toggle light/dark mode">
          <input type="checkbox" id="themeToggle" checked>
          <div class="toggle-track"></div>
          <div class="toggle-thumb" id="toggleIcon">🌙</div>
        </label>
      </div>
    </div>
  </header>

  <div class="note-banner">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
    <span><strong>Note:</strong> Some devices on the list show both a letter and number for the rack in which they are located.
    The number after the letter denotes the shelf where the device resides within the lettered rack.</span>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input type="text" id="search" placeholder="Filter by device, IP, MAC, location…" autocomplete="off">
    </div>
    <div class="row-count"><b id="visibleCount">0</b> / <span id="totalCount">0</span> devices</div>
  </div>

  <div class="table-wrapper">
    {table_html}
  </div>

  <div id="toast"><span class="dot"></span><span id="toastText"></span></div>

  <div id="scanModal" class="scan-modal hidden">
    <div class="scan-card">
      <div class="scan-head">
        <div>
          <h3>Open ports</h3>
          <p id="scanIp">&mdash;</p>
        </div>
        <button id="scanClose" class="scan-close" title="Close">&#10005;</button>
      </div>
      <div id="scanBody" class="scan-body"></div>
    </div>
  </div>

  <script>
    // ── Matrix rain background (slow & subtle) ─────────────────────
    (function matrixRain() {{
      const canvas = document.getElementById('matrix-bg');
      const ctx = canvas.getContext('2d');
      const glyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*+=<>/\\\\|アイウエオカキクケコサシスセソタチツテトナニヌネノ'.split('');
      const fontSize = 16;
      const STEP_MS = 130;   // advance the rain only ~7.5 times per second
      let columns, drops, last = 0;

      function resize() {{
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        columns = Math.floor(canvas.width / fontSize);
        drops = new Array(columns).fill(0).map(() => Math.random() * -canvas.height / fontSize);
      }}
      resize();
      window.addEventListener('resize', resize);

      function draw(now) {{
        requestAnimationFrame(draw);
        if (now - last < STEP_MS) return;   // throttle: keeps it slow
        last = now;

        // translucent black to create a gentle fading trail
        ctx.fillStyle = 'rgba(0, 0, 0, 0.10)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.font = fontSize + 'px monospace';
        for (let i = 0; i < drops.length; i++) {{
          const text = glyphs[Math.floor(Math.random() * glyphs.length)];
          const x = i * fontSize;
          const y = drops[i] * fontSize;

          // muted green, with an occasional slightly brighter head
          ctx.fillStyle = Math.random() > 0.98 ? '#5fbf7f' : '#1f7a44';
          ctx.fillText(text, x, y);

          if (y > canvas.height && Math.random() > 0.985) {{
            drops[i] = 0;
          }}
          drops[i]++;
        }}
      }}
      requestAnimationFrame(draw);
    }})();

    // ── Dark / Light toggle ────────────────────────────────────────
    const html = document.documentElement;
    const toggle = document.getElementById('themeToggle');
    const toggleIcon = document.getElementById('toggleIcon');

    toggle.addEventListener('change', () => {{
      const dark = toggle.checked;
      html.setAttribute('data-theme', dark ? 'dark' : 'light');
      toggleIcon.textContent = dark ? '🌙' : '☀️';
    }});

    // ── Row counting + live filtering ────────────────────────────
    const totalCountEl = document.getElementById('totalCount');
    const visibleCountEl = document.getElementById('visibleCount');
    const searchInput = document.getElementById('search');
    let rows = [];

    function updateCounts() {{
      const visible = rows.filter(r => !r.classList.contains('hidden')).length;
      visibleCountEl.textContent = visible;
      totalCountEl.textContent = rows.length;
    }}

    function applyFilter() {{
      const term = searchInput.value.toLowerCase();
      rows.forEach(row => {{
        row.classList.toggle('hidden', term !== '' && !row.textContent.toLowerCase().includes(term));
      }});
      updateCounts();
    }}
    searchInput.addEventListener('input', applyFilter);

    // ── Click-to-copy + ping status setup ────────────────────────
    const ipRe = /\\b\\d{{1,3}}(\\.\\d{{1,3}}){{3}}\\b/;
    const macRe = /\\b([0-9A-Fa-f]{{2}}[:\\-]?){{5}}[0-9A-Fa-f]{{2}}\\b/;
    const toast = document.getElementById('toast');
    const toastText = document.getElementById('toastText');
    let toastTimer = null;
    let pingTargets = [];

    function showToast(msg) {{
      toastText.textContent = msg;
      toast.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.remove('show'), 1800);
    }}

    // ── Online/offline ping status ────────────────────────────────
    const PING_INTERVAL_MS = 30000; // auto re-check every 30s
    let isChecking = false;

    async function pingIp(dot, ip) {{
      dot.className = 'status-dot checking';
      dot.title = 'Checking ' + ip + '…';
      try {{
        const resp = await fetch('/ping?ip=' + encodeURIComponent(ip));
        const data = await resp.json();
        const online = !!data.online;
        dot.className = 'status-dot ' + (online ? 'online' : 'offline');
        dot.title = ip + ' is ' + (online ? 'online ✓' : 'offline ✗') + ' — click to re-check';
      }} catch (e) {{
        dot.className = 'status-dot offline';
        dot.title = ip + ' — check failed, click to retry';
      }}
    }}

    async function checkAll() {{
      if (isChecking || pingTargets.length === 0) return;
      isChecking = true;
      const btn = document.getElementById('refreshStatus');
      btn.classList.add('spinning');
      await Promise.all(pingTargets.map(t => pingIp(t.dot, t.ip)));
      btn.classList.remove('spinning');
      isChecking = false;
    }}

    // Wires up rows/cells for filtering, copy-to-clipboard, and ping dots.
    // Re-run after a data refresh replaces the table's HTML.
    function initTable() {{
      rows = Array.from(document.querySelectorAll('table tbody tr'));
      pingTargets = [];
      updateCounts();

      document.querySelectorAll('table tbody td').forEach(td => {{
        const text = td.textContent.trim();
        const ipMatch = text.match(ipRe);
        const isCopyable = ipMatch || macRe.test(text);

        if (isCopyable) {{
          td.classList.add('copyable');
          td.title = 'Click to copy';
          td.addEventListener('click', (e) => {{
            if (e.target.classList.contains('status-dot')) return;
            navigator.clipboard.writeText(text).then(() => showToast('Copied "' + text + '"')).catch(() => {{}});
          }});
        }}

        if (ipMatch) {{
          const ip = ipMatch[0];
          const dot = document.createElement('span');
          dot.className = 'status-dot checking';
          dot.title = 'Checking ' + ip + '…';
          dot.addEventListener('click', (e) => {{
            e.stopPropagation();
            pingIp(dot, ip);
          }});
          td.insertBefore(dot, td.firstChild);
          pingTargets.push({{ dot, ip }});

          const scanBtn = document.createElement('button');
          scanBtn.className = 'scan-btn';
          scanBtn.title = 'Run nmap port scan on ' + ip;
          scanBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1"/></svg><span>nmap</span>';
          scanBtn.addEventListener('click', (e) => {{
            e.stopPropagation();
            scanPorts(ip);
          }});
          td.appendChild(scanBtn);
        }}
      }});
    }}

    document.getElementById('refreshStatus').addEventListener('click', checkAll);

    // ── Refresh data from Confluence ──────────────────────────────
    const refreshDataBtn = document.getElementById('refreshData');
    refreshDataBtn.addEventListener('click', async () => {{
      refreshDataBtn.classList.add('spinning');
      refreshDataBtn.disabled = true;
      try {{
        const resp = await fetch('/refresh', {{ method: 'POST' }});
        const data = await resp.json();
        document.querySelector('.table-wrapper').innerHTML = data.table_html;
        document.getElementById('fetchedAt').textContent = data.fetched_at;
        initTable();
        applyFilter();
        checkAll();
        showToast(data.ok ? 'Table refreshed from Confluence' : 'Refresh failed — check credentials');
      }} catch (e) {{
        showToast('Refresh failed — server unreachable');
      }}
      refreshDataBtn.classList.remove('spinning');
      refreshDataBtn.disabled = false;
    }});

    // ── Port scan modal ───────────────────────────────────────────
    const scanModal = document.getElementById('scanModal');
    const scanBody  = document.getElementById('scanBody');
    const scanIpEl  = document.getElementById('scanIp');

    function escapeHtml(s) {{
      return String(s).replace(/[&<>"']/g, c => (
        {{ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }}[c]
      ));
    }}

    function closeScan() {{ scanModal.classList.add('hidden'); }}

    document.getElementById('scanClose').addEventListener('click', closeScan);
    scanModal.addEventListener('click', (e) => {{ if (e.target === scanModal) closeScan(); }});
    document.addEventListener('keydown', (e) => {{ if (e.key === 'Escape') closeScan(); }});

    async function scanPorts(ip) {{
      scanIpEl.textContent = ip;
      scanModal.classList.remove('hidden');
      scanBody.innerHTML =
        '<div class="scan-loading"><span class="scan-spinner"></span>' +
        'Scanning the top 1000 TCP ports… this can take up to a minute.</div>';
      try {{
        const resp = await fetch('/scan?ip=' + encodeURIComponent(ip));
        const data = await resp.json();
        if (data.error) {{
          scanBody.innerHTML = '<div class="scan-empty">Scan failed: ' + escapeHtml(data.error) + '</div>';
          return;
        }}
        const ports = data.ports || [];
        if (ports.length === 0) {{
          scanBody.innerHTML = '<div class="scan-empty">No open ports found in the top 1000.</div>';
          return;
        }}
        const rowsHtml = ports.map(p =>
          '<tr><td class="scan-port">' + escapeHtml(p.port) + '/' + escapeHtml(p.proto) +
          '</td><td>' + escapeHtml(p.service) + '</td></tr>'
        ).join('');
        scanBody.innerHTML =
          '<div class="scan-summary">' + ports.length + ' open port' + (ports.length === 1 ? '' : 's') + '</div>' +
          '<table class="scan-table"><thead><tr><th>Port</th><th>Service</th></tr></thead><tbody>' +
          rowsHtml + '</tbody></table>';
      }} catch (e) {{
        scanBody.innerHTML = '<div class="scan-empty">Scan failed — server unreachable.</div>';
      }}
    }}

    // Initial setup, then auto-check status on load and every PING_INTERVAL_MS
    initTable();
    checkAll();
    setInterval(checkAll, PING_INTERVAL_MS);
  </script>
</body>
</html>"""


# ── Fetch (and re-fetch on demand) ──────────────────────────────────────────
PAGE_BYTES = b""
LOGO_DATA_URI = load_logo_base64()
page_lock = threading.Lock()


def refresh_data():
    """Re-fetch the Confluence table, rebuild the cached page, and return the result."""
    global PAGE_BYTES
    fetched_at = datetime.now().strftime("%b %d, %Y %I:%M %p")
    try:
        raw_html = fetch_page_html()
        table_html = extract_tables(raw_html)
        ok = True
    except Exception as e:
        table_html = f"<p style='color:red;'><strong>Error fetching page:</strong></p><pre>{e}</pre>"
        ok = False

    with page_lock:
        PAGE_BYTES = build_full_page(table_html, LOGO_DATA_URI, fetched_at).encode("utf-8")

    return ok, table_html, fetched_at


print("⏳  Fetching page from Confluence…")
_ok, _table_html, _fetched_at = refresh_data()
print("✅  Table extracted successfully." if _ok else "❌  Error fetching page — check credentials.")


# ── Tiny HTTP server ────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/ping":
            self.handle_ping(parsed)
            return

        if parsed.path == "/scan":
            self.handle_scan(parsed)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        with page_lock:
            self.wfile.write(PAGE_BYTES)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/refresh":
            ok, table_html, fetched_at = refresh_data()
            body = json.dumps({
                "ok": ok,
                "table_html": table_html,
                "fetched_at": fetched_at,
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def handle_ping(self, parsed):
        ip = (parse_qs(parsed.query).get("ip") or [""])[0]

        if not is_valid_ipv4(ip):
            body = json.dumps({"error": "invalid ip"}).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        online = ping_host(ip)
        body = json.dumps({"ip": ip, "online": online}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_scan(self, parsed):
        ip = (parse_qs(parsed.query).get("ip") or [""])[0]

        if not is_valid_ipv4(ip):
            self._send_json(400, {"error": "invalid ip"})
            return

        result = run_port_scan(ip)
        result["ip"] = ip
        self._send_json(200, result)

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # suppress noisy logs


print(f"🌐  Serving at  http://localhost:{PORT}")
print("    Press Ctrl+C to stop.\n")
ThreadingHTTPServer(("", PORT), Handler).serve_forever()
