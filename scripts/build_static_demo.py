"""Build the static GitHub Pages demo into ./site.

Renders the real dashboard in demo mode (sample data, no host access), then
rewrites it to run as a static page: assets are made relative, live refresh is
off, and static/demo.js simulates changes in the browser.

    python scripts/build_static_demo.py [output_dir]
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

NOTICE = (
    '<div class="static-banner" role="note">'
    "<span><strong>Live demo.</strong> This runs entirely in your browser with sample data. "
    "Try dragging a rule, adding one, or changing a policy, then confirm or roll back. "
    "Reload to reset.</span>"
    '<a class="ghost-link accent" href="https://github.com/reonsmith/host-firewall">Get it on GitHub</a>'
    "</div>"
)


def build(out: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ.update(
            HOST_FIREWALL_DEMO="1",
            HOST_FIREWALL_DATA_DIR=str(Path(tmp) / "data"),
            HOST_FIREWALL_LABEL="demo-host",
        )
        from fastapi.testclient import TestClient

        from backend.app import create_app
        from backend.config import load_settings
        from backend.demo import DEMO_PASSWORD

        client = TestClient(create_app(settings=load_settings(), start_watchdog=False))
        resp = client.post("/login", data={"password": DEMO_PASSWORD}, follow_redirects=False)
        assert resp.status_code == 303, resp.text
        html = client.get("/").text

    html = re.sub(r'href="/static/app\.css\?v=([^"]*)"', r'href="app.css?v=\1"', html)
    html = re.sub(
        r'<script src="/static/app\.js\?v=([^"]*)" defer></script>',
        r'<script src="demo.js?v=\1" defer></script>\n  <script src="app.js?v=\1" defer></script>',
        html,
    )
    html = html.replace('data-page="dashboard"', 'data-page="static-demo"')
    html = re.sub(r"<noscript>.*?</noscript>", "", html, flags=re.S)
    html = re.sub(
        r'<p class="demo-note">.*?</p>',
        '<p class="demo-note">Sample data. Changes are simulated in your browser and reset when you reload.</p>',
        html,
        count=1,
        flags=re.S,
    )
    html = html.replace("<main>", "<main>\n" + NOTICE, 1)
    html = html.replace(
        "<title>",
        '<meta name="description" content="Live demo of Host Firewall, a web panel for UFW with confirm-or-rollback." />\n  <title>',
        1,
    )
    assert "/static/" not in html, "unrewritten static path"

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / "index.html").write_text(html, encoding="utf-8")
    static = ROOT / "backend" / "static"
    for name in ("app.css", "app.js"):
        shutil.copy2(static / name, out / name)
    shutil.copy2(ROOT / "scripts" / "static-demo" / "demo.js", out / "demo.js")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    print(f"built {out / 'index.html'} ({len(html):,} bytes)")


if __name__ == "__main__":
    build(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "site")
