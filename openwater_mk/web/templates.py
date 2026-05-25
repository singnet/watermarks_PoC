"""HTML rendering helpers.

The web service intentionally avoids a JS frontend for the V1 demo. It
serves a small static HTML page for the home route and styled HTML
versions of verify reports. All markup is hand-rolled to keep the
dependency surface minimal.
"""
from __future__ import annotations

import html
from typing import Any


def render_index() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>openwater.mk</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { font-family: -apple-system, system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #111; }
    h1 { margin-bottom: 0; }
    .subtitle { color: #555; margin-top: 0.25rem; }
    .card { border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin: 1rem 0; }
    .pill { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.85rem; }
    .pill-ok { background: #d4edda; color: #155724; }
    .pill-warn { background: #fff3cd; color: #856404; }
    code { background: #f4f4f4; padding: 0.1rem 0.25rem; border-radius: 3px; }
    pre { background: #f4f4f4; padding: 0.75rem; overflow: auto; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>openwater.mk</h1>
  <p class="subtitle">Internal demo of the OpenWater provenance stack.</p>
  <div class="card">
    <p><span class="pill pill-warn">DEMO</span>
      Reference watermark profiles. Local/fake storage by default. Real
      storage and Blockfrost anchors are opt-in.</p>
  </div>
  <h2>Endpoints</h2>
  <ul>
    <li><code>GET /healthz</code> &mdash; liveness probe</li>
    <li><code>POST /sign-embed</code> &mdash; multipart upload (PNG); returns job_id</li>
    <li><code>GET /jobs/{job_id}</code> &mdash; job manifest</li>
    <li><code>GET /jobs/{job_id}/watermarked.png</code> &mdash; embedded image</li>
    <li><code>POST /jobs/{job_id}/verify</code> &mdash; verify the job&#x27;s watermarked image</li>
    <li><code>POST /verify</code> &mdash; multipart upload (PNG) + job_id form field</li>
    <li><code>POST /jobs/{job_id}/anchor</code> &mdash; publish a Cardano anchor</li>
    <li><code>GET /jobs/{job_id}/anchor</code> &mdash; anchor record + receipt + verification</li>
    <li><code>GET /jobs/{job_id}/report.html</code> &mdash; human-readable verify report</li>
  </ul>
  <p>Interactive API docs at <a href="/docs">/docs</a>.</p>
</body>
</html>
"""


def render_verify_report_html(report: dict[str, Any]) -> str:
    verified = bool(report.get("verified"))
    pill_class = "pill-ok" if verified else "pill-warn"
    pill_text = "VERIFIED" if verified else "REJECTED"
    rows = [
        ("Job ID", report.get("job_id", "")),
        ("Watermarked", report.get("watermarked_path", "")),
        ("Extraction", report.get("extraction_status", "")),
        ("Verification", report.get("verification_status", "")),
        ("Locator mode", report.get("locator_mode", "")),
        ("Key ID", report.get("key_id", "")),
    ]
    row_html = "".join(
        f"<tr><th align=left style='padding-right:1rem'>{html.escape(str(k))}</th>"
        f"<td><code>{html.escape(str(v))}</code></td></tr>"
        for k, v in rows
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>openwater.mk verify report</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }}
  .pill {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 999px; font-weight: 600; }}
  .pill-ok {{ background: #d4edda; color: #155724; }}
  .pill-warn {{ background: #f8d7da; color: #721c24; }}
  table {{ border-collapse: collapse; margin-top: 1rem; }}
  td, th {{ padding: 0.25rem 0.5rem; border-bottom: 1px solid #eee; }}
  .note {{ background: #fff8d6; padding: 0.75rem 1rem; border-left: 3px solid #d4a017; margin-top: 1.5rem; }}
</style>
</head>
<body>
<h1>openwater.mk verify report</h1>
<p>Result: <span class="pill {pill_class}">{pill_text}</span></p>
<table>{row_html}</table>
<p class="note">A green VERIFIED chip means the artifact&#x27;s essence binds to a signed
manifest from a trusted key. It does <strong>not</strong> mean the events
depicted in the artifact are true. It also does not protect against
out-of-band recompression by hostile channels &mdash; the reference
carriers are demo-grade and not proof of real-world robustness.</p>
</body>
</html>
"""
