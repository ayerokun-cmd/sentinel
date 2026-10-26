"""Print results to the terminal and save JSON / HTML reports."""
import datetime as dt
import html
import json
import platform
import sys

from .findings import sort_findings

COLORS = {"critical": "\033[91m", "high": "\033[31m", "medium": "\033[33m",
          "low": "\033[36m", "info": "\033[90m", "ok": "\033[32m"}
RESET = "\033[0m"


def print_report(findings, stats=None, show_ok=True):
    findings = sort_findings(findings)
    print()
    for f in findings:
        if f.severity == "ok" and not show_ok:
            continue
        c = COLORS.get(f.severity, "")
        print(f"{c}[{f.severity.upper():8}]{RESET} {f.title}")
        if f.path:
            print(f"           where: {f.path}")
        if f.detail:
            print(f"           why:   {f.detail}")
        if f.fix:
            print(f"           fix:   {f.fix}")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print("\nSummary: " + ", ".join(f"{v} {k}" for k, v in counts.items()) if counts else "\nNo findings.")
    if stats:
        print(f"Files scanned: {stats.get('files_scanned', 0)}, skipped: {stats.get('files_skipped', 0)}, "
              f"signatures loaded: {stats.get('signatures', 0)}, YARA: {'on' if stats.get('yara') else 'off'}")
    sys.stdout.flush()  # show results immediately, even when output goes to a log file


def save_json(findings, stats, path):
    data = {"generated": dt.datetime.now().isoformat(timespec="seconds"),
            "host": platform.node(), "os": platform.platform(),
            "stats": stats or {}, "findings": [f.to_dict() for f in sort_findings(findings)]}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def save_html(findings, stats, path):
    rows = []
    for f in sort_findings(findings):
        rows.append(
            f"<tr class='{f.severity}'><td><span class='sev'>{f.severity}</span></td>"
            f"<td><b>{html.escape(f.title)}</b><div class='d'>{html.escape(f.detail)}</div>"
            + (f"<div class='p'>{html.escape(f.path)}</div>" if f.path else "")
            + f"</td><td>{html.escape(f.fix)}</td></tr>")
    page = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel scan report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:24px;background:#fafafa;color:#222}}
table{{border-collapse:collapse;width:100%;background:#fff}} td{{padding:10px;border-bottom:1px solid #eee;vertical-align:top}}
.sev{{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px;text-transform:uppercase}}
.critical .sev{{background:#b00020}} .high .sev{{background:#e65100}} .medium .sev{{background:#f9a825}}
.low .sev{{background:#0277bd}} .info .sev{{background:#757575}} .ok .sev{{background:#2e7d32}}
.d{{color:#555;font-size:14px}} .p{{color:#888;font-size:12px;font-family:monospace;word-break:break-all}}
</style></head><body>
<h1>Sentinel scan report</h1>
<p>{html.escape(platform.node())} &middot; {html.escape(platform.platform())} &middot; {dt.datetime.now():%Y-%m-%d %H:%M}</p>
<p>Files scanned: {(stats or {}).get('files_scanned', 0)}</p>
<table><tr><th>Severity</th><th>Finding</th><th>How to fix</th></tr>{''.join(rows)}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(page)
