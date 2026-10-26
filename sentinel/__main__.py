"""Command line: python -m sentinel <command>"""
import argparse
import os
import platform
import sys
import urllib.request

from . import __version__, file_scanner, mobile, posture, report


def cmd_update(source):
    """Append SHA-256 hashes from a file or URL to the local signature list."""
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=60) as r:
            text = r.read().decode("utf-8", errors="ignore")
    else:
        with open(source, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    existing = file_scanner.load_signatures([file_scanner.DEFAULT_SIGNATURES])
    added = 0
    with open(file_scanner.DEFAULT_SIGNATURES, "a", encoding="utf-8") as out:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip().strip('"')
            h = line.split(None, 1)[0].split(",")[0].lower() if line else ""
            if len(h) == 64 and all(c in "0123456789abcdef" for c in h) and h not in existing:
                name = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else "Imported signature"
                out.write(f"{h} {name}\n")
                existing[h] = name
                added += 1
    print(f"Added {added} new signatures ({len(existing)} total).")


def main(argv=None):
    if platform.system() == "Windows":
        os.system("")  # enables colour output in the Windows console
    p = argparse.ArgumentParser(prog="sentinel", description="Scan devices for malware and weak security settings.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan files for malware")
    s.add_argument("paths", nargs="*", help="files/folders to scan (default: quick-scan common locations)")
    s.add_argument("--full", action="store_true", help="scan the whole home folder")
    s.add_argument("--signatures", nargs="*", help="extra signature files")

    sub.add_parser("settings", help="check this computer's security settings")

    a = sub.add_parser("android", help="check a USB-connected Android phone")
    a.add_argument("--serial", help="device serial if several are connected")
    a.add_argument("--deep", action="store_true", help="also copy and hash every app (slow)")

    sub.add_parser("ios", help="check a USB-connected iPhone/iPad")
    sub.add_parser("all", help="settings + quick file scan + any connected phones")

    u = sub.add_parser("update", help="add malware hashes from a file or URL")
    u.add_argument("source")

    for sp in (s, a, sub.choices["settings"], sub.choices["ios"], sub.choices["all"]):
        sp.add_argument("--json", metavar="FILE", help="save a JSON report")
        sp.add_argument("--html", metavar="FILE", help="save an HTML report")
        sp.add_argument("--hide-ok", action="store_true", help="hide passing checks")

    args = p.parse_args(argv)
    if args.command == "update":
        cmd_update(args.source)
        return 0

    findings, stats = [], {}
    if args.command in ("settings", "all"):
        print("Checking security settings...", file=sys.stderr)
        findings += posture.check_local()
    if args.command in ("scan", "all"):
        paths = getattr(args, "paths", None) or (
            [os.path.expanduser("~")] if getattr(args, "full", False) else posture.default_scan_paths())
        print("Scanning files in: " + ", ".join(map(str, paths)), file=sys.stderr)
        f, stats = file_scanner.scan_paths(paths, (getattr(args, "signatures", None) or [])
                                           + [file_scanner.DEFAULT_SIGNATURES])
        findings += f
    if args.command == "android":
        findings += mobile.check_android(args.serial, args.deep)
    if args.command == "ios":
        findings += mobile.check_ios()
    if args.command == "all":
        if mobile.list_android_devices():
            findings += mobile.check_android()
        findings += [x for x in mobile.check_ios() if "not installed" not in x.title
                     and "No iPhone" not in x.title]

    report.print_report(findings, stats, show_ok=not args.hide_ok)
    if args.json:
        report.save_json(findings, stats, args.json)
        print(f"JSON report saved to {args.json}")
    if args.html:
        report.save_html(findings, stats, args.html)
        print(f"HTML report saved to {args.html}")
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
