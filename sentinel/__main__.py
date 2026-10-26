"""Command line: python -m sentinel <command>"""
import argparse
import os
import platform
import sys
import urllib.request

from . import __version__, file_scanner, mobile, notify, posture, report, url_checks
from .findings import Finding


def _read_source(source):
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=60) as r:
            return r.read().decode("utf-8", errors="ignore")
    with open(source, encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def cmd_update(source, domains=False):
    """Add SHA-256 hashes (or bad domains with --domains) from a file or URL."""
    text = _read_source(source)
    if domains:
        existing = url_checks.load_bad_domains()
        added = 0
        with open(url_checks.DEFAULT_BAD_DOMAINS, "a", encoding="utf-8") as out:
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip().lower()
                if not line:
                    continue
                d = line.split()[-1].strip(".")
                if "." in d and d not in existing and d != "localhost":
                    out.write(d + "\n")
                    existing.add(d)
                    added += 1
        print(f"Added {added} new bad domains ({len(existing)} total).")
        return
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


def _notifier(args):
    return notify.Notifier.from_config({"level": getattr(args, "notify_level", None),
                                        "webhook": getattr(args, "webhook", None)})


def main(argv=None):
    if platform.system() == "Windows":
        os.system("")  # enables colour output in the Windows console
    p = argparse.ArgumentParser(prog="sentinel",
                                description="Scan devices for malware, web shells, phishing emails, "
                                            "bad links and weak security settings.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan files (also checks PHP shells, emails and links inside them)")
    s.add_argument("paths", nargs="*", help="files/folders to scan (default: quick-scan common locations)")
    s.add_argument("--full", action="store_true", help="scan the whole home folder")
    s.add_argument("--signatures", nargs="*", help="extra signature files")

    w = sub.add_parser("watch", help="keep watching folders and alert the moment a threat appears")
    w.add_argument("paths", nargs="*", help="folders to watch (default: common download locations)")
    w.add_argument("--interval", type=int, default=10, help="seconds between checks (default 10)")

    ur = sub.add_parser("url", help="check one or more links for phishing / malware signs")
    ur.add_argument("urls", nargs="+")

    st = sub.add_parser("settings", help="check this computer's security settings")

    a = sub.add_parser("android", help="check a USB-connected Android phone")
    a.add_argument("--serial", help="device serial if several are connected")
    a.add_argument("--deep", action="store_true", help="also copy and hash every app (slow)")

    i = sub.add_parser("ios", help="check a USB-connected iPhone/iPad")
    al = sub.add_parser("all", help="settings + quick file scan + any connected phones")

    u = sub.add_parser("update", help="add malware hashes (or bad domains) from a file or URL")
    u.add_argument("source")
    u.add_argument("--domains", action="store_true", help="the source is a list of bad domains")

    sub.add_parser("notify-setup", help="create ~/.sentinel/config.json for alerts")
    nt = sub.add_parser("notify-test", help="send a test alert through every configured channel")

    for sp in (s, w, ur, st, a, i, al, nt):
        sp.add_argument("--notify", action="store_true", help="send alerts for what is found")
        sp.add_argument("--notify-level", choices=["critical", "high", "medium", "low"],
                        help="lowest severity that triggers an alert (default: high)")
        sp.add_argument("--webhook", help="Slack / Discord / Teams webhook URL for alerts")
    for sp in (s, ur, st, a, i, al):
        sp.add_argument("--json", metavar="FILE", help="save a JSON report")
        sp.add_argument("--html", metavar="FILE", help="save an HTML report")
        sp.add_argument("--hide-ok", action="store_true", help="hide passing checks")

    args = p.parse_args(argv)
    if args.command == "update":
        cmd_update(args.source, args.domains)
        return 0
    if args.command == "notify-setup":
        created = notify.write_default_config()
        print(("Created " if created else "Already exists: ") + str(notify.CONFIG_FILE))
        print("Edit it to add a webhook URL or email settings. Alerts are logged to "
              + str(notify.ALERT_LOG))
        return 0
    if args.command == "notify-test":
        n = _notifier(args)
        n.level = "critical"
        sent = n.send([Finding("test", "This is a test alert from Sentinel", "critical",
                               "If you can see this, notifications work.")], context="test")
        print(f"Test alert sent ({sent}). Log: {notify.ALERT_LOG}")
        return 0

    notify_on = args.notify or bool(args.webhook) or notify.load_config()["notify"].get("enabled")
    notifier = _notifier(args)

    if args.command == "watch":
        paths = args.paths or posture.default_scan_paths()
        file_scanner.watch(paths, notifier, args.interval,
                           on_findings=lambda f: report.print_report(f, show_ok=False))
        return 0

    findings, stats = [], {}
    if args.command == "url":
        bad = url_checks.load_bad_domains()
        for link in args.urls:
            found = url_checks.check_url(link, bad)
            findings += found or [Finding("url", f"No warning signs: {link}", "ok")]
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
    if notify_on:
        sent = notifier.send(findings, context=args.command)
        if sent:
            print(f"Alert sent for {sent} finding(s).")
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
