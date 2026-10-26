"""Simple numbered menu, shown when Sentinel is opened by double-clicking (no commands needed)."""
import getpass
import json
import os
import platform
import subprocess
import sys
import webbrowser

from . import __version__, notify
from .file_scanner import USER_DIR

REPORT = USER_DIR / "last-report.html"
PASSWORD_FILE = USER_DIR / "smtp_password"
# Free lists that need no account (checked October 2026).
UPDATE_SOURCES = [
    ("malware fingerprints",   # SHA-256 hashes collected from abuse.ch, VirusTotal feeds and others
     "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt"),
    ("scam and malware domains",   # CERT Polska's public warning list
     "https://hole.cert.pl/domains/v2/domains.txt"),
]

MENU = f"""
=============================================
   SENTINEL {__version__}  -  device security scanner
=============================================
  1  Scan this computer (quick)
  2  Scan this computer (full, slower)
  3  Real-time protection: watch my Downloads
  4  Check a link
  5  Check an email file (.eml)
  6  Scan an Android phone (USB)
  7  Update malware lists
  8  Set up email alerts
  9  Send a test alert
  0  Exit
"""


def _cli(*args):
    from .__main__ import main
    try:
        return main(list(args))
    except SystemExit as e:
        return e.code
    except Exception as e:
        print(f"\nSomething went wrong: {e}")


def _open(path):
    try:
        if platform.system() == "Windows":
            os.startfile(str(path))  # type: ignore[attr-defined]
        else:
            webbrowser.open(path.as_uri())
    except Exception:
        print(f"Report saved to {path}")


def _scan(full=False):
    USER_DIR.mkdir(parents=True, exist_ok=True)
    args = ["all", "--notify", "--hide-ok", "--html", str(REPORT)]
    if full:
        _cli("settings", "--notify", "--hide-ok")
        args = ["scan", "--full", "--notify", "--hide-ok", "--html", str(REPORT)]
    _cli(*args)
    _open(REPORT)


def _setup_email():
    print("\nEmail alerts send you a message when Sentinel finds a threat.")
    print("For Gmail you need an 'app password' (a 16-letter code from Google), not your normal password.")
    print("Get one here: https://myaccount.google.com/apppasswords  (needs 2-Step Verification on)\n")
    cfg = notify.load_config()
    current = (cfg["notify"].get("email") or {}).get("to", [""])
    address = input(f"Your email address [{current[0] if current else ''}]: ").strip() or (current[0] if current else "")
    if "@" not in address:
        print("That doesn't look like an email address. Nothing changed.")
        return
    password = getpass.getpass("Paste the app password (it stays hidden as you type): ").replace(" ", "")
    if not password:
        print("No password entered. Nothing changed.")
        return
    domain = address.split("@")[1].lower()
    smtp = {"gmail.com": "smtp.gmail.com", "googlemail.com": "smtp.gmail.com",
            "outlook.com": "smtp-mail.outlook.com", "hotmail.com": "smtp-mail.outlook.com",
            "live.com": "smtp-mail.outlook.com", "yahoo.com": "smtp.mail.yahoo.com",
            "icloud.com": "smtp.mail.me.com", "me.com": "smtp.mail.me.com"}.get(domain)
    if not smtp:
        smtp = input("Your email provider's SMTP server (e.g. smtp.example.com): ").strip()
    cfg["notify"].update({"enabled": True, "email": {
        "smtp_host": smtp, "smtp_port": 587, "use_tls": True,
        "username": address, "from": address, "to": [address]}})
    USER_DIR.mkdir(parents=True, exist_ok=True)
    notify.CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    PASSWORD_FILE.write_text(password, encoding="utf-8")
    try:
        os.chmod(PASSWORD_FILE, 0o600)  # only you can read it (macOS / Linux)
    except OSError:
        pass
    print("\nSaved. Sending a test email now...")
    _cli("notify-test")
    print(f"Check {address} for a message titled 'Sentinel: 1 threat found (test)'.")


def _update():
    for kind, url in UPDATE_SOURCES:
        print(f"\nDownloading {kind} from {url} ...")
        _cli("update", url, *(["--domains"] if "domains" in kind else []))


def do(choice):
    """Run one menu option. Returns False if the choice isn't valid."""
    if choice == "1":
        _scan()
    elif choice == "2":
        _scan(full=True)
    elif choice == "3":
        print("Real-time protection is ON while this window is open.")
        print("Close the window (or press Ctrl+C) to stop.
")
        _cli("watch", "--notify")
    elif choice == "4":
        link = input("Paste the link: ").strip()
        if link:
            _cli("url", link if "://" in link else "http://" + link)
    elif choice == "5":
        path = input("Drag the email file into this window, then press Enter: ").strip().strip('"'& ')
        if path:
            _cli("scan", path, "--notify")
    elif choice == "6":
        _cli("android", "--notify")
    elif choice == "7":
        _update()
    elif choice == "8":
        _setup_email()
    elif choice == "9":
        _cli("notify-test")
    else:
        return False
    return True


def run_once(choice):
    """Used by Desktop shortcuts: run one option, then wait so the window doesn't vanish."""
    if platform.system() == "Windows":
        os.system("")
    do(choice)
    input("
Done. Press Enter to close this window...")
    return 0


def run():
    if platform.system() == "Windows":
        os.system("")  # colour support
    while True:
        print(MENU)
        choice = input("Choose a number and press Enter: ").strip()
        print()
        if choice in ("0", "q", "exit"):
            return 0
        if not do(choice):
            print("Please type one of the numbers shown.")
            continue
        input("
Press Enter to go back to the menu...")


if __name__ == "__main__":
    sys.exit(run())
