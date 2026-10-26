"""Alerts when something is found: desktop pop-up, chat webhook, email, and a log file.

Settings live in ~/.sentinel/config.json (create it with `python -m sentinel notify-setup`):

{
  "notify": {
    "enabled": true,                 # alert after every scan, without needing --notify
    "level": "high",                 # lowest severity that triggers an alert
    "desktop": true,
    "webhook": "https://hooks.slack.com/services/...",   # Slack, Discord or Teams
    "email": {
      "smtp_host": "smtp.gmail.com", "smtp_port": 587, "use_tls": true,
      "username": "you@gmail.com", "from": "you@gmail.com", "to": ["you@gmail.com"]
    }
  }
}

The SMTP password is never stored in config.json. It comes from the SENTINEL_SMTP_PASSWORD
environment variable, or ~/.sentinel/smtp_password (written by the menu's email setup).
"""
import datetime as dt
import json
import os
import platform
import shutil
import smtplib
import subprocess
import sys
import urllib.request
from email.message import EmailMessage
from pathlib import Path

from .findings import SEVERITY_ORDER, sort_findings

CONFIG_DIR = Path.home() / ".sentinel"
CONFIG_FILE = CONFIG_DIR / "config.json"
ALERT_LOG = CONFIG_DIR / "alerts.log"

DEFAULT_CONFIG = {"notify": {"enabled": False, "level": "high", "desktop": True,
                             "webhook": "", "email": None}}

_WINDOWS_TOAST = r"""
$t = $env:SENTINEL_TITLE; $m = $env:SENTINEL_MSG
try {
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
  $n = $xml.GetElementsByTagName('text')
  $n.Item(0).AppendChild($xml.CreateTextNode($t)) | Out-Null
  $n.Item(1).AppendChild($xml.CreateTextNode($m)) | Out-Null
  $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
  $app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show($toast)
} catch {
  Add-Type -AssemblyName System.Windows.Forms, System.Drawing
  $i = New-Object System.Windows.Forms.NotifyIcon
  $i.Icon = [System.Drawing.SystemIcons]::Warning; $i.Visible = $true
  $i.ShowBalloonTip(10000, $t, $m, 'Warning'); Start-Sleep -Seconds 10; $i.Dispose()
}
"""


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        user = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        cfg["notify"].update(user.get("notify", {}))
    except (OSError, ValueError):
        pass
    return cfg


def write_default_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        return False
    example = {"notify": {"enabled": True, "level": "high", "desktop": True, "webhook": "",
                          "email": None}}
    CONFIG_FILE.write_text(json.dumps(example, indent=2), encoding="utf-8")
    return True


class Notifier:
    def __init__(self, level="high", desktop=True, webhook="", email_cfg=None):
        self.level = level
        self.desktop = desktop
        self.webhook = webhook
        self.email_cfg = email_cfg
        self._sent = set()   # avoid repeating the same alert (used by watch mode)

    @classmethod
    def from_config(cls, overrides=None):
        n = load_config()["notify"]
        n.update({k: v for k, v in (overrides or {}).items() if v not in (None, "")})
        return cls(n.get("level", "high"), n.get("desktop", True), n.get("webhook", ""),
                   n.get("email"))

    def _important(self, findings):
        limit = SEVERITY_ORDER.get(self.level, 1)
        new = []
        for f in sort_findings(findings):
            key = (f.title, f.path)
            if SEVERITY_ORDER.get(f.severity, 9) <= limit and key not in self._sent:
                self._sent.add(key)
                new.append(f)
        return new

    def send(self, findings, context="Scan"):
        """Alert on findings at or above the configured level. Returns how many triggered."""
        hits = self._important(findings)
        if not hits:
            return 0
        title = f"Sentinel: {len(hits)} threat{'s' if len(hits) != 1 else ''} found ({context})"
        lines = [f"[{f.severity.upper()}] {f.title}" + (f" - {f.path}" if f.path else "")
                 for f in hits[:8]]
        if len(hits) > 8:
            lines.append(f"...and {len(hits) - 8} more")
        body = "\n".join(lines)
        _log(hits, context)
        for name, fn in (("desktop", self._desktop), ("webhook", self._webhook),
                         ("email", self._email)):
            try:
                fn(title, body, hits)
            except Exception as e:  # one broken channel must not stop the others
                print(f"  ! {name} notification failed: {e}", file=sys.stderr)
        return len(hits)

    # -------------------------------------------------------------- channels
    def _desktop(self, title, body, hits):
        if not self.desktop:
            return
        short = hits[0].title + (f" (+{len(hits) - 1} more)" if len(hits) > 1 else "")
        system = platform.system()
        if system == "Windows":
            env = dict(os.environ, SENTINEL_TITLE=title, SENTINEL_MSG=short)
            subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
                              "-Command", _WINDOWS_TOAST], env=env,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        elif system == "Darwin":
            # Text goes in as arguments, so quotes in file names can't break the script.
            subprocess.run(["osascript", "-e", "on run argv",
                            "-e", "display notification (item 2 of argv) with title (item 1 of argv)"
                                  " sound name \"Basso\"",
                            "-e", "end run", title, short], timeout=15)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", "-u", "critical", title, short], timeout=15)

    def _webhook(self, title, body, hits):
        if not self.webhook:
            return
        text = f"*{title}*\n{body}"[:1900]
        payload = {"content": text} if "discord" in self.webhook else {"text": text}
        req = urllib.request.Request(self.webhook, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=15).close()

    def _email(self, title, body, hits):
        cfg = self.email_cfg
        if not cfg or not cfg.get("to"):
            return
        password = _smtp_password()
        if cfg.get("username") and not password:
            return  # email alerts not finished setting up yet (no app password saved)
        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = cfg.get("from") or cfg.get("username")
        msg["To"] = ", ".join(cfg["to"] if isinstance(cfg["to"], list) else [cfg["to"]])
        details = "\n\n".join(
            f"[{f.severity.upper()}] {f.title}\nWhere: {f.path}\nWhy: {f.detail}\nFix: {f.fix}"
            for f in hits)
        msg.set_content(f"{body}\n\nDetails\n-------\n{details}\n\nHost: {platform.node()}")
        with smtplib.SMTP(cfg["smtp_host"], int(cfg.get("smtp_port", 587)), timeout=30) as s:
            if cfg.get("use_tls", True):
                s.starttls()
            if cfg.get("username") and password:
                s.login(cfg["username"], password)
            s.send_message(msg)


def _smtp_password():
    """From the SENTINEL_SMTP_PASSWORD variable, or the file saved by the menu's email setup."""
    if os.environ.get("SENTINEL_SMTP_PASSWORD"):
        return os.environ["SENTINEL_SMTP_PASSWORD"]
    try:
        return (CONFIG_DIR / "smtp_password").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _log(hits, context):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(ALERT_LOG, "a", encoding="utf-8") as fh:
            for f in hits:
                fh.write(json.dumps({"time": dt.datetime.now().isoformat(timespec="seconds"),
                                     "context": context, **f.to_dict()}) + "\n")
    except OSError:
        pass
