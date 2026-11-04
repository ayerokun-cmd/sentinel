"""Speed-up tool: finds what is slowing the computer, suggests fixes, and applies the ones you pick.

Nothing is changed without asking. Fixes that could lose work (closing apps, restarting) ask again
before running. Startup changes are recorded so they can be undone (type 'undo' at the prompt, or
run `python -m sentinel optimize --undo`).
"""
import datetime as dt
import getpass
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

from .file_scanner import USER_DIR

SYSTEM = platform.system()
LOG_FILE = USER_DIR / "optimizer.log"
STARTUP_LOG = USER_DIR / "startup_changes.json"
DISABLED_DIR = USER_DIR / "disabled_startup"
GB = 1024 ** 3
MB = 1024 ** 2

# Programs that keep the system running. Never offered for closing.
PROTECTED = {
    "system", "system idle process", "idle", "registry", "memory compression", "secure system",
    "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsaiso", "svchost", "dwm",
    "explorer", "fontdrvhost", "sihost", "ctfmon", "conhost", "msmpeng", "nissrv", "mpdefendercoreservice",
    "securityhealthservice", "securityhealthsystray", "audiodg", "spoolsv", "taskhostw",
    "runtimebroker", "searchhost", "searchindexer", "startmenuexperiencehost",
    "shellexperiencehost", "textinputhost", "applicationframehost", "dllhost", "wmiprvse",
    "sentinel", "python", "pythonw", "py", "powershell", "pwsh", "cmd", "windowsterminal",
    "openconsole", "kernel_task", "windowserver", "launchd", "loginwindow", "finder", "dock",
    "systemuiserver", "mds", "mds_stores", "coreaudiod", "systemd", "xorg", "gnome-shell", "kwin",
    "kwin_x11", "kwin_wayland", "plasmashell", "pulseaudio", "pipewire", "claude",
}
BROWSERS = {"chrome", "msedge", "firefox", "brave", "opera", "safari", "vivaldi"}
# Startup items it's usually better to keep (security, drivers, sync).
KEEP_HINTS = ("defender", "securityhealth", "antivirus", "norton", "mcafee", "avast", "avg",
              "bitdefender", "kaspersky", "eset", "malwarebytes", "realtek", "synaptics", "elan",
              "nvidia", "amd", "radeon", "intel", "igfx", "audio", "touchpad", "onedrive", "dropbox",
              "icloud", "googledrive", "backup", "sentinel")


@dataclass
class Fix:
    label: str
    explain: str
    action: Callable[[], str]      # runs the fix, returns a short result message
    safe: bool = True              # True = can't lose data or interrupt work
    auto: bool = True              # applied by --auto (only if also safe)
    warning: str = ""


@dataclass
class Issue:
    title: str
    severity: str                  # high | medium | low | ok
    detail: str = ""
    fixes: List[Fix] = field(default_factory=list)


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit not in ("B", "KB") else f"{n:.0f} {unit}"
        n /= 1024


def _log(text):
    try:
        USER_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S}  {text}\n")
    except OSError:
        pass


def _run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="ignore")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def _ask_yes(question):
    try:
        return input(f"{question} (y/N): ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


# ======================================================================== running apps
def _app_name(proc_name):
    name = proc_name.lower()
    return name[:-4] if name.endswith(".exe") else name


def sample_apps(seconds=1.5):
    """Group running processes by app: total CPU % (of whole machine), memory, PIDs, closable."""
    me = getpass.getuser().lower()
    own_pids = {os.getpid()}
    try:
        own_pids.update(p.pid for p in psutil.Process().parents())
    except psutil.Error:
        pass
    procs = []
    for p in psutil.process_iter(["name", "username", "memory_info"]):
        try:
            p.cpu_percent(None)  # first call primes the counter
            procs.append(p)
        except psutil.Error:
            pass
    time.sleep(seconds)
    cores = psutil.cpu_count() or 1
    apps = {}
    for p in procs:
        try:
            name = _app_name(p.info["name"] or "")
            if not name:
                continue
            cpu = p.cpu_percent(None) / cores
            mem = p.info["memory_info"].rss if p.info["memory_info"] else 0
            user = (p.info["username"] or "").lower()
        except psutil.Error:
            continue
        a = apps.setdefault(name, {"name": name, "cpu": 0.0, "mem": 0, "pids": [], "mine": True})
        a["cpu"] += cpu
        a["mem"] += mem
        a["pids"].append(p.pid)
        if not user.endswith(me) or p.pid in own_pids:
            a["mine"] = False
    for a in apps.values():
        a["closable"] = a["mine"] and a["name"] not in PROTECTED
    return apps


def close_app(app, force_prompt=True):
    """Ask the app to close normally (it can still ask to save). Offer force-close if it won't."""
    name, pids = app["name"], app["pids"]
    for pid in pids:
        try:
            if SYSTEM == "Windows":
                _run(["taskkill", "/PID", str(pid)])   # polite close, like clicking X
            else:
                psutil.Process(pid).terminate()
        except psutil.Error:
            pass
    deadline = time.time() + 10
    alive = pids
    while time.time() < deadline:
        alive = [p for p in pids if psutil.pid_exists(p)]
        if not alive:
            break
        time.sleep(0.5)
    if not alive:
        _log(f"closed app {name}")
        return f"Closed {name}."
    if force_prompt and _ask_yes(f"{name} is still open (it may be asking to save). Force it to close? "
                                 "Unsaved work in it will be lost"):
        for pid in alive:
            try:
                psutil.Process(pid).kill()
            except psutil.Error:
                pass
        _log(f"force-closed app {name}")
        return f"Force-closed {name}."
    return f"{name} is still open. Close it yourself when you're ready."


def _close_fix(app, reason):
    label = app["name"].title()
    extra = ""
    if app["name"] in BROWSERS and len(app["pids"]) > 8:
        extra = f" It is running {len(app['pids'])} processes; closing tabs you don't need also helps."
    return Fix(f"Close {label}", f"{label} {reason}.{extra}", lambda: close_app(app), safe=False,
               warning=f"Save your work in {label} first.")


# ======================================================================== temp files
def temp_dirs():
    dirs = [Path(tempfile.gettempdir())]
    home = Path.home()
    if SYSTEM == "Windows":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        dirs += [local / "CrashDumps", Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp",
                 local / "Microsoft/Windows/INetCache"]
    elif SYSTEM == "Darwin":
        dirs += [home / "Library/Caches", home / "Library/Logs/DiagnosticReports"]
    else:
        dirs += [home / ".cache", Path("/tmp")]
    seen, out = set(), []
    for d in dirs:
        try:
            r = d.resolve()
        except OSError:
            continue
        if r.exists() and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def clean_temp(dirs=None, min_age_hours=48, dry_run=False):
    """Delete files older than min_age_hours in temp/cache folders. Files in use are skipped.
    Returns (file_count, bytes)."""
    cutoff = time.time() - min_age_hours * 3600
    count = size = 0
    for root in dirs if dirs is not None else temp_dirs():
        root = Path(root)
        for dirpath, dirnames, filenames in os.walk(root, topdown=False, onerror=lambda e: None):
            for fn in filenames:
                p = Path(dirpath) / fn
                try:
                    st = p.lstat()
                    if p.is_symlink() or st.st_mtime > cutoff:
                        continue
                    if not dry_run:
                        p.unlink()
                    count += 1
                    size += st.st_size
                except OSError:
                    continue  # in use or no permission: leave it
            if not dry_run and Path(dirpath) != root:
                try:
                    Path(dirpath).rmdir()  # only removes folders that are now empty
                except OSError:
                    pass
    if not dry_run:
        _log(f"cleaned {count} temp files, {human(size)}")
    return count, size


# ======================================================================== startup apps
def _filetime_now():
    return int((time.time() + 11644473600) * 10_000_000)


def list_startup():
    """Startup apps that are currently turned on. Each: name, command, where, kind, keep."""
    items = _list_startup_windows() if SYSTEM == "Windows" else _list_startup_files()
    for it in items:
        it["keep"] = any(h in (it["name"] + it.get("command", "")).lower() for h in KEEP_HINTS)
    return items


def _list_startup_windows(base=r"Software\Microsoft\Windows\CurrentVersion"):
    import winreg
    items = []
    sources = [
        (winreg.HKEY_CURRENT_USER, base + r"\Run", "Run", "you"),
        (winreg.HKEY_LOCAL_MACHINE, base + r"\Run", "Run", "all users"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
         "Run32", "all users"),
    ]
    for root, key, approved, who in sources:
        try:
            with winreg.OpenKey(root, key) as k:
                i = 0
                while True:
                    try:
                        name, cmd, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if _approved_enabled(root, base, approved, name):
                        items.append({"name": name, "command": str(cmd), "kind": "registry",
                                      "root": int(root), "approved": approved, "base": base,
                                      "where": f"startup list ({who})"})
        except OSError:
            continue
    folders = [(winreg.HKEY_CURRENT_USER,
                Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup", "you"),
               (winreg.HKEY_LOCAL_MACHINE,
                Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\StartUp",
                "all users")]
    for root, folder, who in folders:
        if not folder.exists():
            continue
        for f in folder.iterdir():
            if f.name.lower() == "desktop.ini" or not f.is_file():
                continue
            if _approved_enabled(root, base, "StartupFolder", f.name):
                items.append({"name": f.stem, "command": str(f), "kind": "registry", "root": int(root),
                              "approved": "StartupFolder", "value": f.name, "base": base,
                              "where": f"Startup folder ({who})"})
    return items


def _approved_enabled(root, base, approved, value):
    import winreg
    try:
        with winreg.OpenKey(root, base + r"\Explorer\StartupApproved\\" + approved) as k:
            data, _ = winreg.QueryValueEx(k, value)
            return not (data and data[0] & 1)   # odd first byte = turned off
    except OSError:
        return True


def _set_approved(item, enabled):
    import winreg
    path = item["base"] + r"\Explorer\StartupApproved\\" + item["approved"]
    data = bytes([2]) + bytes(11) if enabled else bytes([3, 0, 0, 0]) + _filetime_now().to_bytes(8, "little")
    with winreg.CreateKeyEx(item["root"], path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, item.get("value", item["name"]), 0, winreg.REG_BINARY, data)


def _list_startup_files():
    home = Path.home()
    folder = home / "Library/LaunchAgents" if SYSTEM == "Darwin" else home / ".config/autostart"
    pattern = "*.plist" if SYSTEM == "Darwin" else "*.desktop"
    if not folder.exists():
        return []
    return [{"name": f.stem, "command": str(f), "kind": "file", "path": str(f),
             "where": str(folder)} for f in sorted(folder.glob(pattern))]


def disable_startup(item):
    """Turn a startup app off (reversible). Returns a message."""
    try:
        if item["kind"] == "registry":
            _set_approved(item, enabled=False)   # same switch Task Manager uses
        else:
            DISABLED_DIR.mkdir(parents=True, exist_ok=True)
            dest = DISABLED_DIR / Path(item["path"]).name
            shutil.move(item["path"], dest)
            item = dict(item, moved_to=str(dest))
    except PermissionError:
        return (f"'{item['name']}' needs administrator rights. Turn it off in Task Manager > "
                "Startup apps instead.")
    except OSError as e:
        return f"Couldn't turn off '{item['name']}': {e}"
    changes = _load_changes()
    changes.append(dict(item, time=dt.datetime.now().isoformat(timespec="seconds")))
    _save_changes(changes)
    _log(f"turned off startup app {item['name']}")
    return f"Turned off '{item['name']}' at startup. It still works if you open it yourself."


def undo_startup():
    changes = _load_changes()
    if not changes:
        return "There are no startup changes to undo."
    done = []
    for item in changes:
        try:
            if item["kind"] == "registry":
                _set_approved(item, enabled=True)
            else:
                shutil.move(item["moved_to"], item["path"])
            done.append(item["name"])
        except OSError as e:
            print(f"  Couldn't restore '{item['name']}': {e}")
    _save_changes([c for c in changes if c["name"] not in done])
    _log(f"undid startup changes: {', '.join(done)}")
    return "Turned back on: " + (", ".join(done) if done else "nothing")


def _load_changes():
    try:
        return json.loads(STARTUP_LOG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def _save_changes(changes):
    USER_DIR.mkdir(parents=True, exist_ok=True)
    STARTUP_LOG.write_text(json.dumps(changes, indent=2), encoding="utf-8")


def choose_startup_to_disable(items):
    print("\nApps that start automatically when you sign in:")
    for n, it in enumerate(items, 1):
        tag = "   (better to keep: security, driver or sync)" if it["keep"] else ""
        print(f"  {n:2}. {it['name']}{tag}")
    raw = input("Type the numbers to turn off (e.g. 2 5), or press Enter to skip: ")
    picked = [items[int(x) - 1] for x in raw.replace(",", " ").split()
              if x.isdigit() and 1 <= int(x) <= len(items)]
    if not picked:
        return "No startup apps changed."
    return "\n".join(disable_startup(it) for it in picked) + \
        "\nChanges take effect next time you sign in. Type 'undo' in the optimizer to reverse them."


# ======================================================================== other actions
def restart_computer():
    if SYSTEM == "Windows":
        _run(["shutdown", "/r", "/t", "60", "/c", "Sentinel: restarting in 1 minute to speed things up."])
        _log("scheduled restart")
        return "Restarting in 60 seconds. To cancel, open a command prompt and type:  shutdown /a"
    return "Please save your work and restart from the Apple / system menu."


def set_balanced_power():
    code, out = _run(["powercfg", "/setactive", "SCHEME_BALANCED"])
    _log("power plan -> Balanced")
    return "Switched to the Balanced power plan." if code == 0 else f"Couldn't change the power plan: {out}"


def open_path(path):
    if SYSTEM == "Windows":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif SYSTEM == "Darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])
    return f"Opened {path}"


def _clean_action():
    count, size = clean_temp()
    return f"Deleted {count} old temporary files and freed {human(size)}."


def run_quick_scan():
    from .__main__ import main
    main(["scan", "--hide-ok", "--notify"])
    return "Virus scan finished (results above)."


# ======================================================================== diagnosis
def check_cpu(apps, total):
    top = sorted((a for a in apps.values() if a["name"] not in ("system idle process", "idle")),
                 key=lambda a: a["cpu"], reverse=True)[:5]
    names = ", ".join(f"{a['name'].title()} {a['cpu']:.0f}%" for a in top[:3] if a["cpu"] >= 1)
    if total < 60:
        return Issue(f"Processor is not busy ({total:.0f}%)", "ok")
    sev = "high" if total >= 85 else "medium"
    issue = Issue(f"Processor is very busy ({total:.0f}%)", sev,
                  f"Biggest users right now: {names or 'background system tasks'}.")
    for a in top:
        if a["closable"] and a["cpu"] >= 10:
            issue.fixes.append(_close_fix(a, f"is using {a['cpu']:.0f}% of the processor"))
    if not issue.fixes:
        issue.detail += " These are system tasks; they usually calm down after a few minutes."
    return issue


def check_memory(apps):
    vm = psutil.virtual_memory()
    top = sorted(apps.values(), key=lambda a: a["mem"], reverse=True)
    names = ", ".join(f"{a['name'].title()} {human(a['mem'])}" for a in top[:3])
    issues = []
    if vm.percent >= 80:
        sev = "high" if vm.percent >= 90 else "medium"
        issue = Issue(f"Memory is almost full ({vm.percent:.0f}% of {human(vm.total)} used)", sev,
                      f"When memory fills up, the computer swaps to disk and slows down a lot. "
                      f"Biggest users: {names}.")
        for a in top[:6]:
            if a["closable"] and a["mem"] >= 300 * MB and len(issue.fixes) < 3:
                issue.fixes.append(_close_fix(a, f"is using {human(a['mem'])} of memory"))
        issues.append(issue)
    else:
        issues.append(Issue(f"Memory is fine ({vm.percent:.0f}% of {human(vm.total)} used)", "ok"))
    if vm.total < 7.5 * GB:
        issues.append(Issue(f"Only {human(vm.total)} of memory installed", "low",
                            "8 GB or more makes a big difference for modern apps and browsers. "
                            "Adding memory is the most effective hardware upgrade if your computer allows it."))
    return issues


def check_disk():
    drive = (os.environ.get("SystemDrive", "C:") + "\\") if SYSTEM == "Windows" else "/"
    du = psutil.disk_usage(drive)
    free_pct = 100 - du.percent
    tcount, tsize = clean_temp(dry_run=True)
    issues = []
    clean = Fix(f"Delete {human(tsize)} of old temporary files",
                f"{tcount} leftover files older than 2 days in temp and cache folders. Files in use are skipped.",
                _clean_action)
    if free_pct < 10 or du.free < 10 * GB:
        sev = "high" if free_pct < 5 or du.free < 5 * GB else "medium"
        issue = Issue(f"Disk is almost full ({human(du.free)} free on {drive})", sev,
                      "Windows and apps need free space to run smoothly and install updates.")
        if tsize > 50 * MB:
            issue.fixes.append(clean)
        if SYSTEM == "Windows":
            issue.fixes.append(Fix("Open Storage settings", "Windows' own tool to find large files, old "
                                   "updates and the Recycle Bin.", lambda: open_path("ms-settings:storagesense"),
                                   auto=False))
        issue.fixes.append(Fix("Open Downloads folder", "Downloads is often full of old installers you "
                               "no longer need.", lambda: open_path(Path.home() / "Downloads"), auto=False))
        issues.append(issue)
    else:
        issues.append(Issue(f"Disk space is fine ({human(du.free)} free on {drive})", "ok"))
        if tsize > 1 * GB:
            issues.append(Issue(f"{human(tsize)} of old temporary files", "low",
                                "Not urgent, but safe to clear.", [clean]))
    return issues


def check_startup():
    items = list_startup()
    n = len(items)
    if n < 6:
        return Issue(f"Startup is lean ({n} apps start automatically)", "ok")
    sev = "medium" if n >= 10 else "low"
    names = ", ".join(i["name"] for i in items[:6]) + ("..." if n > 6 else "")
    return Issue(f"{n} apps start automatically when you sign in", sev,
                 f"Each one slows down start-up and uses memory all day: {names}",
                 [Fix("Choose startup apps to turn off", "You pick which ones. Reversible with 'undo'.",
                      lambda: choose_startup_to_disable(items), safe=True, auto=False)])


def check_restart():
    issues = []
    days = (time.time() - psutil.boot_time()) / 86400
    pending = False
    if SYSTEM == "Windows":
        import winreg
        for key in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"):
            try:
                winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key).Close()
                pending = True
            except OSError:
                pass
    restart = Fix("Restart the computer", "A restart clears memory leaks and finishes updates.",
                  restart_computer, safe=False, auto=False, warning="Save and close everything first.")
    if pending:
        issues.append(Issue("Updates are waiting for a restart", "high",
                            "Half-installed updates can slow things down until you restart.", [restart]))
    elif days >= 7:
        issues.append(Issue(f"Not restarted for {days:.0f} days", "medium",
                            "Long uptimes let memory leaks and stuck background tasks build up.", [restart]))
    else:
        issues.append(Issue(f"Restarted recently ({days:.1f} days ago)", "ok"))
    return issues


def check_power():
    if SYSTEM != "Windows":
        return []
    _, out = _run(["powercfg", "/getactivescheme"])
    if "a1841308-3541-4fab-bc81-f71556f20b4a" in out.lower() or "power saver" in out.lower():
        on_battery = False
        try:
            b = psutil.sensors_battery()
            on_battery = bool(b and not b.power_plugged)
        except Exception:
            pass
        return [Issue("Power saver mode is on", "medium",
                      "Power saver slows the processor down to save energy."
                      + (" You're on battery, so only change this if you need speed now." if on_battery else ""),
                      [Fix("Switch to Balanced power plan", "Full speed when needed, saves power when idle.",
                           set_balanced_power, auto=not on_battery)])]
    return [Issue("Power plan is not limiting speed", "ok")]


def check_malware():
    return Issue("Malware can also slow a computer", "low",
                 "Hidden miners and adware use the processor and memory in the background.",
                 [Fix("Run a quick virus scan", "Scans Downloads, Desktop, Documents and temp folders.",
                      run_quick_scan, auto=False)])


def diagnose(progress=True):
    if progress:
        print("Checking what's slowing your computer down (about 10 seconds)...", file=sys.stderr)
    total_cpu = psutil.cpu_percent(interval=1.0)
    apps = sample_apps()
    total_cpu = max(total_cpu, psutil.cpu_percent(interval=None))
    issues = [check_cpu(apps, total_cpu)]
    issues += check_memory(apps)
    issues += check_disk()
    issues.append(check_startup())
    issues += check_restart()
    issues += check_power()
    issues.append(check_malware())
    order = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    return sorted(issues, key=lambda i: order.get(i.severity, 9))


def health_score(issues):
    penalty = {"high": 25, "medium": 10, "low": 3}
    return max(0, 100 - sum(penalty.get(i.severity, 0) for i in issues))


# ======================================================================== interactive flow
COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "ok": "\033[32m"}
RESET = "\033[0m"


def print_diagnosis(issues):
    score = health_score(issues)
    verdict = "good" if score >= 85 else "could be better" if score >= 60 else "needs attention"
    print(f"\nSpeed health: {score}/100 ({verdict})\n")
    fixes = []
    for issue in issues:
        c = COLORS.get(issue.severity, "")
        print(f"{c}[{issue.severity.upper():6}]{RESET} {issue.title}")
        if issue.detail:
            print(f"          {issue.detail}")
        for fx in issue.fixes:
            fixes.append(fx)
            risk = "" if fx.safe else "  (asks first)"
            print(f"    {len(fixes)}) {fx.label}{risk}")
            print(f"       {fx.explain}")
    return fixes


def apply_fix(fx):
    if not fx.safe:
        if fx.warning:
            print(f"  ! {fx.warning}")
        if not _ask_yes(f"  Go ahead: {fx.label}?"):
            return "Skipped."
    try:
        return fx.action()
    except Exception as e:
        return f"That didn't work: {e}"


def run(auto=False, report_only=False, undo=False):
    if psutil is None:
        print("The optimizer needs the 'psutil' package:  pip install psutil")
        return 1
    if SYSTEM == "Windows":
        os.system("")
    if undo:
        print(undo_startup())
        return 0
    issues = diagnose()
    fixes = print_diagnosis(issues)
    if report_only:
        return 0
    if not fixes:
        print("\nNothing to fix. Your computer looks healthy.")
        return 0
    if auto:
        chosen = [f for f in fixes if f.safe and f.auto]
        if not chosen:
            print("\nNo automatic fixes needed. Run without --auto to see all suggestions.")
    else:
        print("\nType the numbers of the fixes to apply (e.g. 1 3), 'safe' for all safe fixes,")
        print("'undo' to turn startup apps back on, or press Enter to skip.")
        raw = input("> ").strip().lower()
        if raw == "undo":
            print(undo_startup())
            return 0
        if raw == "safe":
            chosen = [f for f in fixes if f.safe and f.auto]
        else:
            chosen = [fixes[int(x) - 1] for x in raw.replace(",", " ").split()
                      if x.isdigit() and 1 <= int(x) <= len(fixes)]
    if not chosen:
        if not auto:
            print("No changes made.")
        return 0
    for fx in chosen:
        print(f"\n> {fx.label}")
        print(f"  {apply_fix(fx)}")
    vm = psutil.virtual_memory()
    print(f"\nDone. Memory now {vm.percent:.0f}% used. A log of changes is in {LOG_FILE}")
    return 0
