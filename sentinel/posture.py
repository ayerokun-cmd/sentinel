"""Security-settings checks (the "vulnerability" side) for the computer Sentinel runs on."""
import datetime as dt
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

from .findings import Finding

CAT = "security-setting"


def run(cmd, timeout=60):
    """Run a command, return (exit_code, stdout). Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="ignore")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return -1, str(e)


def ps_json(script):
    """Run PowerShell and parse JSON output. Returns None on failure."""
    code, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     script + " | ConvertTo-Json -Compress -Depth 3"])
    if code != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------- Windows
def _reg_value(root, key, name):
    try:
        import winreg
        with winreg.OpenKey(root, key) as k:
            return winreg.QueryValueEx(k, name)[0]
    except OSError:
        return None


def check_windows():
    import winreg
    f = []

    av = ps_json("Get-MpComputerStatus | Select-Object AntivirusEnabled,"
                 "RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected")
    if av is None:
        f.append(Finding(CAT, "Could not read Microsoft Defender status", "medium",
                         "Another antivirus may be installed, or Defender is disabled.",
                         "Open Windows Security and confirm an antivirus is active."))
    else:
        if not av.get("RealTimeProtectionEnabled"):
            f.append(Finding(CAT, "Real-time virus protection is OFF", "critical",
                             "Microsoft Defender is not watching files as they are opened.",
                             "Windows Security > Virus & threat protection > turn on Real-time protection."))
        else:
            f.append(Finding(CAT, "Real-time virus protection is on", "ok"))
        age = av.get("AntivirusSignatureAge") or 0
        if age > 3:
            f.append(Finding(CAT, f"Virus definitions are {age} days old", "high",
                             "Out-of-date definitions miss new malware.",
                             "Windows Security > Virus & threat protection > Check for updates."))
        if av.get("IsTamperProtected") is False:
            f.append(Finding(CAT, "Tamper protection is off", "medium",
                             "Malware can switch Defender off without you noticing.",
                             "Windows Security > Virus & threat protection settings > Tamper Protection."))

    fw = ps_json("Get-NetFirewallProfile | Select-Object Name,Enabled")
    if isinstance(fw, dict):
        fw = [fw]
    if fw:
        off = [p["Name"] for p in fw if not p.get("Enabled")]
        if off:
            f.append(Finding(CAT, f"Firewall is off for: {', '.join(off)}", "high",
                             "Other devices on the network can reach services on this PC.",
                             "Windows Security > Firewall & network protection > turn each profile on."))
        else:
            f.append(Finding(CAT, "Firewall is on for all network types", "ok"))

    lua = _reg_value(winreg.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    if lua == 0:
        f.append(Finding(CAT, "User Account Control (UAC) is disabled", "high",
                         "Programs can make system changes without asking.",
                         "Control Panel > User Accounts > Change User Account Control settings."))

    rdp = _reg_value(winreg.HKEY_LOCAL_MACHINE,
                     r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if rdp == 0:
        f.append(Finding(CAT, "Remote Desktop is enabled", "medium",
                         "Remote Desktop is a common target for password-guessing attacks.",
                         "Settings > System > Remote Desktop > Off, unless you need it."))

    smb1 = ps_json("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol")
    if smb1 and smb1.get("EnableSMB1Protocol"):
        f.append(Finding(CAT, "SMBv1 file sharing is enabled", "high",
                         "SMBv1 is the protocol abused by WannaCry ransomware.",
                         "Run as admin: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"))

    bl = ps_json("Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object ProtectionStatus")
    if bl is None:
        f.append(Finding(CAT, "Disk encryption status unknown", "info",
                         "Reading BitLocker status needs administrator rights.",
                         "Run Sentinel as administrator to check BitLocker / Device Encryption."))
    elif str(bl.get("ProtectionStatus")) in ("0", "Off"):
        f.append(Finding(CAT, "System drive is not encrypted", "medium",
                         "If the laptop is lost or stolen, files can be read directly.",
                         "Settings > Privacy & security > Device encryption (or BitLocker)."))
    else:
        f.append(Finding(CAT, "System drive is encrypted", "ok"))

    hf = ps_json("Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending "
                 "| Select-Object -First 1 @{n='d';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}")
    if hf and hf.get("d"):
        last = dt.date.fromisoformat(hf["d"])
        days = (dt.date.today() - last).days
        if days > 45:
            f.append(Finding(CAT, f"No Windows update installed for {days} days", "high",
                             f"Last update installed on {last}. Missing patches leave known holes open.",
                             "Settings > Windows Update > Check for updates."))
        else:
            f.append(Finding(CAT, f"Windows updates are recent (last: {last})", "ok"))

    f.extend(_windows_startup_items())
    return f


def _windows_startup_items():
    """Flag auto-start programs that live in temp or download folders."""
    import winreg
    f = []
    keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")]
    risky = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp", "\\public\\")
    for root, key in keys:
        try:
            with winreg.OpenKey(root, key) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if any(r in str(value).lower() for r in risky):
                        f.append(Finding("malware", f"Suspicious startup program: {name}", "high",
                                         f"Starts with Windows from an unusual folder: {value}",
                                         "If you don't recognise it, remove it in Task Manager > Startup apps "
                                         "and scan the file.", str(value)))
        except OSError:
            continue
    return f


# ---------------------------------------------------------------- macOS
def check_macos():
    f = []
    _, out = run(["csrutil", "status"])
    if "disabled" in out.lower():
        f.append(Finding(CAT, "System Integrity Protection is disabled", "critical",
                         "Malware can modify protected system files.",
                         "Boot to Recovery mode, open Terminal, run: csrutil enable"))
    elif "enabled" in out.lower():
        f.append(Finding(CAT, "System Integrity Protection is on", "ok"))

    _, out = run(["spctl", "--status"])
    if "disabled" in out.lower():
        f.append(Finding(CAT, "Gatekeeper is disabled", "high",
                         "Apps from unknown developers can run without any check.",
                         "Run: sudo spctl --master-enable"))
    elif "enabled" in out.lower():
        f.append(Finding(CAT, "Gatekeeper is on", "ok"))

    _, out = run(["fdesetup", "status"])
    if "off" in out.lower():
        f.append(Finding(CAT, "FileVault disk encryption is off", "medium",
                         "If the Mac is lost or stolen, files can be read directly.",
                         "System Settings > Privacy & Security > FileVault > Turn On."))
    elif "on" in out.lower():
        f.append(Finding(CAT, "FileVault is on", "ok"))

    _, out = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if "disabled" in out.lower():
        f.append(Finding(CAT, "macOS firewall is off", "medium",
                         "Incoming connections to apps are not filtered.",
                         "System Settings > Network > Firewall > On."))
    elif "enabled" in out.lower():
        f.append(Finding(CAT, "macOS firewall is on", "ok"))

    _, out = run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                  "AutomaticallyInstallMacOSUpdates"])
    if out.strip() == "0":
        f.append(Finding(CAT, "Automatic macOS updates are off", "medium",
                         "Security fixes are not installed automatically.",
                         "System Settings > General > Software Update > Automatic updates."))

    # Launch agents are the most common persistence trick for Mac malware.
    for d in [Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"),
              Path("/Library/LaunchDaemons")]:
        if not d.exists():
            continue
        for plist in d.glob("*.plist"):
            if not plist.name.startswith(("com.apple.", "com.google.", "com.microsoft.")):
                f.append(Finding("malware", f"Auto-start item: {plist.name}", "info",
                                 "Runs automatically at login. Most are legitimate.",
                                 "If you don't recognise the app, remove the file and restart.",
                                 str(plist)))
    return f


# ---------------------------------------------------------------- Linux
def check_linux():
    f = []
    if shutil.which("ufw"):
        _, out = run(["ufw", "status"])
        if "inactive" in out.lower():
            f.append(Finding(CAT, "UFW firewall is inactive", "medium", "",
                             "Run: sudo ufw enable"))
    sshd = Path("/etc/ssh/sshd_config")
    if sshd.exists():
        try:
            text = sshd.read_text(errors="ignore").lower()
            if "\npermitrootlogin yes" in text:
                f.append(Finding(CAT, "SSH allows root login", "high", "",
                                 "Set 'PermitRootLogin no' in /etc/ssh/sshd_config."))
            if "\npasswordauthentication yes" in text:
                f.append(Finding(CAT, "SSH allows password login", "medium",
                                 "Passwords can be guessed; keys are safer.",
                                 "Set 'PasswordAuthentication no' and use SSH keys."))
        except PermissionError:
            pass
    return f


def check_local():
    system = platform.system()
    if system == "Windows":
        return check_windows()
    if system == "Darwin":
        return check_macos()
    if system == "Linux":
        return check_linux()
    return [Finding(CAT, f"No settings checks for {system}", "info")]


def default_scan_paths():
    """Places malware most often lands for a quick scan."""
    home = Path.home()
    paths = [home / "Downloads", home / "Desktop", home / "Documents"]
    if platform.system() == "Windows":
        paths += [Path(os.environ.get("TEMP", "")),
                  Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"]
    elif platform.system() == "Darwin":
        paths += [home / "Library/LaunchAgents", Path("/Applications"), Path("/tmp")]
    else:
        paths += [Path("/tmp"), home / ".config/autostart"]
    return [p for p in paths if str(p) and p.exists()]
