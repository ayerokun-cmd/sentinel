"""Phone checks over USB.

Android: uses `adb` (Android platform-tools). Turn on Developer options > USB debugging.
iOS:     uses `ideviceinfo` (libimobiledevice). Apple does not allow any app to scan
         other apps on an iPhone, so iOS support is limited to device info. For deep
         spyware forensics, use Amnesty's Mobile Verification Toolkit (MVT).
"""
import datetime as dt
import shutil
import tempfile
from pathlib import Path

from .file_scanner import DATA_DIR, load_signatures, sha256_of, DEFAULT_SIGNATURES
from .findings import Finding
from .posture import run

CAT = "device"
BAD_PACKAGES_FILE = DATA_DIR / "android_bad_packages.txt"



def _adb(serial, *args, timeout=60):
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    return run(cmd, timeout=timeout)


def _prop(serial, name):
    return _adb(serial, "shell", "getprop", name)[1].strip()


def list_android_devices():
    if not shutil.which("adb"):
        return None
    _, out = run(["adb", "devices"])
    return [line.split()[0] for line in out.splitlines()[1:]
            if line.strip().endswith("device")]


def _load_bad_packages():
    if not BAD_PACKAGES_FILE.exists():
        return {}
    bad = {}
    for line in BAD_PACKAGES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            parts = line.split(None, 1)
            bad[parts[0]] = parts[1] if len(parts) > 1 else "Known malicious app"
    return bad


def check_android(serial=None, deep=False):
    devices = list_android_devices()
    if devices is None:
        return [Finding(CAT, "adb not found", "info",
                        "Install Android platform-tools to scan Android phones.",
                        "https://developer.android.com/tools/releases/platform-tools")]
    if not devices:
        return [Finding(CAT, "No Android device connected", "info",
                        "Plug in the phone, enable USB debugging and accept the prompt on screen.")]
    serial = serial or devices[0]
    f = []
    model = _prop(serial, "ro.product.model")
    version = _prop(serial, "ro.build.version.release")
    f.append(Finding(CAT, f"Android device: {model} (Android {version})", "info", path=serial))

    patch = _prop(serial, "ro.build.version.security_patch")
    try:
        age = (dt.date.today() - dt.date.fromisoformat(patch)).days
        if age > 180:
            f.append(Finding(CAT, f"Security patch is {age} days old ({patch})", "critical",
                             "The phone is missing many months of security fixes.",
                             "Settings > System > Software update. If none is offered, the phone "
                             "is no longer supported by its maker."))
        elif age > 90:
            f.append(Finding(CAT, f"Security patch is {age} days old ({patch})", "high", "",
                             "Settings > System > Software update."))
        else:
            f.append(Finding(CAT, f"Security patch is recent ({patch})", "ok"))
    except ValueError:
        pass

    _, su = _adb(serial, "shell", "which su")
    if su.strip().startswith("/") or _prop(serial, "ro.debuggable") == "1":
        f.append(Finding(CAT, "Phone appears to be rooted", "high",
                         "Root access lets any app with root bypass Android's protections.",
                         "Unroot or reflash stock firmware unless you rooted it on purpose."))

    if _prop(serial, "ro.crypto.state") == "unencrypted":
        f.append(Finding(CAT, "Phone storage is not encrypted", "high", "",
                         "Set a screen lock PIN; modern Android encrypts automatically."))

    _, acc = _adb(serial, "shell", "settings get secure enabled_accessibility_services")
    acc = acc.strip()
    if acc and acc != "null":
        for svc in acc.split(":"):
            f.append(Finding(CAT, f"App has accessibility access: {svc.split('/')[0]}", "medium",
                             "Accessibility access can read the screen and tap for you. "
                             "Spyware and banking trojans abuse it.",
                             "Settings > Accessibility: turn it off for apps you don't recognise."))

    # Third-party apps and where they were installed from
    _, out = _adb(serial, "shell", "pm list packages -3 -i")
    bad = _load_bad_packages()
    packages = []
    for line in out.splitlines():
        if not line.startswith("package:"):
            continue
        pkg, _, installer = line[len("package:"):].partition(" installer=")
        pkg, installer = pkg.strip(), installer.strip()
        packages.append(pkg)
        if pkg in bad:
            f.append(Finding("malware", f"Known malicious app: {pkg}", "critical", bad[pkg],
                             "Uninstall it: Settings > Apps. If it can't be removed, check "
                             "Settings > Security > Device admin apps first.", pkg))
        elif installer in ("", "null"):
            f.append(Finding(CAT, f"Sideloaded app: {pkg}", "low",
                             "Installed from outside an app store, so it skipped store malware checks.",
                             "Remove it if you don't recognise it.", pkg))
    f.append(Finding(CAT, f"{len(packages)} third-party apps installed", "info"))

    if deep:
        f.extend(_hash_apks(serial, packages))
    return f


def _hash_apks(serial, packages):
    """Copy each app's APK to the computer and compare its hash to the signature list."""
    sigs = load_signatures([DEFAULT_SIGNATURES])
    f = []
    with tempfile.TemporaryDirectory() as tmp:
        for pkg in packages:
            _, out = _adb(serial, "shell", "pm path", pkg)
            for line in out.splitlines():
                if not line.startswith("package:"):
                    continue
                remote = line[len("package:"):].strip()
                local = Path(tmp) / f"{pkg}.apk"
                code, _ = _adb(serial, "pull", remote, str(local), timeout=300)
                if code != 0 or not local.exists():
                    continue
                digest = sha256_of(local)
                if digest in sigs:
                    f.append(Finding("malware", f"Malware app: {pkg} ({sigs[digest]})", "critical",
                                     f"APK hash {digest} matches the signature database.",
                                     "Uninstall the app immediately.", pkg))
                local.unlink(missing_ok=True)
                break  # base APK is enough
    return f


def check_ios():
    if not shutil.which("ideviceinfo"):
        return [Finding(CAT, "iOS tools not installed", "info",
                        "Install libimobiledevice to read iPhone info over USB.",
                        "macOS: brew install libimobiledevice | Windows: install iTunes + libimobiledevice")]
    code, out = run(["ideviceinfo"])
    if code != 0:
        return [Finding(CAT, "No iPhone/iPad connected", "info",
                        "Connect it by USB, unlock it and tap 'Trust this computer'.")]
    info = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    f = [Finding(CAT, f"iOS device: {info.get('ProductType', '?')} on iOS "
                      f"{info.get('ProductVersion', '?')}", "info")]
    major = info.get("ProductVersion", "0").split(".")[0]
    if major.isdigit() and int(major) < 17:
        f.append(Finding(CAT, f"iOS {info['ProductVersion']} is out of date", "high",
                         "Older iOS versions have publicly known, actively exploited bugs.",
                         "Settings > General > Software Update."))
    f.append(Finding(CAT, "Deep iPhone scan not possible from an app", "info",
                     "Apple's sandbox blocks scanning other apps. For spyware checks (e.g. Pegasus), "
                     "make an encrypted backup and analyse it with MVT.",
                     "https://docs.mvt.re"))
    return f
