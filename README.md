# Sentinel

A cross-platform scanner that checks devices for **malware** and **weak security settings**.

| Device | Malware scan | Security settings check |
|---|---|---|
| Windows | Files (hash signatures, YARA, disguised extensions), suspicious startup programs | Defender, firewall, UAC, Remote Desktop, SMBv1, BitLocker, Windows Update |
| macOS | Files, unknown Launch Agents | SIP, Gatekeeper, FileVault, firewall, auto-updates |
| Linux | Files | UFW firewall, SSH config |
| Android (USB) | Known bad app list, sideloaded apps, optional APK hashing | Security patch age, root, encryption, accessibility abuse |
| iPhone/iPad (USB) | Not possible (Apple blocks it, see below) | iOS version |

## Install

Requires Python 3.9+. No other packages are required.

```bash
git clone https://github.com/<you>/sentinel.git
cd sentinel
pip install -r requirements.txt   # optional: adds YARA rule scanning
```

## Use

```bash
python -m sentinel all                  # settings + quick scan + connected phones
python -m sentinel settings             # security settings only
python -m sentinel scan                 # quick scan of Downloads, Desktop, Documents, temp
python -m sentinel scan --full          # whole home folder
python -m sentinel scan D:\ E:\stuff    # specific drives or folders
python -m sentinel android --deep       # Android phone, hashing every app
python -m sentinel ios
python -m sentinel all --html report.html --json report.json
```

Run as administrator (Windows) or with `sudo` (macOS/Linux) for complete results.
Exit code is `1` when anything critical or high is found, so it works in scripts.

### Phones

- **Android:** install [platform-tools](https://developer.android.com/tools/releases/platform-tools) (`adb`),
  turn on *Developer options > USB debugging*, plug in and accept the prompt.
- **iPhone:** install `libimobiledevice`. Apple's sandbox stops any app from inspecting other apps,
  so only device info is available. For spyware forensics use [MVT](https://docs.mvt.re).

## Keeping signatures up to date

Detection is only as good as the signature list in `sentinel/data/signatures.txt`.
Add SHA-256 hashes from any list (one hash per line):

```bash
python -m sentinel update hashes.txt
python -m sentinel update https://example.com/sha256-list.txt
```

Free sources: [MalwareBazaar](https://bazaar.abuse.ch/export/) hash exports, VirusShare hash lists.
For Android stalkerware package names, see
[stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) and add them to
`sentinel/data/android_bad_packages.txt`. Add YARA rules to `sentinel/data/rules/`.

## Limitations

This is a scanner, not a replacement for a real-time antivirus. It does not watch files as they
open, does not quarantine automatically, and cannot detect malware that isn't in its signatures or
rules. Keep Microsoft Defender / XProtect turned on.

## Project layout

```
sentinel/
  __main__.py      command line
  file_scanner.py  hashing, YARA, heuristics
  posture.py       Windows / macOS / Linux settings checks
  mobile.py        Android (adb) and iOS (libimobiledevice)
  report.py        terminal, JSON and HTML output
  data/            signatures, YARA rules, bad Android packages
```
