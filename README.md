# Sentinel

A cross-platform scanner that checks devices for **malware** and **weak security settings**.

## Download (no install needed)

Go to the [Releases page](https://github.com/ayerokun-cmd/sentinel/releases/latest), download the
file for your computer and double-click it. A simple numbered menu opens, so no commands needed:

```
  1  Scan this computer (quick)          6  Scan an Android phone (USB)
  2  Scan this computer (full, slower)   7  Update malware lists
  3  Real-time protection                8  Set up email alerts
  4  Check a link                        9  Send a test alert
  5  Check an email file (.eml)
```

- **Windows:** `Sentinel-windows.exe`. If you see "Windows protected your PC", click *More info* then *Run anyway*
  (the program isn't code-signed yet).
- **Mac:** `Sentinel-macos`. Right-click it and choose *Open* the first time.
- **Linux:** `Sentinel-linux`. Run `chmod +x Sentinel-linux && ./Sentinel-linux`.

Run option **7** first to download the latest malware lists (about 130,000 malware fingerprints
and 125,000 scam domains, saved in `~/.sentinel/`).

### Shortcuts for one task

`Sentinel.exe --menu <number>` runs one menu option directly, for example
`Sentinel.exe --menu 1` for a quick scan. Use it for Desktop shortcuts or scheduled tasks.

### Building the program yourself

```bash
pip install pyinstaller
python build.py          # creates dist/Sentinel.exe (or dist/Sentinel on Mac/Linux)
```

GitHub Actions builds all three versions on every push. To publish a release, push a tag:
`git tag v0.3.0 && git push --tags`.

| Device | Malware scan | Security settings check |
|---|---|---|
| Windows | Files (hash signatures, YARA, disguised extensions), suspicious startup programs | Defender, firewall, UAC, Remote Desktop, SMBv1, BitLocker, Windows Update |
| macOS | Files, unknown Launch Agents | SIP, Gatekeeper, FileVault, firewall, auto-updates |
| Linux | Files | UFW firewall, SSH config |
| Android (USB) | Known bad app list, sideloaded apps, optional APK hashing | Security patch age, root, encryption, accessibility abuse |
| iPhone/iPad (USB) | Not possible (Apple blocks it, see below) | iOS version |

It also looks **inside** files:

| What | Detects |
|---|---|
| **PHP web shells** (`.php`, `.phtml`, `.phar`, ...) | Code that runs visitor commands, encoded `eval`, `preg_replace /e`, known shell names (c99, r57, WSO, b374k...), obfuscation. Also PHP hidden inside images. |
| **Emails** (`.eml`, `.mbox`) | Spoofed senders, failed SPF/DKIM/DMARC, mismatched Reply-To, dangerous or disguised attachments, macro documents, links whose text lies about where they go, password forms, scam wording. |
| **Links** (in emails, `.html`, `.url` files, or checked directly) | Blocklisted domains, fake brand sites (`paypal.secure-login.xyz`), raw IP addresses, look-alike (punycode) domains, `@` tricks, shorteners, direct program downloads, logins over plain http. |

## Alerts

When something is found, Sentinel can alert you by:

- **Desktop pop-up** on Windows, macOS and Linux
- **Chat message** through a Slack, Discord or Microsoft Teams webhook
- **Email** over SMTP
- **Log file:** every alert is also saved to `~/.sentinel/alerts.log`

```bash
python -m sentinel scan --notify                       # pop-up if anything high or critical is found
python -m sentinel all --notify --notify-level medium  # alert on medium and above
python -m sentinel scan --webhook https://hooks.slack.com/services/...
python -m sentinel watch                               # real-time: alert the moment a bad file lands
python -m sentinel watch C:\inetpub\wwwroot            # watch a web server for new web shells
python -m sentinel notify-test                         # check your alert channels work
```

To set up alerts once instead of passing flags each time, run `python -m sentinel notify-setup`
and edit `~/.sentinel/config.json` (webhook URL, email server, alert level, `"enabled": true`).
The email password is read from the `SENTINEL_SMTP_PASSWORD` environment variable and never
stored in the file.

## Install from source (for developers)

Requires Python 3.9+. No other packages are required.

```bash
git clone https://github.com/ayerokun-cmd/sentinel.git
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
python -m sentinel url "http://paypal.account-verify.top/login"   # check a link
python -m sentinel scan suspicious-email.eml                      # check an email
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

Free sources that need no account: [malicious-hash](https://github.com/romainmarcoux/malicious-hash) (SHA-256 lists).
The easiest way is menu option 7 (*Update malware lists*).
For Android stalkerware package names, see
[stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) and add them to
`sentinel/data/android_bad_packages.txt`. Add YARA rules to `sentinel/data/rules/`.

Bad domains for link checks live in `sentinel/data/bad_domains.txt`. Import a public list:

```bash
python -m sentinel update --domains https://hole.cert.pl/domains/v2/domains.txt
```

## Tests

```bash
python -m unittest discover tests
```

Test samples are built in memory so your real antivirus doesn't quarantine them.

## Limitations

This is a scanner, not a replacement for a real-time antivirus. It does not watch files as they
open, does not quarantine automatically, and cannot detect malware that isn't in its signatures or
rules. Keep Microsoft Defender / XProtect turned on.

## Project layout

```
sentinel/
  __main__.py      command line
  file_scanner.py    hashing, YARA, heuristics, watch mode
  content_scanner.py PHP web shells, emails, links inside files
  url_checks.py      phishing / malicious link checks
  notify.py          desktop, webhook, email and log alerts
  posture.py         Windows / macOS / Linux settings checks
  mobile.py          Android (adb) and iOS (libimobiledevice)
  report.py          terminal, JSON and HTML output
  data/              signatures, YARA rules, bad domains, bad Android packages
tests/               unit tests
```

Outlook `.msg` files aren't read yet; save the email as `.eml` first (drag it out of Outlook
or use *File > Save As*).
