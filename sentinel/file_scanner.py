"""File scanning: known-bad hashes, optional YARA rules, and simple heuristics."""
import hashlib
import os
import sys
from pathlib import Path

from . import content_scanner, url_checks
from .findings import Finding

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_SIGNATURES = DATA_DIR / "signatures.txt"
DEFAULT_RULES = DATA_DIR / "rules"

MAX_FILE_BYTES = 200 * 1024 * 1024   # skip files bigger than 200 MB
CHUNK = 1024 * 1024

# Folders that are slow to walk and rarely useful to scan.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "$Recycle.Bin", "System Volume Information",
    "WinSxS", "proc", "sys", "dev", ".Trash",
}

EXECUTABLE_EXTS = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".hta", ".msi", ".jar", ".apk", ".app", ".dmg", ".pkg", ".sh", ".command", ".lnk",
}
DOCUMENT_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".zip"}


def load_signatures(paths):
    """Read SHA-256 signature files. Each line: <sha256> [name]. '#' starts a comment."""
    sigs = {}
    for p in paths:
        p = Path(p)
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            h = parts[0].lower()
            if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                sigs[h] = parts[1].strip() if len(parts) > 1 else "Known malware"
    return sigs


def load_yara(rules_dir):
    """Compile YARA rules if yara-python is installed. Returns None otherwise."""
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    rules_dir = Path(rules_dir)
    files = {f.stem: str(f) for f in rules_dir.glob("*.yar*")} if rules_dir.exists() else {}
    if not files:
        return None
    return yara.compile(filepaths=files)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def heuristic_checks(path: Path):
    """Cheap red flags that need no signature database."""
    out = []
    name = path.name.lower()
    suffixes = [s.lower() for s in path.suffixes]
    # "invoice.pdf.exe" style double extensions
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTS and suffixes[-2] in DOCUMENT_EXTS:
        out.append(Finding(
            "malware", "Disguised file extension", "high",
            f"'{path.name}' pretends to be a {suffixes[-2]} file but is really {suffixes[-1]}.",
            "Do not open it. Delete it unless you know exactly where it came from.", str(path)))
    # Right-to-left override character used to hide real extensions
    if "‮" in name:
        out.append(Finding(
            "malware", "Hidden characters in file name", "high",
            "The name uses a right-to-left override character, a common trick to hide '.exe'.",
            "Delete the file.", str(path)))
    return out


def iter_files(roots):
    for root in roots:
        root = Path(root).expanduser()
        if root.is_file():
            yield root
            continue
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                yield Path(dirpath) / fn


def scan_paths(roots, signature_files=None, rules_dir=DEFAULT_RULES, progress=True,
               domain_files=None):
    sigs = load_signatures(signature_files or [DEFAULT_SIGNATURES])
    bad_domains = url_checks.load_bad_domains(domain_files)
    yara_rules = load_yara(rules_dir)
    findings = []
    stats = {"files_scanned": 0, "files_skipped": 0, "signatures": len(sigs),
             "yara": yara_rules is not None}

    for path in iter_files(roots):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                stats["files_skipped"] += 1
                continue
            findings.extend(heuristic_checks(path))
            digest = sha256_of(path)
            if digest in sigs:
                findings.append(Finding(
                    "malware", f"Known malware: {sigs[digest]}", "critical",
                    f"SHA-256 {digest} matches the signature database.",
                    "Quarantine or delete this file, then run a full scan.", str(path)))
            if yara_rules is not None:
                for m in yara_rules.match(str(path), timeout=30):
                    findings.append(Finding(
                        "malware", f"YARA rule matched: {m.rule}", "high",
                        f"Rule set '{m.namespace}' flagged this file.",
                        "Inspect the file; upload it to VirusTotal for a second opinion.", str(path)))
            # PHP web shells, emails and links inside web pages
            findings.extend(content_scanner.scan_file(path, sigs, bad_domains))
            stats["files_scanned"] += 1
            if progress and stats["files_scanned"] % 500 == 0:
                print(f"  ...{stats['files_scanned']} files scanned", file=sys.stderr)
        except (PermissionError, OSError):
            stats["files_skipped"] += 1
        except Exception:  # a YARA timeout or odd file must not stop the scan
            stats["files_skipped"] += 1
    return findings, stats


def watch(roots, notifier, interval=10, on_findings=None, **scan_kwargs):
    """Keep checking folders; scan any file that is new or changed and alert straight away."""
    import time

    def snapshot():
        snap = {}
        for p in iter_files(roots):
            try:
                snap[p] = p.stat().st_mtime
            except OSError:
                pass
        return snap

    known = snapshot()
    print(f"Watching {len(known)} files in: {', '.join(map(str, roots))}  (Ctrl+C to stop)",
          file=sys.stderr)
    try:
        while True:
            time.sleep(interval)
            current = snapshot()
            changed = [p for p, m in current.items() if known.get(p) != m]
            known = current
            if not changed:
                continue
            found, _ = scan_paths(changed, progress=False, **scan_kwargs)
            if found:
                if on_findings:
                    on_findings(found)
                notifier.send(found, context="real-time watch")
    except KeyboardInterrupt:
        print("Stopped watching.", file=sys.stderr)
