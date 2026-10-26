"""Looks inside files: PHP web shells, emails (.eml / .mbox) and links in web pages."""
import email
import email.policy
import hashlib
import mailbox
import re
from email.utils import getaddresses, parseaddr
from pathlib import Path

from . import url_checks
from .findings import Finding

MAX_CONTENT_BYTES = 10 * 1024 * 1024

PHP_EXTS = {".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".inc", ".pht"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".ico", ".bmp", ".webp", ".svg"}
EMAIL_EXTS = {".eml"}
MBOX_EXTS = {".mbox", ".mbx"}
LINK_EXTS = {".html", ".htm", ".url", ".webloc", ".svg"}

# ------------------------------------------------------------------ PHP web shells
# (pattern, reason, weight). A file's weights add up; a high total means a likely web shell.
_INPUT = r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)"
_EXEC = r"(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)"
_DECODE = r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin)"
PHP_RULES = [
    (rf"\b(?:eval|assert)\s*\(\s*(?:@\s*)?{_DECODE}\s*\(", "runs hidden, encoded code", 5),
    (rf"\b{_EXEC}\s*\(\s*(?:@\s*)?(?:(?:stripslashes|trim|{_DECODE})\s*\(\s*)*{_INPUT}",
     "runs commands sent by a visitor", 6),
    (rf"{_INPUT}\s*\[[^\]]{{1,40}}\]\s*\(", "calls a function name sent by a visitor", 5),
    (rf"`[^`]*{_INPUT}[^`]*`", "runs a shell command built from visitor input", 6),
    (r"preg_replace\s*\(\s*(['\"]).{1,200}?/[a-z]*e[a-z]*\1", "uses preg_replace /e to run code", 5),
    (r"\b(?:c99shell|r57shell|b374k|FilesMan|weevely|IndoXploit|AlfaShell|WSO\s*[0-9.]+)\b",
     "contains the name of a known web shell", 5),
    (r"\bcreate_function\s*\(", "builds functions from text", 2),
    (r"\bfsockopen\s*\(|\bsocket_create\s*\(", "opens network connections (possible reverse shell)", 2),
    (rf"\b{_EXEC}\s*\(", "can run system commands", 1),
    (rf"\b{_DECODE}\s*\(", "decodes hidden data", 1),
    (r"\bmove_uploaded_file\s*\(", "accepts file uploads", 1),
    (r"(?:chr\(\d+\)\s*\.\s*){5,}", "builds code from character numbers", 2),
    (r"(?:\\x[0-9a-fA-F]{2}){30,}", "contains a long hex-encoded string", 2),
    (r"[A-Za-z0-9+/]{800,}={0,2}", "contains a very long encoded blob", 2),
    (r"\$\w+\s*\(\s*\$\w+\s*\(", "calls functions through variables (obfuscation)", 1),
]
_PHP_COMPILED = [(re.compile(p, re.I | re.S), why, w) for p, why, w in PHP_RULES]


def scan_php_text(text, where):
    reasons, score = [], 0
    for rx, why, weight in _PHP_COMPILED:
        if rx.search(text):
            reasons.append(why)
            score += weight
    if score >= 8:
        sev, title = "critical", "PHP web shell detected"
    elif score >= 5:
        sev, title = "high", "Likely PHP web shell"
    elif score >= 3:
        sev, title = "medium", "Suspicious PHP code"
    else:
        return []
    return [Finding("web-shell", title, sev,
                    "This script " + "; ".join(reasons) + f". (score {score})",
                    "If this is on a web server, take the site offline, delete the file, change all "
                    "passwords and check other files changed around the same time.", where,
                    {"score": score})]


def scan_php_in_image(data, where):
    if b"<?php" in data or b"<?=" in data[:4096]:
        return [Finding("web-shell", "PHP code hidden in an image", "high",
                        "Attackers hide web shells inside image files to slip past upload filters.",
                        "Delete the file and check how it was uploaded.", where)]
    return []


# ------------------------------------------------------------------ links in files
def scan_links_text(text, where, bad_domains, seen=None):
    seen = set() if seen is None else seen
    out = []
    for u in url_checks.extract_urls(text):
        if u in seen:
            continue
        seen.add(u)
        out.extend(url_checks.check_url(u, bad_domains, where))
    return out


# ------------------------------------------------------------------ emails
DANGEROUS_ATTACH = {".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
                    ".wsf", ".hta", ".jar", ".msi", ".lnk", ".cpl", ".reg", ".apk", ".app", ".pif"}
CONTAINER_ATTACH = {".iso", ".img", ".vhd", ".vhdx"}
ARCHIVE_ATTACH = {".zip", ".rar", ".7z", ".gz", ".ace", ".cab"}
MACRO_ATTACH = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xls", ".doc"}
HTML_ATTACH = {".html", ".htm", ".shtml", ".svg"}
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".invoice"}
PHISH_PHRASES = ["verify your account", "confirm your identity", "account has been suspended",
                 "account will be closed", "unusual sign-in", "unusual activity", "password expires",
                 "update your payment", "gift card", "wire transfer", "urgent action required",
                 "click below to", "you have won", "invoice attached", "reset your password",
                 "mailbox is full", "re-activate", "within 24 hours", "kindly"]
ANCHOR_RE = re.compile(r"<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")


def _domain(addr):
    return addr.rsplit("@", 1)[-1].lower().strip(">") if "@" in addr else ""


def scan_email_bytes(raw, where, signatures=None, bad_domains=frozenset()):
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    subject = str(msg.get("Subject", "(no subject)"))[:120]
    label = f"{where} | \"{subject}\""
    out = []

    def add(title, sev, detail, fix="Don't click links or open attachments. Delete the email."):
        out.append(Finding("email", title, sev, detail, fix, label))

    # --- sender checks
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    from_dom = _domain(from_addr)
    if from_name:
        m = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", from_name)
        if m and m.group(1).lower() != from_dom:
            add("Sender name shows a fake address", "high",
                f"The name says '{from_name}' but the email really came from {from_addr}.")
    reply_doms = {_domain(a) for _, a in getaddresses([str(msg.get("Reply-To", ""))]) if a}
    if from_dom and reply_doms and from_dom not in reply_doms:
        add("Replies go to a different domain", "medium",
            f"Sent from {from_dom} but replies go to {', '.join(sorted(reply_doms))}.")
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []) or []).lower()
    failed = sorted(set(re.findall(r"\b(spf|dkim|dmarc)=(?:fail|softfail|permerror)", auth)))
    if failed:
        add(f"Sender verification failed ({', '.join(failed).upper()})",
            "high" if "dmarc" in failed else "medium",
            f"The email claims to be from {from_dom or 'unknown'} but failed the checks that "
            "prove it. It is probably spoofed.")

    # --- attachments
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        name = filename.lower()
        sfx = [s for s in Path(name).suffixes]
        ext = sfx[-1] if sfx else ""
        payload = part.get_payload(decode=True) or b""
        if signatures:
            digest = hashlib.sha256(payload).hexdigest()
            if digest in signatures:
                add(f"Attachment is known malware: {filename}", "critical",
                    f"Matches signature '{signatures[digest]}'.")
        if len(sfx) >= 2 and ext in DANGEROUS_ATTACH and sfx[-2] in DOC_EXTS:
            add(f"Disguised program attached: {filename}", "critical",
                "The attachment pretends to be a document but is a program.")
        elif ext in DANGEROUS_ATTACH:
            add(f"Program or script attached: {filename}", "high",
                f"'{ext}' files run code as soon as they're opened.")
        elif ext in CONTAINER_ATTACH:
            add(f"Disk image attached: {filename}", "high",
                "Disk images are used to sneak programs past email filters.")
        elif ext in MACRO_ATTACH:
            add(f"Office file that may contain macros: {filename}", "medium",
                "Macros in Office files are a top way malware gets in.",
                "Only open it if you expected it, and never click 'Enable content'.")
        elif ext in HTML_ATTACH:
            add(f"Web page attached: {filename}", "medium",
                "HTML attachments are often fake login pages that open in your browser.")
            out.extend(scan_links_text(payload.decode("utf-8", "ignore"), label, bad_domains))
        elif ext in ARCHIVE_ATTACH:
            add(f"Archive attached: {filename}", "low",
                "Zip files can hide programs. Check what's inside before opening anything.",
                "Scan the extracted files with: python -m sentinel scan <folder>")
        if ext in PHP_EXTS:
            out.extend(scan_php_text(payload.decode("utf-8", "ignore"), label))

    # --- body: links, link tricks, phishing wording, forms
    texts = []
    for part in msg.walk():
        if part.get_content_maintype() == "text" and not part.get_filename():
            try:
                texts.append((part.get_content_subtype(), part.get_content()))
            except (LookupError, ValueError):
                texts.append((part.get_content_subtype(),
                              (part.get_payload(decode=True) or b"").decode("utf-8", "ignore")))
    seen = set()
    for subtype, body in texts:
        out.extend(scan_links_text(body, label, bad_domains, seen))
        if subtype == "html":
            for href, inner in ANCHOR_RE.findall(body):
                shown = TAG_RE.sub("", inner)
                m = url_checks.DOMAIN_RE.search(shown)
                real = (url_checks.urlparse(href).hostname or "").lower()
                if m and real and "." in m.group(1):
                    shown_dom = m.group(1).lower()
                    if not (real == shown_dom or real.endswith("." + shown_dom)
                            or shown_dom.endswith("." + real)):
                        add("Link text hides its real destination", "high",
                            f"The link shows '{shown_dom}' but really goes to '{real}'.")
            if re.search(r"<form\b", body, re.I) and re.search(r"type\s*=\s*[\"']?password", body, re.I):
                add("Email contains a password form", "high",
                    "Real companies never ask you to type your password inside an email.")
    full_text = (subject + " " + " ".join(b for _, b in texts)).lower()
    hits = [p for p in PHISH_PHRASES if p in full_text]
    if len(hits) >= 2:
        add("Phishing-style wording", "medium",
            "Uses pressure phrases common in scams: " + ", ".join(f"'{h}'" for h in hits[:4]) + ".")
    return out


def scan_mbox(path, signatures=None, bad_domains=frozenset()):
    out = []
    for i, msg in enumerate(mailbox.mbox(str(path))):
        out.extend(scan_email_bytes(msg.as_bytes(), f"{path} #{i + 1}", signatures, bad_domains))
    return out


# ------------------------------------------------------------------ entry point
def scan_file(path: Path, signatures=None, bad_domains=frozenset()):
    """Pick the right content checks by file type. Returns findings."""
    ext = path.suffix.lower()
    wanted = ext in PHP_EXTS | IMAGE_EXTS | EMAIL_EXTS | MBOX_EXTS | LINK_EXTS
    if not wanted or path.stat().st_size > MAX_CONTENT_BYTES:
        return []
    if ext in MBOX_EXTS:
        return scan_mbox(path, signatures, bad_domains)
    data = path.read_bytes()
    where = str(path)
    if ext in EMAIL_EXTS:
        return scan_email_bytes(data, where, signatures, bad_domains)
    out = []
    if ext in PHP_EXTS:
        out += scan_php_text(data.decode("utf-8", "ignore"), where)
    if ext in IMAGE_EXTS:
        out += scan_php_in_image(data, where)
    if ext in LINK_EXTS:
        out += scan_links_text(data.decode("utf-8", "ignore"), where, bad_domains)
    return out
