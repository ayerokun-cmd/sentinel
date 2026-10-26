"""Checks a URL for signs of phishing or malware delivery."""
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse, unquote

from .findings import Finding

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_BAD_DOMAINS = DATA_DIR / "bad_domains.txt"
USER_BAD_DOMAINS = Path.home() / ".sentinel" / "bad_domains.txt"   # updates go here

URL_RE = re.compile(r"""\bhttps?://[^\s<>"'`)\]}]+""", re.I)
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
              "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id", "t.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "work",
                   "rest", "country", "kim", "loan", "cam", "quest", "sbs", "cfd", "icu", "buzz"}
# Brands phishers copy most. Flagged when the name appears in a domain that isn't theirs.
BRANDS = ["paypal", "apple", "icloud", "microsoft", "office365", "outlook", "google", "amazon",
          "netflix", "facebook", "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica",
          "dhl", "fedex", "usps", "coinbase", "binance", "docusign", "dropbox", "linkedin"]
DANGEROUS_DOWNLOADS = {".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
                       ".jar", ".apk", ".dmg", ".pkg", ".iso", ".img", ".lnk"}
SECOND_LEVEL = {"co", "com", "org", "net", "ac", "gov", "edu", "ne", "or"}
# Real domains owned by the brands above whose names don't match the brand exactly.
OFFICIAL_DOMAINS = {
    "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "sharepoint.com",
    "windows.net", "azure.com", "msn.com", "googleusercontent.com", "googleapis.com", "gstatic.com",
    "gmail.com", "youtube.com", "amazonaws.com", "cloudfront.net", "fbcdn.net", "whatsapp.net",
    "paypalobjects.com", "icloud-content.com", "apple-cloudkit.com", "mzstatic.com", "licdn.com",
    "dropboxusercontent.com", "chasecdn.com",
}


def load_bad_domains(paths=None):
    """One domain per line. Also accepts hosts-file lines like '127.0.0.1 bad.example'."""
    bad = set()
    for p in paths or [DEFAULT_BAD_DOMAINS, USER_BAD_DOMAINS]:
        p = Path(p)
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                bad.add(line.split()[-1].strip("."))
    return bad


def extract_urls(text):
    urls = []
    for u in URL_RE.findall(text):
        u = u.rstrip(".,;:!?")
        if u not in urls:
            urls.append(u)
    return urls


def registered_label(host):
    """'login.paypal.co.uk' -> 'paypal'. Simple guess, good enough for brand checks."""
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else host


def _in_blocklist(host, bad_domains):
    parts = host.split(".")
    return any(".".join(parts[i:]) in bad_domains for i in range(len(parts) - 1))


def check_url(url, bad_domains=frozenset(), source=""):
    """Return findings for one URL (empty list = nothing suspicious)."""
    out = []
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return out
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return out
    where = source or url

    def add(title, severity, detail, fix="Don't open the link or enter any details on that page."):
        out.append(Finding("url", title, severity, f"{detail} URL: {url}", fix, where))

    if _in_blocklist(host, bad_domains):
        add("Link goes to a known malicious site", "critical",
            f"'{host}' is on the blocklist of malware/phishing domains.")
    try:
        ipaddress.ip_address(host)
        add("Link uses a raw IP address", "high",
            "Real companies use names, not numbers. This is common in malware downloads.")
    except ValueError:
        pass
    if "xn--" in host:
        add("Look-alike domain (punycode)", "high",
            f"'{host}' uses special characters to imitate another site's name.")
    if "@" in (parsed.netloc or ""):
        add("Link hides its real destination with '@'", "high",
            f"Everything before '@' is ignored; the link really goes to '{host}'.")
    label = registered_label(host)
    official = any(host == d or host.endswith("." + d) for d in OFFICIAL_DOMAINS)
    for brand in BRANDS:
        if brand in host and brand != label and not official:
            add(f"Possible fake {brand.title()} site", "high",
                f"'{host}' contains '{brand}' but isn't owned by {brand.title()}.")
            break
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        add(f"Domain ends in .{tld}", "medium",
            f".{tld} domains are cheap and heavily used for scams.")
    if host in SHORTENERS:
        add("Shortened link", "low", "The real destination is hidden behind a link shortener.",
            "Expand it first with a service like unshorten.it before opening.")
    path = unquote(parsed.path or "").lower()
    if any(path.endswith(ext) for ext in DANGEROUS_DOWNLOADS):
        add("Link downloads a program", "medium",
            f"The link points straight to a '{Path(path).suffix}' file.",
            "Only download programs from the developer's official site.")
    if parsed.scheme == "http" and re.search(r"log[-_]?in|sign[-_]?in|password|account|verify|bank",
                                             path + (parsed.query or "").lower()):
        add("Login page without encryption", "medium",
            "The page asks for account details over plain http, so they can be intercepted.")
    if host.count(".") >= 4:
        add("Unusually many subdomains", "low",
            "Long chains like 'secure.login.example.com.bad.site' are used to confuse.")
    if parsed.port and parsed.port not in (80, 443):
        add(f"Link uses unusual port {parsed.port}", "low", "Normal websites don't need a special port.")
    return out
