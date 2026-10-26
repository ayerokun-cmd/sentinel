"""Shared result type used by every scanner."""
from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}


@dataclass
class Finding:
    category: str          # "malware", "security-setting", "device", ...
    title: str
    severity: str          # critical | high | medium | low | info | ok
    detail: str = ""
    fix: str = ""
    path: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
