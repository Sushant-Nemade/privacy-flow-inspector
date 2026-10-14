from __future__ import annotations

import enum
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


class InspectorError(Exception):
    """A user-facing error that maps to exit status 2."""


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        normalized = value.strip().upper()
        if normalized == "MODERATE":
            normalized = "MEDIUM"
        try:
            return cls[normalized]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None

    @property
    def label(self) -> str:
        return self.name.lower()


class Decision(enum.Enum):
    APPROVE = "approve"
    REVIEW = "review"
    REJECT = "reject"


class Category(enum.Enum):
    CONTACT = "contact"
    IDENTITY = "identity"
    GOVERNMENT_ID = "government-id"
    FINANCIAL = "financial"
    HEALTH = "health"
    LOCATION = "location"
    ONLINE_ID = "online-identifier"

    @classmethod
    def parse(cls, value: str) -> Category:
        try:
            return cls(value.strip().lower())
        except ValueError:
            names = ", ".join(c.value for c in cls)
            raise ValueError(f"unknown category {value!r} (expected one of: {names})") from None


# Starting severity before recipient and transport adjustments.
BASE_SEVERITY = {
    Category.HEALTH: 3,
    Category.FINANCIAL: 3,
    Category.GOVERNMENT_ID: 3,
    Category.CONTACT: 2,
    Category.IDENTITY: 2,
    Category.LOCATION: 2,
    Category.ONLINE_ID: 1,
}
SPECIAL_CATEGORIES = {Category.HEALTH}


def clean_text(value: str, limit: int = 300) -> str:
    """Remove control and bidi characters from untrusted text and bound its length."""
    text = _CONTROL.sub("", value).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def mask(value: str) -> str:
    """Short, non-reversible preview of a sensitive value."""
    text = value.strip()
    if len(text) <= 6:
        return "*" * max(len(text), 3)
    return f"{text[:2]}{'*' * min(len(text) - 4, 8)}{text[-2:]}"


class Fingerprinter:
    """Keyed hash so the same value can be correlated within a report without revealing it."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def __call__(self, value: str) -> str:
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


@dataclass(frozen=True)
class Evidence:
    har: str
    entry: int
    method: str
    url: str
    channel: str
    key: str
    variant: str
    preview: str
    fingerprint: str
    har_line: int | None = None
    har_column: int | None = None
    initiator: str | None = None


@dataclass
class Finding:
    rule_id: str
    title: str
    category: Category
    confidence: str
    severity: Severity
    recipient: str
    recipient_label: str | None
    first_party: bool
    channel: str
    message: str
    evidence: list[Evidence] = field(default_factory=list)
    occurrences: int = 0
    allowed_reason: str | None = None
    waiver_reason: str | None = None

    @property
    def counted(self) -> bool:
        return self.allowed_reason is None and self.waiver_reason is None


@dataclass(frozen=True)
class Gap:
    code: str
    message: str
    path: str | None = None
    blocking: bool = True


@dataclass
class Flow:
    recipient: str
    label: str | None
    first_party: bool
    requests: int = 0
    categories: dict[Category, Severity] = field(default_factory=dict)


@dataclass
class Report:
    tool_version: str
    inputs: list[str]
    scanned_at: datetime
    requests: int
    findings: list[Finding]
    flows: list[Flow]
    gaps: list[Gap]
    first_party: list[str]
    personas: int
    decision: Decision
    decision_reasons: list[str]
