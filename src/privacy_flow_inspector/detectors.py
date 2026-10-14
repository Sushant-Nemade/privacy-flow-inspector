"""Detectors for personal data. Each match is backed by an exact persona value, a checksum or a field name."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import quote

from privacy_flow_inspector.extract import Carrier
from privacy_flow_inspector.model import Category


@dataclass(frozen=True)
class Persona:
    label: str
    value: str
    category: Category


@dataclass(frozen=True)
class Detector:
    id: str
    title: str
    category: Category | None
    confidence: str
    description: str


DETECTORS: dict[str, Detector] = {
    d.id: d
    for d in (
        Detector(
            "PFI-PERSONA",
            "Test persona value",
            None,
            "exact",
            "A configured test-persona value, or a lowercase, URL-encoded, Base64 or MD5/SHA-1/SHA-256 "
            "form of it. Hashed identifiers are still personal data (pseudonymised, GDPR Recital 26).",
        ),
        Detector("PFI-EMAIL", "Email address", Category.CONTACT, "pattern", "An email address."),
        Detector(
            "PFI-PHONE",
            "Phone number",
            Category.CONTACT,
            "field-name",
            "A phone-like number in a phone field, or a whole value in E.164 format.",
        ),
        Detector(
            "PFI-IBAN",
            "IBAN",
            Category.FINANCIAL,
            "checksum",
            "A bank account number (IBAN, mod-97 verified).",
        ),
        Detector(
            "PFI-CARD",
            "Payment card number",
            Category.FINANCIAL,
            "checksum",
            "A card number with a known issuer prefix and a valid Luhn checksum.",
        ),
        Detector(
            "PFI-DE-TAX-ID",
            "German tax ID (Steuer-ID)",
            Category.GOVERNMENT_ID,
            "checksum",
            "An 11-digit Steuer-ID in a tax-ID field, verified with ISO 7064 MOD 11,10 and the digit rules.",
        ),
        Detector(
            "PFI-DE-KVNR",
            "German health insurance number (KVNR)",
            Category.HEALTH,
            "checksum",
            "A Krankenversichertennummer with a valid check digit; it links a person to their health insurance.",
        ),
        Detector(
            "PFI-HEALTH-FIELD",
            "Health data field",
            Category.HEALTH,
            "field-name",
            "A non-empty value in a field whose name indicates health data (diagnosis, ICD code, medication, ...). "
            "Health data is a special category under GDPR Article 9.",
        ),
        Detector(
            "PFI-IDENTITY-FIELD",
            "Identity field",
            Category.IDENTITY,
            "field-name",
            "A non-empty value in a name, birth-date or postal-address field.",
        ),
        Detector(
            "PFI-PRECISE-LOCATION",
            "Precise location",
            Category.LOCATION,
            "field-name",
            "Latitude or longitude with at least four decimal places (about 11 m) in a location field.",
        ),
        Detector(
            "PFI-IP-ADDRESS",
            "Public IP address in payload",
            Category.ONLINE_ID,
            "pattern",
            "A public IPv4 or IPv6 address sent as data, which is an online identifier under GDPR.",
        ),
    )
}


@dataclass(frozen=True)
class Match:
    detector: str
    category: Category
    value: str
    variant: str
    label: str


def _hashes(text: str) -> dict[str, str]:
    data = text.encode("utf-8")
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def persona_variants(value: str) -> list[tuple[str, str, bool]]:
    """(variant name, needle, case-insensitive) for every form a tracker might send."""
    plain = value.strip()
    forms = {"plain": plain, "lowercase": plain.lower()}
    digits = re.sub(r"\D", "", plain)
    if len(digits) >= 7 and len(digits) >= len(re.sub(r"[\s()+./-]", "", plain)):
        forms["digits"] = digits
        forms["e164"] = "+" + digits
    variants: dict[str, tuple[str, bool]] = {}
    for name, form in forms.items():
        variants.setdefault(form.lower(), (name, True))
        encoded = quote(form, safe="")
        if encoded != form:
            variants.setdefault(encoded.lower(), (f"url-encoded({name})", True))
        for b64name, b64 in (
            ("base64", base64.b64encode(form.encode()).decode().rstrip("=")),
            ("base64url", base64.urlsafe_b64encode(form.encode()).decode().rstrip("=")),
        ):
            variants.setdefault(b64, (f"{b64name}({name})", False))
        if name != "plain" or form == form.lower():
            for hash_name, digest in _hashes(form).items():
                variants.setdefault(digest, (f"{hash_name}({name})", True))
    return [(name, needle, insensitive) for needle, (name, insensitive) in variants.items()]


class PersonaMatcher:
    def __init__(self, personas: list[Persona]) -> None:
        self.personas = personas
        self._needles = [(p, name, needle, ci) for p in personas for name, needle, ci in persona_variants(p.value)]

    def all_needles(self) -> list[str]:
        return [needle for _, _, needle, _ in self._needles]

    def match(self, value: str) -> list[Match]:
        lowered = value.lower()
        found: dict[str, Match] = {}
        for persona, name, needle, insensitive in self._needles:
            hit = needle in lowered if insensitive else needle in value
            if hit and persona.label not in found:
                found[persona.label] = Match("PFI-PERSONA", persona.category, persona.value, name, persona.label)
        return list(found.values())


_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}(?![\w-])"
)
_FILE_TLDS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "js",
    "css",
    "map",
    "ico",
    "woff",
    "woff2",
}
_E164 = re.compile(r"^\+[1-9]\d{7,14}$")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_IBAN_LENGTHS = {
    "AT": 20,
    "BE": 16,
    "CH": 21,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "ES": 24,
    "FI": 18,
    "FR": 27,
    "GB": 22,
    "IE": 22,
    "IT": 27,
    "LU": 20,
    "NL": 18,
    "NO": 15,
    "PL": 28,
    "PT": 25,
    "SE": 24,
}
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_KVNR = re.compile(r"\b[A-Z]\d{9}\b")
_TAX_ID = re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{2,39}(?![\w:])")
_DECIMAL = re.compile(r"^-?\d{1,3}\.(\d{4,})$")
_ICD10 = re.compile(r"^[A-TV-Z]\d[0-9AB](?:\.[0-9A-TV-Z]{1,4})?$")

_PHONE_KEYS = re.compile(r"(phone|mobile|msisdn|telefon|(^|[_.-])tel($|[_.-]))", re.IGNORECASE)
_IP_KEYS = re.compile(r"(^|[_.-])(ip|ip_?addr|ip_?address|client_?ip|remote_?addr|uip)($|[_.-])", re.IGNORECASE)
_TAX_KEYS = re.compile(r"(steuer|tax_?id|taxid|tin$|idnr|identifikationsnummer)", re.IGNORECASE)
_LOCATION_KEYS = re.compile(r"^(lat|latitude|lng|lon|long|longitude|geo_?lat|geo_?lng)$", re.IGNORECASE)
_HEALTH_KEYS = re.compile(
    r"(diagnos|icd|medication|medicat|prescription|symptom|allerg|disease|condition|therapy|"
    r"treatment|blood_?type|pregnan|disabilit|patient_?note|krankheit|befund)",
    re.IGNORECASE,
)
_IDENTITY_KEYS = re.compile(
    r"^(first_?name|last_?name|given_?name|family_?name|surname|full_?name|dob|date_?of_?birth|"
    r"birth_?date|birthday|street|street_?address|address_?line\d?|postcode|postal_?code|zip|zip_?code)$",
    re.IGNORECASE,
)


def _leaf(key: str) -> str:
    name = re.split(r"[.>\]\[<]", key.rstrip(">]"))
    parts = [part for part in name if part and not part.isdigit() and part not in ("json", "base64", "jwt")]
    return parts[-1] if parts else key


def iban_valid(candidate: str) -> bool:
    country = candidate[:2]
    expected = _IBAN_LENGTHS.get(country)
    if expected is not None and len(candidate) != expected:
        return False
    if not 15 <= len(candidate) <= 34:
        return False
    rearranged = candidate[4:] + candidate[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def luhn_valid(digits: str) -> bool:
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _card_prefix_ok(digits: str) -> bool:
    length = len(digits)
    if digits[0] == "4":
        return length in (13, 16, 19)
    if 51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720:
        return length == 16
    if digits[:2] in ("34", "37"):
        return length == 15
    if digits.startswith(("6011", "65")):
        return length in (16, 19)
    return False


def kvnr_valid(candidate: str) -> bool:
    if not _KVNR.fullmatch(candidate):
        return False
    digits = f"{ord(candidate[0]) - 64:02d}" + candidate[1:9]
    total = 0
    for position, char in enumerate(digits):
        product = int(char) * (1 if position % 2 == 0 else 2)
        total += product - 9 if product > 9 else product
    return total % 10 == int(candidate[9])


def tax_id_valid(candidate: str) -> bool:
    if len(candidate) != 11 or not candidate.isdigit() or candidate[0] == "0":
        return False
    head = candidate[:10]
    counts = sorted((head.count(d) for d in set(head)), reverse=True)
    if counts[0] not in (2, 3) or any(c > 1 for c in counts[1:]):
        return False
    if counts[0] == 3 and any(head[i] == head[i + 1] == head[i + 2] for i in range(8)):
        return False
    product = 10
    for char in head:
        total = (int(char) + product) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    check = 11 - product
    return (0 if check == 10 else check) == int(candidate[10])


def detect(carrier: Carrier, disabled: frozenset[str]) -> list[Match]:
    value = carrier.value
    if not value or len(value) > 100_000:
        return []
    leaf = _leaf(carrier.key)
    matches: list[Match] = []

    def add(detector: str, raw: str, variant: str = "plain") -> None:
        if detector in disabled:
            return
        category = DETECTORS[detector].category
        if category is None:
            return
        matches.append(Match(detector, category, raw, variant, DETECTORS[detector].title))

    for found in _EMAIL.finditer(value):
        if found.group(0).rsplit(".", 1)[-1].lower() not in _FILE_TLDS:
            add("PFI-EMAIL", found.group(0))
    stripped = value.strip()
    if _E164.match(re.sub(r"[\s()-]", "", stripped)) or _PHONE_KEYS.search(leaf):
        digits = re.sub(r"\D", "", stripped)
        if 7 <= len(digits) <= 15 and len(stripped) <= 25:
            add("PFI-PHONE", stripped)
    compact = re.sub(r"\s", "", value) if len(value) <= 64 else value
    for found in _IBAN.finditer(compact):
        if iban_valid(found.group(0)):
            add("PFI-IBAN", found.group(0))
    for found in _CARD.finditer(value):
        digits = re.sub(r"\D", "", found.group(0))
        if len(set(digits)) > 1 and _card_prefix_ok(digits) and luhn_valid(digits):
            add("PFI-CARD", found.group(0))
    for found in _KVNR.finditer(value):
        if kvnr_valid(found.group(0)):
            add("PFI-DE-KVNR", found.group(0))
    if _TAX_KEYS.search(leaf):
        for found in _TAX_ID.finditer(value):
            if tax_id_valid(found.group(0)):
                add("PFI-DE-TAX-ID", found.group(0))
    if _LOCATION_KEYS.match(leaf) and _DECIMAL.match(stripped):
        add("PFI-PRECISE-LOCATION", stripped)
    if _HEALTH_KEYS.search(leaf) and stripped and stripped.lower() not in ("true", "false", "null", "0", "1"):
        variant = "icd-10 code" if _ICD10.match(stripped.upper()) else "field value"
        add("PFI-HEALTH-FIELD", stripped, variant)
    if _IDENTITY_KEYS.match(leaf) and any(ch.isalnum() for ch in stripped) and len(stripped) <= 200:
        add("PFI-IDENTITY-FIELD", stripped)
    if carrier.channel != "header" or carrier.key.lower().startswith(("x-forwarded", "x-real-ip", "x-client")):
        ip_field = bool(_IP_KEYS.search(leaf))
        for pattern in (_IPV4, _IPV6):
            for found in pattern.finditer(value):
                # Dotted quads are often version numbers, so IPv4 needs an IP field; IPv6 may be a whole value.
                if not ip_field and (pattern is _IPV4 or found.group(0) != stripped):
                    continue
                try:
                    address = ipaddress.ip_address(found.group(0))
                except ValueError:
                    continue
                if address.is_global:
                    add("PFI-IP-ADDRESS", found.group(0))
    return matches
