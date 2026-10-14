from __future__ import annotations

import base64
import hashlib
import random
from urllib.parse import quote

import pytest
from stdnum import iban as std_iban
from stdnum import luhn as std_luhn
from stdnum.de import idnr as std_idnr

from privacy_flow_inspector.detectors import (
    Persona,
    PersonaMatcher,
    detect,
    iban_valid,
    kvnr_valid,
    luhn_valid,
    persona_variants,
    tax_id_valid,
)
from privacy_flow_inspector.extract import Carrier
from privacy_flow_inspector.model import Category


def _carrier(value: str, key: str = "value", channel: str = "body") -> Carrier:
    return Carrier(channel, key, value, value)


def _ids(value: str, key: str = "value", channel: str = "body") -> list[str]:
    return [m.detector for m in detect(_carrier(value, key, channel), frozenset())]


def test_tax_id_matches_stdnum_except_the_official_three_in_a_row_rule() -> None:
    rng = random.Random(7)
    checked = 0
    for _ in range(100_000):
        candidate = str(rng.randint(10**10, 10**11 - 1))
        head = candidate[:10]
        three_in_a_row = any(head[i] == head[i + 1] == head[i + 2] for i in range(8))
        if three_in_a_row:
            # stdnum does not apply this BZSt rule; ours must reject such numbers.
            assert not tax_id_valid(candidate)
            continue
        assert tax_id_valid(candidate) == std_idnr.is_valid(candidate), candidate
        checked += 1
    assert checked > 90_000


def test_iban_and_luhn_match_stdnum() -> None:
    rng = random.Random(11)
    for _ in range(20_000):
        number = str(rng.randint(10**15, 10**16 - 1))
        assert luhn_valid(number) == std_luhn.is_valid(number)
    for candidate in [
        "DE89370400440532013000",
        "GB82WEST12345698765432",
        "FR1420041010050500013M02606",
        "DE89370400440532013001",
        "NL91ABNA0417164300",
        "NL91ABNA0417164301",
    ]:
        assert iban_valid(candidate) == std_iban.is_valid(candidate), candidate


def test_kvnr_uses_the_documented_example() -> None:
    # Example from the KVNR check-digit rule (gkv-datenaustausch.de, quoted on Wikipedia).
    assert kvnr_valid("A123456780")
    assert not kvnr_valid("A123456781")
    assert not kvnr_valid("a123456780")


def test_persona_variants_cover_tracker_encodings() -> None:
    needles = {needle for _, needle, _ in persona_variants("Jane.Test@Example.com")}
    lower = "jane.test@example.com"
    assert hashlib.sha256(lower.encode()).hexdigest() in needles
    assert hashlib.md5(lower.encode()).hexdigest() in needles
    assert hashlib.sha1(lower.encode()).hexdigest() in needles
    assert quote(lower, safe="").lower() in needles
    assert base64.b64encode(lower.encode()).decode().rstrip("=") in needles
    assert base64.urlsafe_b64encode(b"Jane.Test@Example.com").decode().rstrip("=") in needles
    phone = {name: needle for name, needle, _ in persona_variants("+49 151 23456789")}
    assert phone["digits"] == "4915123456789"
    assert phone["sha256(digits)"] == hashlib.sha256(b"4915123456789").hexdigest()


def test_persona_matcher_finds_hashes_case_insensitively() -> None:
    matcher = PersonaMatcher([Persona("email", "jane.test@example.com", Category.CONTACT)])
    digest = hashlib.sha256(b"jane.test@example.com").hexdigest().upper()
    (match,) = matcher.match(f"em={digest}")
    assert match.variant == "sha256(plain)"
    assert matcher.match("nothing here") == []


@pytest.mark.parametrize(
    ("value", "key", "expected"),
    [
        ("contact: jane@example.org", "msg", ["PFI-EMAIL"]),
        ("+491512345678", "x", ["PFI-PHONE"]),
        ("0151 2345678", "phone_number", ["PFI-PHONE"]),
        ("DE89 3704 0044 0532 0130 00", "account", ["PFI-IBAN"]),
        ("4111 1111 1111 1111", "pan", ["PFI-CARD"]),
        ("A123456780", "member", ["PFI-DE-KVNR"]),
        ("58914170363", "steuer_id", ["PFI-DE-TAX-ID"]),
        ("52.520008", "lat", ["PFI-PRECISE-LOCATION"]),
        ("J45.9", "diagnosis", ["PFI-HEALTH-FIELD"]),
        ("Asthma", "condition", ["PFI-HEALTH-FIELD"]),
        ("1990-04-01", "date_of_birth", ["PFI-IDENTITY-FIELD"]),
        ("8.8.8.8", "client_ip", ["PFI-IP-ADDRESS"]),
        ("2001:4860:4860::8888", "x", ["PFI-IP-ADDRESS"]),
        ("ip=2001:4860:4860::8888", "x", []),
    ],
)
def test_detectors(value: str, key: str, expected: list[str]) -> None:
    assert _ids(value, key) == expected


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("1728900000123", "ts"),
        ("58914170363", "order_id"),
        ("1.2.3.4", "app_version"),
        ("8.8.8.8", "x"),
        ("10:30:00", "time"),
        ("10.0.0.5", "client_ip"),
        ("icon@2x.png", "src"),
        ("4111 1111 1111 1112", "pan"),
        ("DE89370400440532013001", "iban"),
        ("A123456781", "member"),
        ("52.52", "lat"),
        ("true", "diagnosis"),
        ("550e8400-e29b-41d4-a716-446655440000", "uuid"),
        ("d41d8cd98f00b204e9800998ecf8427e", "etag"),
        ("1234567890123456", "session"),
    ],
)
def test_common_tracking_values_are_not_flagged(value: str, key: str) -> None:
    assert _ids(value, key) == []


def test_disabled_detectors_are_skipped() -> None:
    carrier = _carrier("jane@example.org")
    assert detect(carrier, frozenset({"PFI-EMAIL"})) == []
