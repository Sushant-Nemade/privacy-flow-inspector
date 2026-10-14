from __future__ import annotations

from datetime import UTC, date, datetime

import pytest
from conftest import DEMO_CONFIG, DEMO_HAR, entry

from privacy_flow_inspector.engine import inspect, severity_for
from privacy_flow_inspector.model import Category, Decision, Severity
from privacy_flow_inspector.policy import Allowance, Config, Waiver, load_config

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)

EXPECTED = {
    ("PFI-PERSONA", "legacy-ads.test", "query", "critical", "open"),
    ("PFI-PRECISE-LOCATION", "geo-widgets.test", "query", "high", "open"),
    ("PFI-PERSONA", "pixel-tracker.test", "query", "high", "open"),
    ("PFI-DE-KVNR", "session-cam.test", "body", "high", "open"),
    ("PFI-HEALTH-FIELD", "session-cam.test", "body", "high", "open"),
    ("PFI-PERSONA", "analytics-vendor.test", "body", "medium", "open"),
    ("PFI-IBAN", "payments-processor.test", "body", "high", "allowed"),
    ("PFI-PERSONA", "payments-processor.test", "body", "medium", "allowed"),
    ("PFI-DE-KVNR", "shop.example", "body", "low", "open"),
    ("PFI-HEALTH-FIELD", "shop.example", "body", "low", "open"),
    ("PFI-PERSONA", "shop.example", "body", "info", "open"),
    ("PFI-PERSONA", "shop.example", "header", "info", "open"),
}


def _status(finding) -> str:  # type: ignore[no-untyped-def]
    return "allowed" if finding.allowed_reason else "waived" if finding.waiver_reason else "open"


def test_demo_har_recorded_by_chromium() -> None:
    report = inspect([DEMO_HAR], load_config(DEMO_CONFIG), now=NOW).report
    found = {(f.rule_id, f.recipient, f.channel, f.severity.label, _status(f)) for f in report.findings}
    assert found == EXPECTED
    assert report.decision is Decision.REJECT
    assert report.requests == 10
    assert [g.code for g in report.gaps] == []
    pixel = next(f for f in report.findings if f.recipient == "pixel-tracker.test" and "email" in f.title)
    assert pixel.evidence[0].variant == "sha256(plain)"
    assert "pseudonymised" in pixel.message
    legacy = next(f for f in report.findings if f.recipient == "legacy-ads.test")
    assert "plain HTTP" in legacy.message
    assert legacy.evidence[0].url == "http://ads.legacy-ads.test/i.gif?ref=..."


@pytest.mark.parametrize(
    ("category", "first", "channel", "scheme", "expected"),
    [
        (Category.CONTACT, True, "body", "https", Severity.INFO),
        (Category.CONTACT, False, "body", "https", Severity.MEDIUM),
        (Category.CONTACT, False, "query", "https", Severity.HIGH),
        (Category.CONTACT, False, "query", "http", Severity.CRITICAL),
        (Category.HEALTH, False, "body", "https", Severity.HIGH),
        (Category.HEALTH, False, "url-path", "http", Severity.CRITICAL),
        (Category.HEALTH, True, "body", "https", Severity.LOW),
        (Category.ONLINE_ID, True, "body", "https", Severity.INFO),
        (Category.ONLINE_ID, False, "referer", "https", Severity.MEDIUM),
    ],
)
def test_severity_matrix(category: Category, first: bool, channel: str, scheme: str, expected: Severity) -> None:
    assert severity_for(category, first, channel, scheme) is expected


def test_first_party_inference_and_missing_persona_are_notes(har_factory) -> None:  # type: ignore[no-untyped-def]
    har = har_factory(
        [entry("https://www.shop.example/", _resourceType="document"), entry("https://cdn.shop.example/x?email=a@b.de")]
    )
    report = inspect([har], Config(), now=NOW).report
    assert report.first_party == ["shop.example"]
    assert {g.code for g in report.gaps} == {"first-party-inferred", "no-persona"}
    assert all(not g.blocking for g in report.gaps)
    (finding,) = report.findings
    assert finding.first_party and finding.severity is Severity.LOW
    assert report.decision is Decision.REVIEW


def test_waivers_and_fingerprints(har_factory) -> None:  # type: ignore[no-untyped-def]
    har = har_factory([entry("https://t.example/c?email=a@b.de"), entry("https://t.example/d?email=a@b.de")])
    config = Config(
        first_party=("shop.example",),
        waivers=(Waiver("PFI-EMAIL", "Vendor contract reviewed by DPO.", date(2026, 12, 31), "t.example"),),
    )
    first = inspect([har], config, now=NOW, fingerprint_key=b"k").report
    second = inspect([har], config, now=NOW, fingerprint_key=b"k").report
    (finding,) = first.findings
    assert finding.waiver_reason and finding.occurrences == 2
    assert first.decision is Decision.APPROVE
    assert finding.evidence[0].fingerprint == second.findings[0].evidence[0].fingerprint
    assert finding.evidence[0].fingerprint == finding.evidence[1].fingerprint
    other = inspect([har], config, now=NOW, fingerprint_key=b"other").report
    assert other.findings[0].evidence[0].fingerprint != finding.evidence[0].fingerprint


def _font_session(har_factory):  # type: ignore[no-untyped-def]
    page = "https://www.site.example/"
    return har_factory(
        [
            entry(page, _resourceType="document"),
            entry("https://fonts.googleapis.com/css2?family=Archivo", headers=[("Referer", page)]),
            entry("https://fonts.gstatic.com/s/a.woff2", headers=[("Referer", "https://fonts.googleapis.com/")]),
            entry("https://fonts.gstatic.com/s/b.woff2"),
        ]
    )


def test_connection_rule_is_opt_in(har_factory) -> None:  # type: ignore[no-untyped-def]
    report = inspect([_font_session(har_factory)], Config(first_party=("site.example",)), now=NOW).report
    assert report.findings == []
    assert report.decision is Decision.APPROVE
    assert {(f.recipient, f.requests) for f in report.flows if not f.first_party} == {
        ("fonts.googleapis.com", 1),
        ("gstatic.com", 2),
    }


def test_connection_rule_reports_each_third_party_once(har_factory) -> None:  # type: ignore[no-untyped-def]
    config = Config(first_party=("site.example",), enabled=frozenset({"PFI-THIRD-PARTY-CONNECTION"}))
    report = inspect([_font_session(har_factory)], config, now=NOW).report
    found = {(f.recipient, f.severity, f.occurrences, f.channel) for f in report.findings}
    assert found == {
        ("fonts.googleapis.com", Severity.LOW, 1, "connection"),
        ("gstatic.com", Severity.LOW, 2, "connection"),
    }
    assert report.decision is Decision.REVIEW
    google = next(f for f in report.findings if f.recipient == "fonts.googleapis.com")
    assert "which first-party page" in google.message
    assert google.evidence[0].url == "https://fonts.googleapis.com/css2?family=..."
    gstatic = next(f for f in report.findings if f.recipient == "gstatic.com")
    assert "which first-party page" not in gstatic.message


def test_connection_rule_respects_allowances(har_factory) -> None:  # type: ignore[no-untyped-def]
    config = Config(
        first_party=("site.example",),
        enabled=frozenset({"PFI-THIRD-PARTY-CONNECTION"}),
        allow=tuple(
            Allowance(site, frozenset({Category.ONLINE_ID}), "Font CDN covered by a DPA.")
            for site in ("fonts.googleapis.com", "gstatic.com")
        ),
    )
    report = inspect([_font_session(har_factory)], config, now=NOW).report
    assert all(f.allowed_reason for f in report.findings)
    assert report.decision is Decision.APPROVE
