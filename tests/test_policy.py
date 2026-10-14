from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from conftest import DEMO_CONFIG

from privacy_flow_inspector.model import Category, Decision, Finding, Gap, Severity
from privacy_flow_inspector.policy import Allowance, Config, ConfigError, Waiver, apply_policy, decide, load_config


def _config(tmp_path: Path, text: str) -> Config:
    path = tmp_path / "c.toml"
    path.write_text(text, encoding="utf-8")
    return load_config(path)


def _finding(
    rule: str = "PFI-EMAIL",
    recipient: str = "t.example",
    severity: Severity = Severity.MEDIUM,
    category: Category = Category.CONTACT,
) -> Finding:
    return Finding(rule, "t", category, "pattern", severity, recipient, None, False, "body", "m")


def test_example_config_loads() -> None:
    config = load_config(DEMO_CONFIG)
    assert config.first_party == ("shop.example",)
    assert [p.label for p in config.personas] == ["Test user email", "Test user phone", "Test user name"]
    assert config.allow[0].recipient == "payments-processor.test"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("unknown = 1", "unknown top-level"),
        ("version = 2", "version"),
        ("[gate]\nreject_at = 'low'\nreview_at = 'high'", "must not be higher"),
        ("[[persona]]\nlabel = 'x'\nvalue = 'abc'", "at least 5"),
        ("[[persona]]\nlabel = 'x'\nvalue = 'abcdef'\ncategory = 'shoe-size'", "unknown category"),
        ("[[allow]]\nrecipient = 'a.example'\ncategories = []\nreason = 'long enough reason'", "non-empty"),
        ("[[allow]]\nrecipient = 'a.example'\ncategories = ['contact']\nreason = 'short'", "at least 10"),
        ("[[waivers]]\nid = 'PFI-NOPE'\nreason = 'long enough reason'\nexpires = 2026-12-31", "unknown rule"),
        ("[[waivers]]\nid = 'PFI-EMAIL'\nreason = 'long enough reason'\nexpires = '2026-12-31'", "TOML date"),
        ("[detectors]\ndisabled = ['PFI-NOPE']", "unknown rule"),
        ("[first_party]\ndomains = [1]", "list of domain"),
        ("= broken", "invalid config TOML"),
    ],
)
def test_invalid_configs(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        _config(tmp_path, text)


def test_allowlist_matches_recipient_site_and_category() -> None:
    config = Config(allow=(Allowance("t.example", frozenset({Category.CONTACT}), "Processor with DPA."),))
    allowed, other_category = _finding(), _finding(category=Category.HEALTH, rule="PFI-HEALTH-FIELD")
    gaps = apply_policy([allowed, other_category], config, date(2026, 10, 14))
    assert allowed.allowed_reason and not other_category.allowed_reason
    assert gaps == []


def test_waiver_expiry_and_unused() -> None:
    config = Config(
        waivers=(
            Waiver("PFI-EMAIL", "Old acceptance of risk.", date(2026, 1, 1)),
            Waiver("PFI-PHONE", "Nothing matches this one.", date(2027, 1, 1)),
        )
    )
    finding = _finding()
    gaps = apply_policy([finding], config, date(2026, 10, 14))
    assert not finding.waiver_reason
    assert [g.code for g in gaps] == ["waiver-expired", "waiver-unused"]


@pytest.mark.parametrize(
    ("severities", "gaps", "expected"),
    [
        ([], [], Decision.APPROVE),
        ([Severity.INFO], [], Decision.APPROVE),
        ([Severity.LOW], [], Decision.REVIEW),
        ([Severity.HIGH], [], Decision.REJECT),
        ([], [Gap("body-not-recorded", "x")], Decision.REVIEW),
        ([], [Gap("no-persona", "x", blocking=False)], Decision.APPROVE),
    ],
)
def test_decision(severities: list[Severity], gaps: list[Gap], expected: Decision) -> None:
    decision, reasons = decide([_finding(severity=s) for s in severities], gaps, Config())
    assert decision is expected and reasons
