from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import DEMO_CONFIG, DEMO_HAR, DETECTED_VALUES, PERSONA_VALUES, entry

from privacy_flow_inspector import output
from privacy_flow_inspector.detectors import DETECTORS, persona_variants
from privacy_flow_inspector.engine import inspect
from privacy_flow_inspector.model import Category, Finding, InspectorError, Severity
from privacy_flow_inspector.policy import Config, load_config

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def _forbidden() -> set[str]:
    values = {v.lower() for v in PERSONA_VALUES + DETECTED_VALUES}
    for value in PERSONA_VALUES:
        values.update(needle.lower() for _, needle, _ in persona_variants(value))
    return {v for v in values if len(v) >= 4}


def test_no_raw_or_encoded_personal_data_in_any_output(tmp_path: Path) -> None:
    result = inspect([DEMO_HAR], load_config(DEMO_CONFIG), now=NOW)
    redacted = tmp_path / "demo.redacted.har"
    output.redact_har(DEMO_HAR, redacted, result.redactions["demo-shop.har"])
    texts = {
        "json": output.to_json(result.report),
        "sarif": output.to_sarif(result.report),
        "markdown": output.to_markdown(result.report),
        "text": output.to_text(result.report),
        "redacted-har": redacted.read_text(encoding="utf-8"),
    }
    forbidden = _forbidden()
    # The test is only meaningful if the input really contains the persona data.
    assert "jane.test@example.com" in DEMO_HAR.read_text(encoding="utf-8")
    for name, text in texts.items():
        leaks = [value for value in forbidden if value in text.lower()]
        assert not leaks, (name, leaks[:3])


def test_redacted_har_stays_a_valid_har_without_secrets(tmp_path: Path) -> None:
    result = inspect([DEMO_HAR], load_config(DEMO_CONFIG), now=NOW)
    target = tmp_path / "r.har"
    output.redact_har(DEMO_HAR, target, result.redactions["demo-shop.har"])
    document = json.loads(target.read_text(encoding="utf-8"))
    entries = document["log"]["entries"]
    assert len(entries) == 10
    for item in entries:
        assert "text" not in item["response"]["content"]
        for header in item["request"]["headers"]:
            if header["name"].lower() in ("authorization", "cookie"):
                assert header["value"] == output.REDACTED
    assert "[REDACTED]" in entries[4]["request"]["postData"]["text"]


def test_redaction_self_check_refuses_to_write(tmp_path: Path) -> None:
    har = tmp_path / "x.har"
    har.write_text(json.dumps({"log": {"entries": [entry("https://t.example/a")], "comment": "secret-value"}}), "utf-8")
    target = tmp_path / "out.har"
    with pytest.raises(InspectorError, match="self-check"):
        output.redact_har(har, target, {"secret-value"})
    assert not target.exists()


def test_sarif_and_json_structure(tmp_path: Path) -> None:
    report = inspect([DEMO_HAR], load_config(DEMO_CONFIG), now=NOW).report
    sarif = json.loads(output.to_sarif(report, {"demo-shop.har": "examples/recorded"}))
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "examples/recorded/demo-shop.har"
        assert location["region"]["startLine"] >= 1
        assert location["region"]["startColumn"] > 1
    assert sum(1 for r in run["results"] if "suppressions" in r) == 2
    document = json.loads(output.to_json(report))
    assert document["summary"]["allowed"] == 2
    assert document["summary"]["third_party_recipients"] == 6


def test_markdown_escapes_untrusted_values() -> None:
    report = inspect([DEMO_HAR], Config(), now=NOW).report
    report.findings.insert(
        0,
        Finding(
            "PFI-EMAIL",
            "![x](https://evil.example/p.png) <script>",
            Category.CONTACT,
            "pattern",
            Severity.HIGH,
            "evil`|.example",
            None,
            False,
            "query",
            "m",
        ),
    )
    markdown = output.to_markdown(report)
    assert "![x]" not in markdown and "<script>" not in markdown
    assert "\\<script\\>" in markdown


def test_third_party_recipients_are_listed_without_findings() -> None:
    report = inspect([DEMO_HAR], Config(disabled=frozenset(DETECTORS)), now=NOW).report
    assert report.findings == []
    markdown = output.to_markdown(report)
    assert "### Third-party recipients" in markdown
    assert "| `pixel-tracker.test` | " in markdown and "| none |" in markdown
    assert "Enable `PFI-THIRD-PARTY-CONNECTION`" in markdown
    assert "Third parties: " in output.to_text(report)
