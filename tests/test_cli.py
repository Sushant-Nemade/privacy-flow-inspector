from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from conftest import DEMO_CONFIG, DEMO_HAR

from privacy_flow_inspector import cli


def test_scan_writes_reports_and_redacted_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "repo"
    (work / "captures").mkdir(parents=True)
    shutil.copy(DEMO_HAR, work / "captures" / "demo-shop.har")
    monkeypatch.chdir(work)
    code = cli.main(
        [
            "scan",
            "captures/demo-shop.har",
            "--config",
            str(DEMO_CONFIG),
            "--json",
            "out/r.json",
            "--sarif",
            "out/r.sarif",
            "--markdown",
            "out/r.md",
            "--redact-dir",
            "out/redacted",
            "-q",
        ]
    )
    assert code == cli.EXIT_GATE
    assert sorted(p.name for p in (work / "out").iterdir()) == ["r.json", "r.md", "r.sarif", "redacted"]
    assert (work / "out" / "redacted" / "demo-shop.redacted.har").is_file()
    sarif = json.loads((work / "out" / "r.sarif").read_text(encoding="utf-8"))
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "captures/demo-shop.har"


@pytest.mark.parametrize(("fail_on", "expected"), [("never", 0), ("reject", 1), ("review", 1)])
def test_fail_on(fail_on: str, expected: int) -> None:
    assert cli.main(["scan", str(DEMO_HAR), "--config", str(DEMO_CONFIG), "--fail-on", fail_on, "-q"]) == expected


@pytest.mark.parametrize(
    "args",
    [
        ["scan", "missing.har"],
        ["scan", str(DEMO_HAR), str(DEMO_HAR)],
        ["scan", str(DEMO_HAR), "--config", "missing.toml"],
    ],
)
def test_usage_errors(args: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(args) == cli.EXIT_USAGE
    assert "error:" in capsys.readouterr().err


def test_summary_and_rules(capsys: pytest.CaptureFixture[str]) -> None:
    cli.main(["scan", str(DEMO_HAR), "--config", str(DEMO_CONFIG)])
    out = capsys.readouterr().out
    assert out.startswith("Decision: REJECT")
    assert "jane.test" not in out.lower()
    assert cli.main(["rules"]) == 0
    assert "PFI-DE-KVNR" in capsys.readouterr().out
