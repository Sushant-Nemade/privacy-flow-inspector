"""Re-records the demo with real Chromium and expects the same data flows (set PFI_RECORD=1)."""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import DEMO_CONFIG, ROOT
from test_engine import EXPECTED

from privacy_flow_inspector.engine import inspect
from privacy_flow_inspector.policy import load_config

pytestmark = pytest.mark.skipif(os.environ.get("PFI_RECORD") != "1", reason="browser recording is opt-in")


def test_fresh_recording_matches_committed_expectations(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import record_demo

    target = tmp_path / "demo-shop.har"
    record_demo.record(target)
    report = inspect([target], load_config(DEMO_CONFIG), now=datetime(2026, 10, 14, tzinfo=UTC)).report
    found = {
        (f.rule_id, f.recipient, f.channel, f.severity.label, "allowed" if f.allowed_reason else "open")
        for f in report.findings
    }
    assert found == EXPECTED
