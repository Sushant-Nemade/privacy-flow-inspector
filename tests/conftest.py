from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO_HAR = ROOT / "examples" / "recorded" / "demo-shop.har"
DEMO_CONFIG = ROOT / "examples" / "pfi.toml"
PERSONA_VALUES = ["jane.test@example.com", "+49 151 23456789", "Jane Test"]
DETECTED_VALUES = ["DE89370400440532013000", "A123456780", "J45.9", "52.520008", "13.404954"]


def entry(
    url: str,
    method: str = "GET",
    headers: list[tuple[str, str]] | None = None,
    body: str | None = None,
    mime: str = "application/json",
    **extra: Any,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": [{"name": n, "value": v} for n, v in (headers or [])],
        "queryString": [],
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(body) if body else 0,
    }
    if body is not None:
        request["postData"] = {"mimeType": mime, "text": body}
    item: dict[str, Any] = {
        "startedDateTime": "2026-10-14T10:00:00.000Z",
        "time": 1,
        "request": request,
        "response": {
            "status": 204,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": [],
            "cookies": [],
            "content": {"size": 0, "mimeType": "text/plain"},
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": 0,
        },
        "cache": {},
        "timings": {"send": 0, "wait": 1, "receive": 0},
    }
    item.update(extra)
    return item


def write_har(path: Path, entries: list[dict[str, Any]]) -> Path:
    document = {"log": {"version": "1.2", "creator": {"name": "test", "version": "1"}, "entries": entries}}
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def har_factory(tmp_path: Path):  # type: ignore[no-untyped-def]
    def make(entries: list[dict[str, Any]], name: str = "test.har") -> Path:
        return write_har(tmp_path / name, entries)

    return make
