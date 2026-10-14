from __future__ import annotations

from pathlib import Path

from conftest import entry, write_har

from privacy_flow_inspector.har import Limits, load_har


def test_skips_non_network_schemes_and_records_lines(tmp_path: Path) -> None:
    har = write_har(
        tmp_path / "a.har",
        [
            entry("data:text/plain,hi"),
            entry("https://a.example/one"),
            entry(
                "https://b.example/two",
                _initiator={
                    "type": "script",
                    "stack": {"callFrames": [{"url": "https://a.example/app.js", "lineNumber": 41}]},
                },
                _resourceType="fetch",
            ),
        ],
    )
    requests, gaps = load_har(har, "a.har", Limits())
    assert [r.index for r in requests] == [1, 2]
    assert gaps == []
    text = har.read_text(encoding="utf-8").splitlines()
    assert '"https://a.example/one"' in text[requests[0].line - 1]
    assert requests[1].initiator == "https://a.example/app.js:42"
    assert requests[1].resource_type == "fetch"


def test_bodies_that_were_not_recorded_are_a_blocking_gap(tmp_path: Path) -> None:
    omitted = entry("https://a.example/p", method="POST")
    omitted["request"]["bodySize"] = 84
    attached = entry("https://a.example/q", method="POST", body="")
    attached["request"]["bodySize"] = 10
    attached["request"]["postData"]["_file"] = "abc.json"
    _, gaps = load_har(write_har(tmp_path / "b.har", [omitted, attached]), "b.har", Limits())
    (gap,) = gaps
    assert gap.code == "body-not-recorded" and gap.blocking
    assert gap.message.startswith("2 request(s)")


def test_invalid_files(tmp_path: Path) -> None:
    bad = tmp_path / "bad.har"
    bad.write_text("{not json", encoding="utf-8")
    _, gaps = load_har(bad, "bad.har", Limits())
    assert gaps[0].code == "parse-error"
    empty = write_har(tmp_path / "empty.har", [])
    _, gaps = load_har(empty, "empty.har", Limits())
    assert gaps[0].code == "no-requests"
    _, gaps = load_har(empty, "empty.har", Limits(max_har_bytes=10))
    assert gaps[0].code == "size-limit"


def test_large_body_is_skipped(tmp_path: Path) -> None:
    har = write_har(tmp_path / "c.har", [entry("https://a.example/p", method="POST", body="x" * 100)])
    (request,), gaps = load_har(har, "c.har", Limits(max_body_bytes=10))
    assert request.body is None
    assert gaps[0].code == "size-limit"
