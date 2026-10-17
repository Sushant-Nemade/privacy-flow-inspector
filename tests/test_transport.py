from __future__ import annotations

import base64
import gzip
import json
import zlib
from datetime import UTC, datetime
from pathlib import Path

from conftest import entry, write_har

from privacy_flow_inspector import output
from privacy_flow_inspector.detectors import Persona
from privacy_flow_inspector.engine import inspect
from privacy_flow_inspector.extract import carriers
from privacy_flow_inspector.har import Limits, load_har
from privacy_flow_inspector.model import Category, Decision
from privacy_flow_inspector.policy import Config

NOW = datetime(2026, 10, 18, 12, 0, tzinfo=UTC)
EMAIL = "jane.test@example.com"
PAYLOAD = json.dumps({"traits": {"email": EMAIL}})
PERSONA_CONFIG = Config(first_party=("shop.example",), personas=(Persona("Test email", EMAIL, Category.CONTACT),))


def _socket(messages: list[dict[str, object]] | None, host: str = "live.chat.test") -> dict[str, object]:
    item = entry(f"wss://{host}/socket", _resourceType="websocket")
    if messages is not None:
        item["_webSocketMessages"] = messages
    return item


def _keys(har: Path) -> dict[str, str]:
    requests, _ = load_har(har, har.name, Limits())
    return {c.key: c.value for request in requests for c in carriers(request)[0]}


def test_websocket_messages_with_socket_io_signalr_and_binary_frames(tmp_path: Path) -> None:
    binary = base64.b64encode(gzip.compress(PAYLOAD.encode())).decode()
    har = write_har(
        tmp_path / "ws.har",
        [
            _socket(
                [
                    {"type": "send", "time": 1, "opcode": 1, "data": '42["identify",' + PAYLOAD + "]"},
                    {"type": "send", "time": 2, "opcode": 1, "data": PAYLOAD + "\x1e"},
                    {"type": "send", "time": 3, "opcode": 2, "data": binary},
                    {"type": "receive", "time": 4, "opcode": 1, "data": json.dumps({"email": "server@x.test"})},
                ]
            )
        ],
    )
    keys = _keys(har)
    assert keys["message[0]<json>[1].traits.email"] == EMAIL
    assert keys["message[1]<json>.traits.email"] == EMAIL
    assert keys["message[2]<json>.traits.email"] == EMAIL
    assert all("server@x.test" not in value for value in keys.values())
    report = inspect([har], PERSONA_CONFIG, now=NOW).report
    (finding,) = report.findings
    assert finding.channel == "websocket" and "a WebSocket message" in finding.message
    assert finding.occurrences == 3


def test_websocket_without_messages_is_a_gap(tmp_path: Path) -> None:
    har = write_har(
        tmp_path / "pw.har",
        [entry("https://shop.example/", _resourceType="document"), _socket(None), _socket(None, "ws.shop.example")],
    )
    report = inspect([har], PERSONA_CONFIG, now=NOW).report
    gaps = {(g.code, g.blocking): g.message for g in report.gaps}
    assert "live.chat.test" in gaps[("websocket-not-recorded", True)]
    assert "ws.shop.example" in gaps[("websocket-not-recorded", False)]
    assert report.decision is Decision.REVIEW
    undecodable = write_har(
        tmp_path / "bin.har",
        [_socket([{"type": "send", "opcode": 2, "data": base64.b64encode(b"\x00\xff\x10").decode()}])],
    )
    codes = {g.code for g in inspect([undecodable], PERSONA_CONFIG, now=NOW).report.gaps}
    assert "websocket-binary" in codes


def _post(text: str, encoding_header: str | None = None, **post: object) -> dict[str, object]:
    headers = [("Content-Type", "application/json")]
    if encoding_header:
        headers.append(("Content-Encoding", encoding_header))
    item = entry("https://ingest.vendor.test/batch", method="POST", headers=headers, body=text)
    item["request"]["postData"].update(post)  # type: ignore[index]
    return item


def test_compressed_and_encoded_bodies(tmp_path: Path) -> None:
    gz = gzip.compress(PAYLOAD.encode())
    entries = [
        _post(base64.b64encode(gz).decode(), "gzip", encoding="base64"),
        _post(gz.decode("latin-1"), "gzip"),
        _post(base64.b64encode(zlib.compress(PAYLOAD.encode())).decode(), "deflate", encoding="base64"),
        _post(PAYLOAD, "gzip"),  # recorder already decompressed it (for example mitmproxy)
        _post(base64.b64encode(PAYLOAD.encode()).decode(), None, encoding="base64"),
    ]
    har = write_har(tmp_path / "bodies.har", entries)
    requests, gaps = load_har(har, har.name, Limits())
    assert [r.body_encoding for r in requests] == ["gzip", "gzip", "deflate", None, "base64"]
    assert gaps == []
    report = inspect([har], PERSONA_CONFIG, now=NOW).report
    (finding,) = report.findings
    assert finding.occurrences == 5
    assert {e.key for e in finding.evidence} >= {"$<gzip><json>.traits.email", "$<deflate><json>.traits.email"}


def test_undecodable_bodies_are_blocking_gaps(tmp_path: Path) -> None:
    lossy = gzip.compress(PAYLOAD.encode()).decode("utf-8", "replace")  # what Playwright stores
    har = write_har(
        tmp_path / "lossy.har",
        [_post(lossy, "gzip"), _post("binary", "br"), _post("not base64!", None, encoding="base64")],
    )
    requests, gaps = load_har(har, har.name, Limits())
    assert all(r.body is None for r in requests)
    (gap,) = gaps
    assert gap.code == "body-unreadable" and gap.blocking
    assert "stored lossily" in gap.message and "br compression" in gap.message


def test_decompression_bomb_is_bounded(tmp_path: Path) -> None:
    bomb = base64.b64encode(gzip.compress(b"0" * (8 * 1024 * 1024))).decode()
    har = write_har(tmp_path / "bomb.har", [_post(bomb, "gzip", encoding="base64")])
    requests, gaps = load_har(har, har.name, Limits(max_body_bytes=1024 * 1024))
    assert requests[0].body is None
    assert [g.code for g in gaps] == ["body-unreadable"]


def test_base64_gzip_value_inside_json(tmp_path: Path) -> None:
    packed = base64.b64encode(gzip.compress(PAYLOAD.encode())).decode()
    har = write_har(tmp_path / "v.har", [_post(json.dumps({"payload": packed}))])
    assert _keys(har)["$<json>.payload<base64+gzip><json>.traits.email"] == EMAIL


def test_redaction_removes_encoded_bodies_and_frames(tmp_path: Path) -> None:
    gz = gzip.compress(PAYLOAD.encode())
    har = write_har(
        tmp_path / "mixed.har",
        [
            _post(base64.b64encode(gz).decode(), "gzip", encoding="base64"),
            _post(PAYLOAD),
            _socket(
                [
                    {"type": "send", "opcode": 1, "data": PAYLOAD},
                    {"type": "send", "opcode": 2, "data": base64.b64encode(gz).decode()},
                    {"type": "receive", "opcode": 1, "data": "hello from server"},
                ]
            ),
        ],
    )
    result = inspect([har], PERSONA_CONFIG, now=NOW)
    target = tmp_path / "mixed.redacted.har"
    output.redact_har(har, target, result.redactions[har.name])
    document = json.loads(target.read_text(encoding="utf-8"))
    first, second, socket = document["log"]["entries"]
    assert first["request"]["postData"]["text"] == output.REDACTED_BODY
    assert "encoding" not in first["request"]["postData"]
    assert EMAIL not in second["request"]["postData"]["text"] and "[REDACTED]" in second["request"]["postData"]["text"]
    sent_text, sent_binary, received = socket["_webSocketMessages"]
    assert "[REDACTED]" in sent_text["data"] and EMAIL not in sent_text["data"]
    assert sent_binary["data"] == output.REDACTED_BODY and received["data"] == output.REDACTED_BODY
