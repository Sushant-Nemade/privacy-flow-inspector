"""Load HAR 1.2 files defensively and turn entries into outgoing requests."""

from __future__ import annotations

import base64
import binascii
import json
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from privacy_flow_inspector.model import Gap, InspectorError

_SKIPPED_SCHEMES = {"data", "blob", "about", "chrome-extension", "moz-extension", "file"}
_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_DECODABLE = {"gzip", "x-gzip", "deflate"}
_MAX_FRAMES = 10_000


@dataclass(frozen=True)
class Limits:
    max_har_bytes: int = 512 * 1024 * 1024
    max_body_bytes: int = 4 * 1024 * 1024
    max_entries: int = 200_000


@dataclass
class Request:
    har: str
    index: int
    method: str
    url: str
    parts: SplitResult
    host: str
    query: list[tuple[str, str]]
    headers: list[tuple[str, str]]
    cookies: list[tuple[str, str]]
    body: str | None
    body_mime: str
    body_params: list[tuple[str, str]]
    resource_type: str | None = None
    initiator: str | None = None
    line: int | None = None
    column: int | None = None
    notes: list[str] = field(default_factory=list)
    # How the recorded body was wrapped ("gzip", "deflate", "base64"); None for plain text.
    body_encoding: str | None = None
    websocket: bool = False
    ws_recorded: bool = False
    ws_sent: list[str] = field(default_factory=list)


def inflate(data: bytes, limit: int) -> bytes | None:
    """Decompress gzip or zlib data up to limit bytes; None if it is neither or too large."""
    if data[:2] == b"\x1f\x8b":
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif len(data) >= 2 and data[0] & 0x0F == 8 and int.from_bytes(data[:2], "big") % 31 == 0:
        decoder = zlib.decompressobj()
    else:
        return None
    try:
        out = decoder.decompress(data, limit + 1)
    except zlib.error:
        return None
    return None if len(out) > limit or decoder.unconsumed_tail else out


def _text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _inflated_text(data: bytes, limit: int) -> tuple[str | None, str | None, str | None] | None:
    """Decoded result when data is gzip/zlib; None when it is not compressed."""
    inflated = inflate(data, limit)
    if inflated is None:
        return None
    text = _text(inflated)
    if text is None:
        return None, None, "decompressed body is not UTF-8 text"
    return text, "gzip" if data[:2] == b"\x1f\x8b" else "deflate", None


def _decode_body(
    raw: str, post: dict[str, Any], headers: list[tuple[str, str]], limit: int
) -> tuple[str | None, str | None, str | None]:
    """(text, encoding, problem): text to inspect, how it was wrapped, or why it could not be read."""
    declared = next((v.strip().lower() for n, v in headers if n.lower() == "content-encoding"), "")
    if post.get("encoding") == "base64":
        try:
            data = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            return None, None, "body is marked base64 but does not decode"
        decoded = _inflated_text(data, limit)
        if decoded is not None:
            return decoded
        text = _text(data)
        return (text, "base64", None) if text is not None else (None, None, "base64 body is binary")
    # Some recorders keep binary bodies byte-for-byte as Latin-1 characters.
    if raw[:2] in ("\x1f\x8b", "\x78\x9c", "\x78\x01", "\x78\xda") and max(map(ord, raw)) < 256:
        decoded = _inflated_text(raw.encode("latin-1"), limit)
        if decoded is not None:
            return decoded
    if declared in ("br", "zstd"):
        return None, None, f"body uses {declared} compression, which is not decoded"
    if declared in _DECODABLE and "\ufffd" in raw[:64]:
        return None, None, f"{declared} body was stored lossily by the recorder"
    return raw, None, None


def _frames(entry: dict[str, Any], limit: int) -> tuple[list[str], int, bool]:
    """Sent WebSocket messages (Chrome DevTools _webSocketMessages), undecodable count, recorded flag."""
    messages = entry.get("_webSocketMessages")
    if not isinstance(messages, list):
        return [], 0, False
    sent: list[str] = []
    undecodable = 0
    for message in messages[:_MAX_FRAMES]:
        if not isinstance(message, dict) or message.get("type") != "send":
            continue
        data = message.get("data")
        if not isinstance(data, str) or not data:
            continue
        if message.get("opcode") == 2:
            try:
                payload = base64.b64decode(data, validate=True)
            except (binascii.Error, ValueError):
                undecodable += 1
                continue
            text = _text(inflate(payload, limit) or payload)
            if text is None:
                undecodable += 1
                continue
            data = text
        if len(data) <= limit:
            sent.append(data)
    return sent, undecodable, True


def _pairs(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    pairs = []
    for item in value:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            raw = item.get("value", "")
            pairs.append((item["name"], raw if isinstance(raw, str) else str(raw)))
    return pairs


def _initiator(entry: dict[str, Any]) -> str | None:
    initiator = entry.get("_initiator")
    if not isinstance(initiator, dict):
        return None
    url, line = initiator.get("url"), initiator.get("lineNumber")
    if not isinstance(url, str):
        stack = initiator.get("stack")
        frames = stack.get("callFrames") if isinstance(stack, dict) else None
        frame = frames[0] if isinstance(frames, list) and frames else None
        if isinstance(frame, dict):
            url, line = frame.get("url"), frame.get("lineNumber")
    if not isinstance(url, str) or not url:
        return None
    # Chrome reports zero-based line numbers.
    return f"{url}:{line + 1}" if isinstance(line, int) else url


def load_har(path: Path, display: str, limits: Limits) -> tuple[list[Request], list[Gap]]:
    gaps: list[Gap] = []
    try:
        size = path.stat().st_size
    except OSError as error:
        raise InspectorError(f"cannot read {path}: {error.strerror}") from None
    if size > limits.max_har_bytes:
        return [], [Gap("size-limit", f"HAR exceeds {limits.max_har_bytes} bytes; not inspected.", display)]
    try:
        text = path.read_text(encoding="utf-8-sig")
        document = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [], [Gap("parse-error", f"Not a readable HAR/JSON file: {error}.", display)]
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return [], [Gap("parse-error", "HAR has no log.entries array.", display)]
    if len(entries) > limits.max_entries:
        gaps.append(
            Gap(
                "entry-limit",
                f"Only the first {limits.max_entries} entries were inspected.",
                display,
            )
        )
        entries = entries[: limits.max_entries]

    requests: list[Request] = []
    cursor = 0
    omitted_bodies = 0
    undecodable_frames = 0
    unreadable: list[str] = []
    for index, entry in enumerate(entries):
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            gaps.append(Gap("parse-error", f"Entry {index} has no request object.", display))
            continue
        method, url = request.get("method"), request.get("url")
        if not isinstance(method, str) or not isinstance(url, str):
            gaps.append(Gap("parse-error", f"Entry {index} has no method or URL.", display))
            continue
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            gaps.append(Gap("parse-error", f"Entry {index} has an invalid URL.", display))
            continue
        if parts.scheme.lower() in _SKIPPED_SCHEMES or not host:
            continue

        line = column = None
        needle = json.dumps(url)
        found = text.find(needle, cursor)
        if found >= 0:
            cursor = found + len(needle)
            line = text.count("\n", 0, found) + 1
            column = found - (text.rfind("\n", 0, found) + 1) + 1

        body: str | None = None
        body_encoding: str | None = None
        body_mime = ""
        params: list[tuple[str, str]] = []
        headers = _pairs(request.get("headers"))
        post = request.get("postData")
        declared = request.get("bodySize")
        has_body = isinstance(declared, int) and declared > 0
        if isinstance(post, dict):
            body_mime = str(post.get("mimeType") or "")
            params = _pairs(post.get("params"))
            raw = post.get("text")
            if isinstance(raw, str) and raw:
                if len(raw.encode("utf-8")) > limits.max_body_bytes:
                    gaps.append(
                        Gap(
                            "size-limit",
                            f"Entry {index} body exceeds the size limit; skipped.",
                            display,
                        )
                    )
                else:
                    body, body_encoding, problem = _decode_body(raw, post, headers, limits.max_body_bytes)
                    if problem:
                        unreadable.append(f"entry {index}: {problem}")
            elif not params and (has_body or "_file" in post):
                # Playwright with record_har_content="omit"/"attach" keeps only the size or a side file.
                omitted_bodies += 1
        elif method.upper() in _BODY_METHODS and has_body:
            omitted_bodies += 1

        resource_type = entry.get("_resourceType") if isinstance(entry.get("_resourceType"), str) else None
        websocket = parts.scheme.lower() in ("ws", "wss") or (resource_type or "").lower() == "websocket"
        sent, undecodable, ws_recorded = _frames(entry, limits.max_body_bytes) if websocket else ([], 0, False)
        undecodable_frames += undecodable

        requests.append(
            Request(
                har=display,
                index=index,
                method=method.upper(),
                url=url,
                parts=parts,
                host=host,
                query=_pairs(request.get("queryString")),
                headers=headers,
                cookies=_pairs(request.get("cookies")),
                body=body,
                body_mime=body_mime,
                body_params=params,
                resource_type=resource_type,
                initiator=_initiator(entry),
                line=line,
                column=column,
                body_encoding=body_encoding,
                websocket=websocket,
                ws_recorded=ws_recorded,
                ws_sent=sent,
            )
        )
    if unreadable:
        gaps.append(
            Gap(
                "body-unreadable",
                f"{len(unreadable)} request body(ies) could not be decoded, so data in them was not checked "
                f"({'; '.join(unreadable[:3])}).",
                display,
            )
        )
    if undecodable_frames:
        gaps.append(
            Gap(
                "websocket-binary",
                f"{undecodable_frames} sent WebSocket message(s) are binary and were not decoded.",
                display,
            )
        )
    if omitted_bodies:
        gaps.append(
            Gap(
                "body-not-recorded",
                f"{omitted_bodies} request(s) had a body that the HAR does not contain; data in them "
                "could not be checked.",
                display,
            )
        )
    if not requests:
        gaps.append(Gap("no-requests", "The HAR contains no inspectable network requests.", display))
    return requests, gaps
