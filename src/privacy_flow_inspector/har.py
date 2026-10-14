"""Load HAR 1.2 files defensively and turn entries into outgoing requests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

from privacy_flow_inspector.model import Gap, InspectorError

_SKIPPED_SCHEMES = {"data", "blob", "about", "chrome-extension", "moz-extension", "file"}
_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


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
        body_mime = ""
        params: list[tuple[str, str]] = []
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
                    body = raw
            elif not params and (has_body or "_file" in post):
                # Playwright with record_har_content="omit"/"attach" keeps only the size or a side file.
                omitted_bodies += 1
        elif method.upper() in _BODY_METHODS and has_body:
            omitted_bodies += 1

        requests.append(
            Request(
                har=display,
                index=index,
                method=method.upper(),
                url=url,
                parts=parts,
                host=host,
                query=_pairs(request.get("queryString")),
                headers=_pairs(request.get("headers")),
                cookies=_pairs(request.get("cookies")),
                body=body,
                body_mime=body_mime,
                body_params=params,
                resource_type=entry.get("_resourceType") if isinstance(entry.get("_resourceType"), str) else None,
                initiator=_initiator(entry),
                line=line,
                column=column,
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
