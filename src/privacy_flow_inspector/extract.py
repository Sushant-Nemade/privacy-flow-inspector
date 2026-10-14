"""Turn a request into labelled values ("carriers"), decoding common wrappers along the way."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, replace
from email.parser import BytesParser
from email.policy import HTTP
from urllib.parse import parse_qsl, unquote, urlsplit

from privacy_flow_inspector.har import Request

MAX_CARRIERS = 5000
_MAX_DEPTH = 3
_MAX_NESTED = 200_000
_IGNORED_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "host",
    "origin",
    "pragma",
    "priority",
    "upgrade-insecure-requests",
    "user-agent",
}
_BASE64 = re.compile(r"^[A-Za-z0-9+/_-]{16,}={0,2}$")
_JWT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class Carrier:
    channel: str
    key: str
    value: str
    origin: str
    encoded: bool = False
    container: bool = False


def _b64decode(value: str) -> str | None:
    padded = value + "=" * (-len(value) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
        if text and printable / len(text) > 0.95:
            return text
    return None


class _Builder:
    def __init__(self, channel: str) -> None:
        self.channel = channel
        self.items: list[Carrier] = []
        self.truncated = False

    def add(self, key: str, value: str, origin: str, encoded: bool, depth: int = 0) -> None:
        if len(self.items) >= MAX_CARRIERS:
            self.truncated = True
            return
        position = len(self.items)
        self.items.append(Carrier(self.channel, key, value, origin, encoded))
        self._expand(key, value, origin, encoded, depth)
        if len(self.items) > position + 1:
            self.items[position] = replace(self.items[position], container=True)

    def _expand(self, key: str, value: str, origin: str, encoded: bool, depth: int) -> None:
        if depth >= _MAX_DEPTH or len(value) > _MAX_NESTED:
            return
        stripped = value.strip()
        if stripped[:1] in "{[":
            try:
                parsed = json.loads(stripped)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                self.walk(parsed, f"{key}<json>", origin, encoded, depth + 1)
                return
        if _JWT.match(stripped):
            payload = _b64decode(stripped.split(".")[1])
            header = _b64decode(stripped.split(".")[0])
            if payload and header and '"alg"' in header:
                try:
                    claims = json.loads(payload)
                except ValueError:
                    claims = None
                if isinstance(claims, dict):
                    self.walk(claims, f"{key}<jwt>", origin, True, depth + 1)
                    return
        if _BASE64.match(stripped) and not stripped.isdigit():
            decoded_text = _b64decode(stripped)
            if decoded_text is not None:
                self.add(f"{key}<base64>", decoded_text, origin, True, depth + 1)
                return
        if stripped.startswith(("http://", "https://")) and "?" in stripped:
            try:
                inner = urlsplit(stripped)
            except ValueError:
                return
            self.add(
                f"{key}>url",
                f"{inner.scheme}://{inner.netloc}{inner.path}",
                origin,
                encoded,
                depth + 1,
            )
            for name, inner_value in parse_qsl(inner.query, keep_blank_values=False):
                self.add(f"{key}>{name}", inner_value, origin, encoded, depth + 1)
            return
        if "%" in stripped:
            decoded = unquote(stripped)
            if decoded != stripped:
                self.add(f"{key}<url-decoded>", decoded, origin, encoded, depth + 1)

    def walk(self, node: object, key: str, origin: str, encoded: bool, depth: int) -> None:
        if isinstance(node, dict):
            for name, value in node.items():
                self.walk(value, f"{key}.{name}", origin, encoded, depth)
        elif isinstance(node, list):
            for position, value in enumerate(node[:1000]):
                self.walk(value, f"{key}[{position}]", origin, encoded, depth)
        elif isinstance(node, str):
            self.add(key, node, origin, encoded, depth)
        elif isinstance(node, (int, float)) and not isinstance(node, bool):
            self.add(key, repr(node), origin, encoded, depth)


def _body(request: Request) -> _Builder:
    builder = _Builder("body")
    if request.body_params and not request.body:
        for name, value in request.body_params:
            builder.add(name, value, value, False)
        return builder
    body = request.body
    if not body:
        return builder
    mime = request.body_mime.lower()
    if "x-www-form-urlencoded" in mime:
        for name, value in parse_qsl(body, keep_blank_values=False):
            builder.add(name, value, value, False)
    elif "multipart/form-data" in mime:
        message = BytesParser(policy=HTTP).parsebytes(
            f"Content-Type: {request.body_mime}\r\n\r\n".encode() + body.encode("utf-8", "replace")
        )
        if message.is_multipart():
            for part in message.iter_parts():
                param = part.get_param("name", header="content-disposition")
                name = param if isinstance(param, str) and param else "part"
                payload = part.get_payload(decode=True)
                if isinstance(payload, bytes) and part.get_filename() is None:
                    text = payload.decode("utf-8", "replace")
                    builder.add(str(name), text, text, False)
    else:
        builder.add("$", body, body, False)
    return builder


def carriers(request: Request) -> tuple[list[Carrier], bool]:
    """All values the request transmits, with a flag when the per-request limit was hit."""
    found: list[Carrier] = []
    truncated = False

    path = _Builder("url-path")
    for position, segment in enumerate(s for s in request.parts.path.split("/") if s):
        path.add(f"path[{position}]", unquote(segment), segment, False)
    query = _Builder("query")
    for name, value in parse_qsl(request.parts.query, keep_blank_values=False):
        query.add(name, value, value, False)
    if request.parts.fragment:
        query.add("#fragment", unquote(request.parts.fragment), request.parts.fragment, False)

    headers = _Builder("header")
    cookies = _Builder("cookie")
    for name, value in request.cookies:
        cookies.add(name, value, value, False)
    for name, value in request.headers:
        lowered = name.lower()
        if lowered in _IGNORED_HEADERS or lowered.startswith((":", "sec-")):
            continue
        if lowered == "cookie":
            if not request.cookies:
                for pair in value.split(";"):
                    cookie_name, _, cookie_value = pair.strip().partition("=")
                    if cookie_value:
                        cookies.add(cookie_name, cookie_value, cookie_value, False)
            continue
        if lowered == "authorization" and " " in value:
            scheme, _, token = value.partition(" ")
            headers.add(f"{name}<{scheme.lower()}>", token.strip(), value, False)
            continue
        headers.add(name, value, value, False)

    for builder in (path, query, headers, cookies, _body(request)):
        found.extend(builder.items)
        truncated = truncated or builder.truncated
    return found, truncated
