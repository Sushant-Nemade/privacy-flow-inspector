"""Record examples/recorded/demo-shop.har with real Chromium via Playwright, fully offline.

Every request is answered locally by Playwright routing, so nothing leaves the machine.
Playwright does not write WebSocket traffic into HAR files, so the messages Chromium sends through
the routed socket are captured here and added in Chrome DevTools' `_webSocketMessages` format.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

from playwright.sync_api import Route, WebSocketRoute, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "examples" / "demo-shop"
PERSONA = {
    "full_name": "Jane Test",
    "email": "jane.test@example.com",
    "phone": "+49 151 23456789",
    "iban": "DE89370400440532013000",
    "kvnr": "A123456780",
    "diagnosis": "J45.9",
}
CORS = {
    "Access-Control-Allow-Origin": "https://shop.example",
    "Access-Control-Allow-Headers": "content-type, authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
}


def _handle(route: Route) -> None:
    url = route.request.url
    if url in ("https://shop.example/", "https://shop.example/index.html"):
        route.fulfill(status=200, content_type="text/html", body=(SITE / "index.html").read_text("utf-8"))
    elif url == "https://shop.example/app.js":
        route.fulfill(status=200, content_type="text/javascript", body=(SITE / "app.js").read_text("utf-8"))
    elif url.startswith("https://shop.example/api/"):
        route.fulfill(status=200, content_type="application/json", body='{"ok":true}')
    else:
        route.fulfill(status=204, headers=CORS)


def _add_websocket_entries(target: Path, sockets: list[dict[str, object]]) -> None:
    document = json.loads(target.read_text(encoding="utf-8"))
    for socket in sockets:
        document["log"]["entries"].append(
            {
                "startedDateTime": socket["started"],
                "time": 0,
                "request": {
                    "method": "GET",
                    "url": socket["url"],
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": "Origin", "value": "https://shop.example"}],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": 101,
                    "statusText": "Switching Protocols",
                    "httpVersion": "HTTP/1.1",
                    "headers": [],
                    "cookies": [],
                    "content": {"size": 0, "mimeType": "x-unknown"},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
                "_resourceType": "websocket",
                "_webSocketMessages": socket["messages"],
            }
        )
    target.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def record(target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    sockets: list[dict[str, object]] = []

    def _socket(route: WebSocketRoute) -> None:
        messages: list[dict[str, object]] = []
        sockets.append(
            {"url": route.url, "started": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()), "messages": messages}
        )

        def _sent(message: str | bytes) -> None:
            text = message if isinstance(message, str) else message.decode("utf-8", "replace")
            messages.append({"type": "send", "time": time.time(), "opcode": 1, "data": text})

        route.on_message(_sent)

    with sync_playwright() as playwright:
        # Lets the fictional legacy ad call go out over plain HTTP so the HAR shows an unencrypted flow.
        browser = playwright.chromium.launch(args=["--allow-running-insecure-content"])
        # "embed" is required: with "omit" or "attach", Playwright leaves request bodies out of the HAR.
        context = browser.new_context(record_har_path=str(target), record_har_content="embed")
        context.route("**/*", _handle)
        context.route_web_socket(re.compile(r"^wss://"), _socket)
        page = context.new_page()
        page.goto("https://shop.example/")
        for name, value in PERSONA.items():
            page.fill(f"input[name={name}]", value)
        page.click("button[type=submit]")
        page.wait_for_selector("#status:has-text('Account created')")
        context.close()
        browser.close()
    _add_websocket_entries(target, sockets)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "examples" / "recorded" / "demo-shop.har")
    args = parser.parse_args()
    record(args.out)
    print(f"recorded {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
