"""Record examples/recorded/demo-shop.har with real Chromium via Playwright, fully offline.

Every request is answered locally by Playwright routing, so nothing leaves the machine.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from playwright.sync_api import Route, sync_playwright

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


def record(target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        # Lets the fictional legacy ad call go out over plain HTTP so the HAR shows an unencrypted flow.
        browser = playwright.chromium.launch(args=["--allow-running-insecure-content"])
        # "embed" is required: with "omit" or "attach", Playwright leaves request bodies out of the HAR.
        context = browser.new_context(record_har_path=str(target), record_har_content="embed")
        context.route("**/*", _handle)
        page = context.new_page()
        page.goto("https://shop.example/")
        for name, value in PERSONA.items():
            page.fill(f"input[name={name}]", value)
        page.click("button[type=submit]")
        page.wait_for_selector("#status:has-text('Account created')")
        context.close()
        browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "examples" / "recorded" / "demo-shop.har")
    args = parser.parse_args()
    record(args.out)
    print(f"recorded {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
