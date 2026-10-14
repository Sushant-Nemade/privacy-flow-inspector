from __future__ import annotations

import base64
import json
from pathlib import Path

from conftest import entry, write_har

from privacy_flow_inspector.extract import MAX_CARRIERS, carriers
from privacy_flow_inspector.har import Limits, load_har


def _carriers(tmp_path: Path, **kwargs):  # type: ignore[no-untyped-def]
    har = write_har(tmp_path / "x.har", [entry(**kwargs)])
    (request,), _ = load_har(har, "x.har", Limits())
    found, truncated = carriers(request)
    return {c.key: c for c in found}, truncated


def test_query_path_headers_and_cookie_header(tmp_path: Path) -> None:
    found, _ = _carriers(
        tmp_path,
        url="https://t.example/u/jane%40example.org/p?em=abc&x=1#frag=1",
        headers=[("Cookie", "uid=42; theme=dark"), ("User-Agent", "ignored"), ("X-Trace", "t1")],
    )
    assert found["path[1]"].value == "jane@example.org"
    assert found["em"].channel == "query"
    assert found["#fragment"].value == "frag=1"
    assert found["uid"].channel == "cookie"
    assert "User-Agent" not in found
    assert found["X-Trace"].channel == "header"


def test_json_jwt_base64_and_nested_url(tmp_path: Path) -> None:
    claims = base64.urlsafe_b64encode(json.dumps({"email": "a@b.de"}).encode()).decode().rstrip("=")
    header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').decode().rstrip("=")
    token = f"{header}.{claims}.sig"
    blob = base64.b64encode(json.dumps({"form": {"diagnosis": "J45.9"}}).encode()).decode()
    body = json.dumps({"user": {"email": "a@b.de"}, "blob": blob, "ref": "https://s.example/w?mail=x%40y.de"})
    found, _ = _carriers(
        tmp_path, url="https://t.example/e", method="POST", headers=[("Authorization", f"Bearer {token}")], body=body
    )
    assert found["$"].container
    assert found["$<json>.user.email"].value == "a@b.de"
    assert found["Authorization<bearer><jwt>.email"].encoded
    assert found["$<json>.blob<base64><json>.form.diagnosis"].value == "J45.9"
    assert found["$<json>.ref>mail"].value == "x@y.de"
    assert found["$<json>.ref>url"].value == "https://s.example/w"


def test_form_and_multipart_bodies(tmp_path: Path) -> None:
    found, _ = _carriers(
        tmp_path,
        url="https://t.example/f",
        method="POST",
        body="email=a%40b.de&n=1",
        mime="application/x-www-form-urlencoded",
    )
    assert found["email"].value == "a@b.de"
    multipart = (
        '--XYZ\r\nContent-Disposition: form-data; name="phone"\r\n\r\n+491512345678\r\n'
        '--XYZ\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\nskip\r\n--XYZ--\r\n'
    )
    found, _ = _carriers(
        tmp_path, url="https://t.example/m", method="POST", body=multipart, mime="multipart/form-data; boundary=XYZ"
    )
    assert found["phone"].value == "+491512345678"
    assert "file" not in found


def test_carrier_limit(tmp_path: Path) -> None:
    body = json.dumps({f"k{i}": "v" for i in range(MAX_CARRIERS + 10)})
    found, truncated = _carriers(tmp_path, url="https://t.example/big", method="POST", body=body)
    assert truncated
    assert sum(1 for c in found.values() if c.channel == "body") == MAX_CARRIERS
