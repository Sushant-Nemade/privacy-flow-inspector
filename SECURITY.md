# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/Sushant-Nemade/privacy-flow-inspector/security/advisories/new).
Do not open a public issue, and never attach a real HAR file: captures can contain personal data,
session cookies and access tokens. A minimal synthetic HAR that reproduces the problem is ideal.

## How the tool treats data

- It works fully offline. It makes no network requests and sends no telemetry.
- HAR files are treated as untrusted input: file, body, entry and value counts are bounded and
  nested decoding (JSON, Base64, JWT, URLs) has a fixed depth.
- Reports never contain raw personal data. Values are shown as a short mask and a keyed
  fingerprint (HMAC-SHA256 with a random per-run key unless `PFI_FINGERPRINT_KEY` is set).
- The redacted HAR export removes detected values (including their encoded forms), all
  `Authorization`, `Cookie` and `Set-Cookie` values and every response body. It re-checks the result
  and refuses to write the file if any detected value would remain.
- Text taken from the capture is stripped of control and bidirectional characters, and escaped or
  confined to code spans in Markdown.

## Supported versions

Only the latest release on `main` receives fixes.
