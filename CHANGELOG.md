# Changelog

All notable changes are recorded here. The project follows [Semantic Versioning](https://semver.org/);
while the major version is 0, minor releases may change behaviour.

## [0.2.0] - 2026-10-15

### Added

- Reports list every third-party recipient with its request count, including recipients that
  received no detected personal data. Found by scanning a real website that loaded Google Fonts:
  the previous report approved it without naming Google at all.
- Opt-in rule `PFI-THIRD-PARTY-CONNECTION` (`[detectors] enabled = [...]`): one finding per
  third-party site for the visitor IP address every connection discloses, noting when a `Referer`
  revealed the first-party page. Allowances and waivers apply as usual.
- `privacy-flow-inspector rules` marks opt-in rules.

## [0.1.1] - 2026-10-15

### Added

- Published on PyPI: `python -m pip install privacy-flow-inspector`. Releases are uploaded by the
  release workflow through PyPI trusted publishing, without a stored token.

### Changed

- README links are absolute so they also work on the PyPI project page.

## [0.1.0] - 2026-10-14

First public release.

### Added

- Offline HAR 1.2 inspection for Chrome, Firefox and Playwright captures, with line and column
  positions for SARIF and Chrome initiator scripts when present.
- Decoding of URL paths, query strings, fragments, headers, cookies, JSON, form, multipart,
  Base64, JWT claims, nested URLs and percent-encoded values.
- Test-persona matching including lowercase, URL-encoded, Base64 and MD5/SHA-1/SHA-256 forms,
  and phone digits / E.164.
- Checked detectors: email, phone, IBAN (mod-97), payment cards (issuer prefix + Luhn), German
  Steuer-ID (ISO 7064 MOD 11,10 + digit rules), German KVNR, health, identity and location fields,
  public IP addresses.
- Recipient grouping by registrable domain (Public Suffix List), first-party scope, approved
  processors and expiring waivers; APPROVE / REVIEW / REJECT decision with coverage gaps.
- Reports: JSON, SARIF 2.1.0, Markdown data-flow map, and a self-checked redacted HAR export.
- Composite GitHub Action and a Playwright recorder for the fictional demo shop.

### Known limitations

- Only traffic present in the HAR is checked; WebSocket frames and service-worker traffic may be missing.
- Binary payloads (protobuf, compressed bodies) are not decoded.
- Findings are technical evidence for a privacy review, not legal advice.

[0.2.0]: https://github.com/Sushant-Nemade/privacy-flow-inspector/releases/tag/v0.2.0
[0.1.1]: https://github.com/Sushant-Nemade/privacy-flow-inspector/releases/tag/v0.1.1
[0.1.0]: https://github.com/Sushant-Nemade/privacy-flow-inspector/releases/tag/v0.1.0
