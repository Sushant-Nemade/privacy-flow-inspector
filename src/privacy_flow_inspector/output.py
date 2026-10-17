"""Renderers (JSON, SARIF, Markdown, text) and the redacted HAR export."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from privacy_flow_inspector.detectors import DETECTORS
from privacy_flow_inspector.model import (
    Category,
    Finding,
    InspectorError,
    Report,
    Severity,
    clean_text,
)

TOOL_NAME = "privacy-flow-inspector"
TOOL_URL = "https://github.com/Sushant-Nemade/privacy-flow-inspector"
REDACTED = "[REDACTED]"
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}


def write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _timestamp(report: Report) -> str:
    return report.scanned_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def _status(finding: Finding) -> str:
    if finding.allowed_reason:
        return "allowed"
    if finding.waiver_reason:
        return "waived"
    return "open"


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.label: 0 for severity in reversed(Severity)}
    for finding in findings:
        if finding.counted:
            counts[finding.severity.label] += 1
    return counts


def to_json(report: Report) -> str:
    document = {
        "schema": "privacy-flow-inspector/report/v1",
        "tool": {"name": TOOL_NAME, "version": report.tool_version},
        "inputs": report.inputs,
        "scanned_at": _timestamp(report),
        "decision": {"value": report.decision.value, "reasons": report.decision_reasons},
        "summary": {
            "requests": report.requests,
            "recipients": len(report.flows),
            "third_party_recipients": sum(1 for f in report.flows if not f.first_party),
            "personas": report.personas,
            "findings_by_severity": severity_counts(report.findings),
            "allowed": sum(1 for f in report.findings if f.allowed_reason),
            "waived": sum(1 for f in report.findings if f.waiver_reason),
        },
        "first_party": report.first_party,
        "flows": [
            {
                "recipient": flow.recipient,
                "label": flow.label,
                "first_party": flow.first_party,
                "requests": flow.requests,
                "categories": {c.value: s.label for c, s in sorted(flow.categories.items(), key=lambda i: i[0].value)},
            }
            for flow in report.flows
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category.value,
                "severity": f.severity.label,
                "confidence": f.confidence,
                "recipient": f.recipient,
                "recipient_label": f.recipient_label,
                "first_party": f.first_party,
                "channel": f.channel,
                "status": _status(f),
                "allowed_reason": f.allowed_reason,
                "waiver_reason": f.waiver_reason,
                "occurrences": f.occurrences,
                "message": f.message,
                "evidence": [
                    {
                        "har": e.har,
                        "entry": e.entry,
                        "har_line": e.har_line,
                        "har_column": e.har_column,
                        "method": e.method,
                        "url": e.url,
                        "channel": e.channel,
                        "key": e.key,
                        "variant": e.variant,
                        "preview": e.preview,
                        "fingerprint": e.fingerprint,
                        "initiator": e.initiator,
                    }
                    for e in f.evidence
                ],
            }
            for f in report.findings
        ],
        "coverage_gaps": [
            {"code": g.code, "message": g.message, "path": g.path, "blocking": g.blocking} for g in report.gaps
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def har_prefix(har: Path, cwd: Path) -> str:
    try:
        return har.resolve().parent.relative_to(cwd.resolve()).as_posix().removeprefix(".").strip("/")
    except ValueError:
        return ""


def to_sarif(report: Report, prefixes: dict[str, str] | None = None) -> str:
    prefixes = prefixes or {}
    rules: list[dict[str, Any]] = []
    indexes: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        if finding.rule_id not in indexes:
            detector = DETECTORS[finding.rule_id]
            indexes[finding.rule_id] = len(rules)
            rules.append(
                {
                    "id": detector.id,
                    "shortDescription": {"text": detector.title},
                    "fullDescription": {"text": detector.description},
                    "help": {"text": detector.description},
                    "helpUri": f"{TOOL_URL}#detectors",
                    "defaultConfiguration": {"level": "warning"},
                    "properties": {"tags": ["privacy", "personal-data"]},
                }
            )
        evidence = finding.evidence[0] if finding.evidence else None
        prefix = prefixes.get(evidence.har, "") if evidence else ""
        uri = f"{prefix}/{evidence.har}" if evidence and prefix else (evidence.har if evidence else ".")
        physical: dict[str, Any] = {"artifactLocation": {"uri": quote(uri, safe="/._-~")}}
        if evidence and evidence.har_line:
            physical["region"] = {"startLine": evidence.har_line}
            if evidence.har_column:
                physical["region"]["startColumn"] = evidence.har_column
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": indexes[finding.rule_id],
            "level": _sarif_level(finding.severity),
            "message": {"text": clean_text(f"{finding.title}. {finding.message}", 2000)},
            "locations": [{"physicalLocation": physical}],
            "partialFingerprints": {
                "privacyFlowInspector/v1": hashlib.sha256(
                    "|".join(
                        [
                            finding.rule_id,
                            finding.recipient,
                            finding.channel,
                            finding.category.value,
                        ]
                    ).encode()
                ).hexdigest()
            },
            "properties": {
                "category": finding.category.value,
                "recipient": finding.recipient,
                "channel": finding.channel,
                "occurrences": finding.occurrences,
            },
        }
        if finding.severity in _SECURITY_SEVERITY:
            result["properties"]["security-severity"] = _SECURITY_SEVERITY[finding.severity]
        justification = finding.allowed_reason or finding.waiver_reason
        if justification:
            result["suppressions"] = [{"kind": "external", "justification": justification}]
        results.append(result)
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": report.tool_version,
                        "informationUri": TOOL_URL,
                        "rules": rules,
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
                "properties": {"decision": report.decision.value},
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


_MD_SPECIAL = str.maketrans({c: f"\\{c}" for c in "\\`*_{}[]()<>#+-.!|~"})
_MARK = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
    Severity.INFO: "info",
}


def md(value: str, limit: int = 200) -> str:
    return clean_text(value, limit).translate(_MD_SPECIAL)


def code(value: str, limit: int = 160) -> str:
    return "`" + clean_text(value, limit).replace("`", "'").replace("|", "\u00a6") + "`"


def to_markdown(report: Report, max_findings: int = 40) -> str:
    counts = severity_counts(report.findings)
    lines = [
        f"## Privacy Flow Inspector: **{report.decision.value.upper()}**",
        "",
        f"{report.requests} requests in {', '.join(code(i, 80) for i in report.inputs)} scanned at "
        f"{_timestamp(report)}. First party: {', '.join(code(d, 80) for d in report.first_party) or 'none'}.",
        "",
    ]
    lines += [f"- {md(reason, 300)}" for reason in report.decision_reasons]
    lines += [
        "",
        "| Critical | High | Medium | Low | Info | Allowed | Waived | Recipients |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} "
        f"| {sum(1 for f in report.findings if f.allowed_reason)} "
        f"| {sum(1 for f in report.findings if f.waiver_reason)} "
        f"| {len(report.flows)} |",
        "",
    ]
    categories = [c for c in Category if any(f.category is c for f in report.findings)]
    if categories:
        cells: dict[tuple[str, Category], tuple[Severity, str]] = {}
        for finding in report.findings:
            key = (finding.recipient, finding.category)
            status = _status(finding)
            current = cells.get(key)
            if current is None or (status == "open", finding.severity) > (
                current[1] == "open",
                current[0],
            ):
                cells[key] = (finding.severity, status)
        lines += [
            "### Data-flow map",
            "",
            "| Recipient | Party | " + " | ".join(md(c.value, 30) for c in categories) + " |",
            "|---|---|" + "---|" * len(categories),
        ]
        for flow in report.flows:
            if not any((flow.recipient, c) in cells for c in categories):
                continue
            row = []
            for category in categories:
                cell = cells.get((flow.recipient, category))
                if cell is None:
                    row.append("")
                else:
                    severity, status = cell
                    row.append(_MARK[severity] + ("" if status == "open" else f" ({status})"))
            name = code(flow.recipient, 60) + (f" {md(flow.label, 40)}" if flow.label else "")
            party = "first" if flow.first_party else "**third**"
            lines.append(f"| {name} | {party} | " + " | ".join(row) + " |")
        lines.append("")
    third = [flow for flow in report.flows if not flow.first_party]
    if third:
        lines += [
            "### Third-party recipients",
            "",
            "| Recipient | Requests | Personal data found in request content |",
            "|---|---:|---|",
        ]
        for flow in third:
            found = sorted(
                {
                    f.category.value
                    for f in report.findings
                    if f.recipient == flow.recipient and f.channel != "connection"
                }
            )
            name = code(flow.recipient, 60) + (f" {md(flow.label, 40)}" if flow.label else "")
            lines.append(f"| {name} | {flow.requests} | {', '.join(md(c, 30) for c in found) or 'none'} |")
        gated = any(f.channel == "connection" for f in report.findings)
        lines += [
            "",
            "_Each third party also receives the visitor's IP address and browser details with every request. "
            + (
                "These connections are reported as `PFI-THIRD-PARTY-CONNECTION` findings._"
                if gated
                else "Enable `PFI-THIRD-PARTY-CONNECTION` to gate on this._"
            ),
            "",
        ]
    if report.findings:
        lines += [
            "### Findings",
            "",
            "| Severity | Rule | Finding | Channel | Evidence |",
            "|---|---|---|---|---|",
        ]
        for finding in report.findings[:max_findings]:
            evidence = finding.evidence[0] if finding.evidence else None
            where = (
                f"{code(evidence.har, 40)} entry {evidence.entry}, {code(evidence.key, 60)}, "
                f"{md(evidence.variant, 40)}, {code(evidence.preview, 30)}"
                if evidence
                else ""
            )
            status = _status(finding)
            shown = finding.severity.label + ("" if status == "open" else f" ({status})")
            lines.append(
                f"| {shown} | {md(finding.rule_id, 40)} | {md(finding.title, 120)} "
                f"| {md(finding.channel, 20)} | {where} |"
            )
        if len(report.findings) > max_findings:
            lines.append(f"\n_{len(report.findings) - max_findings} more findings in the JSON/SARIF reports._")
        lines.append("")
    if report.gaps:
        lines += ["### Coverage gaps", ""]
        for gap in report.gaps[:30]:
            tag = "blocking" if gap.blocking else "note"
            where = f" ({code(gap.path, 80)})" if gap.path else ""
            lines.append(f"- **{tag}** {md(gap.code, 40)}: {md(gap.message, 300)}{where}")
        lines.append("")
    lines.append(
        "_Values are masked and fingerprinted; no raw personal data is included. This is technical "
        "evidence for a privacy review, not legal advice._"
    )
    return "\n".join(lines) + "\n"


def to_text(report: Report, max_findings: int = 15) -> str:
    counts = severity_counts(report.findings)
    third = [f for f in report.flows if not f.first_party]
    lines = [
        f"Decision: {report.decision.value.upper()}",
        *[f"  - {clean_text(reason, 300)}" for reason in report.decision_reasons],
        f"Requests: {report.requests} | recipients: {len(report.flows)} ({len(third)} third-party) "
        f"| personas: {report.personas}",
        "Findings: " + ", ".join(f"{label} {count}" for label, count in counts.items()),
    ]
    if third:
        shown = ", ".join(f"{clean_text(f.recipient, 60)} ({f.requests})" for f in third[:10])
        lines.append(f"Third parties: {shown}" + (f" and {len(third) - 10} more" if len(third) > 10 else ""))
    for finding in report.findings[:max_findings]:
        status = _status(finding)
        lines.append(
            f"  [{finding.severity.label.upper():8}] {finding.rule_id:20} {clean_text(finding.title, 70)} "
            f"via {finding.channel}" + ("" if status == "open" else f" ({status})")
        )
    if len(report.findings) > max_findings:
        lines.append(f"  ... {len(report.findings) - max_findings} more (see --json/--sarif)")
    blocking = [g for g in report.gaps if g.blocking]
    if blocking:
        lines.append(f"Blocking coverage gaps: {len(blocking)}")
        lines += [f"  - {clean_text(g.code, 40)}: {clean_text(g.message, 200)}" for g in blocking[:10]]
    return "\n".join(lines) + "\n"


def _pattern(needles: set[str]) -> re.Pattern[str] | None:
    usable = sorted((n for n in needles if len(n) >= 4), key=len, reverse=True)
    return re.compile("|".join(re.escape(n) for n in usable), re.IGNORECASE) if usable else None


REDACTED_BODY = "[REDACTED: encoded or binary content removed by privacy-flow-inspector]"


def _opaque_body(post: dict[str, Any], headers: object) -> bool:
    text = post.get("text")
    if post.get("encoding") == "base64" or not isinstance(text, str):
        return True
    encoded = isinstance(headers, list) and any(
        isinstance(h, dict)
        and str(h.get("name", "")).lower() == "content-encoding"
        and str(h.get("value", "")).strip().lower() not in ("", "identity")
        for h in headers
    )
    return encoded or text[:2] in ("\x1f\x8b", "\x78\x9c", "\x78\x01", "\x78\xda") or "\ufffd" in text


def redact_har(source: Path, target: Path, needles: set[str]) -> None:
    """Write a copy of the HAR without detected values, credentials, cookies or response bodies."""
    document = json.loads(source.read_text(encoding="utf-8-sig"))
    pattern = _pattern(needles)

    def scrub(value: object) -> object:
        if isinstance(value, str) and pattern is not None:
            return pattern.sub(REDACTED, value)
        return value

    def scrub_pairs(items: object, always: bool = False) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if isinstance(item, dict) and "value" in item:
                sensitive = always or str(item.get("name", "")).lower() in _SENSITIVE_HEADERS
                item["value"] = REDACTED if sensitive else scrub(item["value"])

    log = document.get("log", {}) if isinstance(document, dict) else {}
    for page in log.get("pages", []) or []:
        if isinstance(page, dict):
            page["title"] = scrub(page.get("title", ""))
    for entry in log.get("entries", []) or []:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if isinstance(request, dict):
            request["url"] = scrub(request.get("url", ""))
            scrub_pairs(request.get("headers"))
            scrub_pairs(request.get("queryString"))
            scrub_pairs(request.get("cookies"), always=True)
            post = request.get("postData")
            if isinstance(post, dict):
                if "text" in post and _opaque_body(post, request.get("headers")):
                    # Text search cannot see inside compressed or base64 data, so the body is removed.
                    post["text"] = REDACTED_BODY
                    post.pop("encoding", None)
                elif "text" in post:
                    post["text"] = scrub(post["text"])
                scrub_pairs(post.get("params"))
        messages = entry.get("_webSocketMessages")
        if isinstance(messages, list):
            for message in messages:
                if not isinstance(message, dict) or "data" not in message:
                    continue
                if message.get("type") == "send" and message.get("opcode") != 2:
                    message["data"] = scrub(message["data"])
                else:
                    message["data"] = REDACTED_BODY
        response = entry.get("response")
        if isinstance(response, dict):
            scrub_pairs(response.get("headers"))
            scrub_pairs(response.get("cookies"), always=True)
            response["redirectURL"] = scrub(response.get("redirectURL", ""))
            content = response.get("content")
            if isinstance(content, dict) and "text" in content:
                content.pop("text")
                content.pop("encoding", None)
                content["comment"] = "Response body removed by privacy-flow-inspector."
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    lowered = text.lower()
    leftovers = [n for n in needles if len(n) >= 4 and n.lower() in lowered]
    if leftovers:
        raise InspectorError(f"redaction self-check failed for {source.name}; no file written")
    write_atomic(target, text)
