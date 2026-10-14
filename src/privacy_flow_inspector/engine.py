"""Run detectors over every request and aggregate the results into data flows."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, quote

from privacy_flow_inspector import __version__
from privacy_flow_inspector.detectors import DETECTORS, Match, PersonaMatcher, detect
from privacy_flow_inspector.extract import carriers
from privacy_flow_inspector.har import Limits, Request, load_har
from privacy_flow_inspector.model import (
    BASE_SEVERITY,
    SPECIAL_CATEGORIES,
    Category,
    Evidence,
    Finding,
    Fingerprinter,
    Flow,
    Gap,
    Report,
    Severity,
    clean_text,
    mask,
)
from privacy_flow_inspector.policy import Config, apply_policy, decide
from privacy_flow_inspector.recipients import Recipients, site_of

MAX_EVIDENCE = 5


@dataclass
class Result:
    report: Report
    # Per input HAR: strings that must not survive in a redacted copy.
    redactions: dict[str, set[str]] = field(default_factory=dict)


def severity_for(category: Category, first_party: bool, channel: str, scheme: str) -> Severity:
    score = BASE_SEVERITY[category]
    if first_party:
        score -= 2
    if channel in ("query", "url-path", "referer"):
        score += 1
    if scheme == "http":
        score += 1
    return Severity(max(0, min(4, score)))


def _redacted_url(request: Request, secret_segments: set[int]) -> str:
    segments = [s for s in request.parts.path.split("/") if s]
    path = "/".join("[redacted]" if i in secret_segments else s for i, s in enumerate(segments))
    url = f"{request.parts.scheme}://{request.host}/{path}"
    keys = [name for name, _ in parse_qsl(request.parts.query, keep_blank_values=True)]
    if keys:
        url += "?" + "&".join(f"{clean_text(k, 40)}=..." for k in dict.fromkeys(keys))
    return clean_text(url, 300)


def _message(match: Match, finding_first_party: bool, channel: str, scheme: str, recipient: str) -> str:
    parts = [
        f"{DETECTORS[match.detector].title if match.detector != 'PFI-PERSONA' else match.label} "
        f"({match.category.value}) was sent to {'first-party' if finding_first_party else 'third-party'} "
        f"recipient {recipient} in the request {channel}."
    ]
    if match.variant not in ("plain", "lowercase", "field value"):
        parts.append(f"It was transmitted as {match.variant}.")
    if any(h in match.variant for h in ("md5", "sha1", "sha256", "base64")):
        parts.append("Hashed or encoded identifiers are still personal data (pseudonymised).")
    if match.category in SPECIAL_CATEGORIES:
        parts.append("Health data is a special category under GDPR Article 9 and needs an explicit legal basis.")
    if channel in ("query", "url-path", "referer"):
        parts.append("Values in URLs end up in server logs, proxies and Referer headers.")
    if scheme == "http":
        parts.append("The request was not encrypted (plain HTTP).")
    if not finding_first_party:
        parts.append("Confirm a legal basis and a data processing agreement, or stop sending it.")
    return " ".join(parts)


def inspect(
    paths: list[Path],
    config: Config,
    limits: Limits | None = None,
    now: datetime | None = None,
    fingerprint_key: bytes | None = None,
) -> Result:
    limits = limits or Limits()
    scanned_at = now or datetime.now(UTC)
    fingerprint = Fingerprinter(fingerprint_key or secrets.token_bytes(32))
    gaps: list[Gap] = []
    requests: list[Request] = []
    displays: list[str] = []
    for path in paths:
        display = path.name
        displays.append(display)
        loaded, har_gaps = load_har(path, display, limits)
        requests.extend(loaded)
        gaps.extend(har_gaps)

    first_party = list(config.first_party)
    if not first_party and requests:
        document = next((r for r in requests if r.resource_type == "document"), requests[0])
        first_party = [site_of(document.host)]
        gaps.append(
            Gap(
                "first-party-inferred",
                f"First party inferred as {first_party[0]} from the first page request; set "
                "first_party.domains in the config to make this explicit.",
                blocking=False,
            )
        )
    recipients = Recipients(first_party, config.labels)
    matcher = PersonaMatcher(list(config.personas))
    if not config.personas:
        gaps.append(
            Gap(
                "no-persona",
                "No test persona configured; only pattern, checksum and field-name detectors ran. "
                "Add [[persona]] values used in the recorded session for exact matching.",
                blocking=False,
            )
        )
    redactions: dict[str, set[str]] = {d: set(matcher.all_needles()) for d in displays}
    findings: dict[tuple[str, str, str, str, str], Finding] = {}
    flows: dict[str, Flow] = {}

    for request in requests:
        site = site_of(request.host)
        is_first = recipients.is_first_party(request.host)
        flow = flows.setdefault(site, Flow(site, recipients.label(request.host), is_first))
        flow.requests += 1
        items, truncated = carriers(request)
        if truncated:
            gaps.append(
                Gap(
                    "carrier-limit",
                    f"Entry {request.index} had too many values; some were skipped.",
                    request.har,
                )
            )
        hits: list[tuple[str, str, Match, str]] = []
        secret_segments: set[int] = set()
        for carrier in items:
            if carrier.container:
                continue
            persona_hits = [] if "PFI-PERSONA" in config.disabled else matcher.match(carrier.value)
            covered = {m.category for m in persona_hits}
            generic = [m for m in detect(carrier, config.disabled) if m.category not in covered]
            for match in persona_hits + generic:
                channel = carrier.channel
                if channel == "header" and carrier.key.lower().startswith("referer"):
                    channel = "referer"
                hits.append(
                    (
                        channel,
                        carrier.key,
                        match,
                        carrier.origin if carrier.encoded else match.value,
                    )
                )
                if carrier.channel == "url-path":
                    secret_segments.add(int(carrier.key.split("[")[1].split("]")[0]))
        if not hits:
            continue
        url = _redacted_url(request, secret_segments)
        scheme = request.parts.scheme.lower()
        for channel, key, match, secret in hits:
            redactions[request.har].update({secret, match.value, quote(match.value, safe="")})
            severity = severity_for(match.category, is_first, channel, scheme)
            flow.categories[match.category] = max(flow.categories.get(match.category, Severity.INFO), severity)
            identity = (match.detector, match.label, site, channel, match.category.value)
            finding = findings.get(identity)
            if finding is None:
                title = f"{match.label} sent to {site}"
                finding = Finding(
                    rule_id=match.detector,
                    title=title,
                    category=match.category,
                    confidence=DETECTORS[match.detector].confidence,
                    severity=severity,
                    recipient=site,
                    recipient_label=flow.label,
                    first_party=is_first,
                    channel=channel,
                    message=_message(match, is_first, channel, scheme, site),
                )
                findings[identity] = finding
            elif severity > finding.severity:
                finding.severity = severity
                finding.message = _message(match, is_first, channel, scheme, site)
            finding.occurrences += 1
            if len(finding.evidence) < MAX_EVIDENCE:
                finding.evidence.append(
                    Evidence(
                        har=request.har,
                        entry=request.index,
                        method=request.method,
                        url=url,
                        channel=channel,
                        key=clean_text(key, 120),
                        variant=match.variant,
                        preview=mask(match.value),
                        fingerprint=fingerprint(match.value),
                        har_line=request.line,
                        har_column=request.column,
                        initiator=clean_text(request.initiator, 300) if request.initiator else None,
                    )
                )

    ordered = sorted(
        findings.values(),
        key=lambda f: (-int(f.severity), f.first_party, f.recipient, f.rule_id, f.channel),
    )
    gaps.extend(apply_policy(ordered, config, scanned_at.date()))
    decision, reasons = decide(ordered, gaps, config)
    report = Report(
        tool_version=__version__,
        inputs=displays,
        scanned_at=scanned_at,
        requests=len(requests),
        findings=ordered,
        flows=sorted(
            flows.values(),
            key=lambda f: (f.first_party, -max(f.categories.values(), default=-1), f.recipient),
        ),
        gaps=gaps,
        first_party=recipients.first_party,
        personas=len(config.personas),
        decision=decision,
        decision_reasons=reasons,
    )
    return Result(report, redactions)
