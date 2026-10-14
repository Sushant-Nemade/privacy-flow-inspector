"""Inspector configuration: first party, test personas, approved recipients, waivers and the gate."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from privacy_flow_inspector.detectors import DETECTORS, OPT_IN, Persona
from privacy_flow_inspector.model import Category, Decision, Finding, Gap, InspectorError, Severity
from privacy_flow_inspector.recipients import site_of


class ConfigError(InspectorError):
    pass


@dataclass(frozen=True)
class Allowance:
    recipient: str
    categories: frozenset[Category]
    reason: str


@dataclass(frozen=True)
class Waiver:
    id: str
    reason: str
    expires: date
    recipient: str | None = None


@dataclass(frozen=True)
class Config:
    reject_at: Severity = Severity.HIGH
    review_at: Severity = Severity.LOW
    first_party: tuple[str, ...] = ()
    personas: tuple[Persona, ...] = ()
    allow: tuple[Allowance, ...] = ()
    waivers: tuple[Waiver, ...] = ()
    disabled: frozenset[str] = frozenset()
    enabled: frozenset[str] = frozenset()
    labels: dict[str, str] = field(default_factory=dict)


def _table(data: dict[str, Any], key: str, allowed: set[str]) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a table")
    unknown = set(value) - allowed
    if unknown:
        raise ConfigError(f"unknown keys in [{key}]: {', '.join(sorted(unknown))}")
    return value


def _array(data: dict[str, Any], key: str, allowed: set[str]) -> list[dict[str, Any]]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConfigError(f"{key} must be an array of tables ([[{key}]])")
    for index, item in enumerate(value, start=1):
        unknown = set(item) - allowed
        if unknown:
            raise ConfigError(f"{key} {index}: unknown keys {', '.join(sorted(unknown))}")
    return value


def _string(item: dict[str, Any], key: str, where: str, minimum: int = 1) -> str:
    value = item.get(key)
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise ConfigError(f"{where}: '{key}' must be a string of at least {minimum} characters")
    return value.strip()


def _severity(value: object, where: str) -> Severity:
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be a severity string")
    try:
        return Severity.parse(value)
    except ValueError as error:
        raise ConfigError(f"{where}: {error}") from None


def _category(value: object, where: str) -> Category:
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be a category string")
    try:
        return Category.parse(value)
    except ValueError as error:
        raise ConfigError(f"{where}: {error}") from None


def load_config(path: Path | None) -> Config:
    if path is None:
        return Config()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ConfigError(f"cannot read config {path}: {error.strerror}") from None
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"invalid config TOML: {error}") from None
    unknown = set(data) - {
        "version",
        "gate",
        "first_party",
        "persona",
        "allow",
        "waivers",
        "detectors",
        "labels",
    }
    if unknown:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(unknown))}")
    if data.get("version", 1) != 1:
        raise ConfigError("unsupported config version (expected 1)")

    gate = _table(data, "gate", {"reject_at", "review_at"})
    reject_at = _severity(gate.get("reject_at", "high"), "gate.reject_at")
    review_at = _severity(gate.get("review_at", "low"), "gate.review_at")
    if review_at > reject_at:
        raise ConfigError("gate.review_at must not be higher than gate.reject_at")

    first = _table(data, "first_party", {"domains"})
    domains = first.get("domains", [])
    if not isinstance(domains, list) or not all(isinstance(d, str) and d.strip() for d in domains):
        raise ConfigError("first_party.domains must be a list of domain names")

    personas = []
    for index, item in enumerate(_array(data, "persona", {"label", "value", "category"}), start=1):
        where = f"persona {index}"
        personas.append(
            Persona(
                _string(item, "label", where),
                _string(item, "value", where, minimum=5),
                _category(item.get("category", "contact"), f"{where}.category"),
            )
        )

    allow = []
    for index, item in enumerate(_array(data, "allow", {"recipient", "categories", "reason"}), start=1):
        where = f"allow {index}"
        categories = item.get("categories")
        if not isinstance(categories, list) or not categories:
            raise ConfigError(f"{where}: 'categories' must be a non-empty list")
        allow.append(
            Allowance(
                site_of(_string(item, "recipient", where)),
                frozenset(_category(c, f"{where}.categories") for c in categories),
                _string(item, "reason", where, minimum=10),
            )
        )

    waivers = []
    for index, item in enumerate(_array(data, "waivers", {"id", "recipient", "reason", "expires"}), start=1):
        where = f"waiver {index}"
        expires = item.get("expires")
        if not isinstance(expires, date) or hasattr(expires, "hour"):
            raise ConfigError(f"{where}: 'expires' must be a TOML date like 2026-12-31")
        waiver_id = _string(item, "id", where)
        if waiver_id not in DETECTORS:
            raise ConfigError(f"{where}: unknown rule id {waiver_id!r}")
        recipient = item.get("recipient")
        if recipient is not None and not isinstance(recipient, str):
            raise ConfigError(f"{where}: 'recipient' must be a domain")
        waivers.append(
            Waiver(
                waiver_id,
                _string(item, "reason", where, minimum=10),
                expires,
                site_of(recipient) if recipient else None,
            )
        )

    detectors = _table(data, "detectors", {"disabled", "enabled"})
    disabled = detectors.get("disabled", [])
    if not isinstance(disabled, list) or not all(isinstance(d, str) for d in disabled):
        raise ConfigError("detectors.disabled must be a list of rule ids")
    unknown_rules = set(disabled) - set(DETECTORS)
    if unknown_rules:
        raise ConfigError(f"unknown rule ids in detectors.disabled: {', '.join(sorted(unknown_rules))}")
    enabled = detectors.get("enabled", [])
    if not isinstance(enabled, list) or not all(isinstance(d, str) for d in enabled):
        raise ConfigError("detectors.enabled must be a list of rule ids")
    not_opt_in = set(enabled) - OPT_IN
    if not_opt_in:
        raise ConfigError(
            f"detectors.enabled accepts only opt-in rules ({', '.join(sorted(OPT_IN))}), "
            f"not: {', '.join(sorted(not_opt_in))}"
        )

    labels = data.get("labels", {})
    if not isinstance(labels, dict) or not all(isinstance(v, str) for v in labels.values()):
        raise ConfigError("[labels] must map domains to names")

    return Config(
        reject_at=reject_at,
        review_at=review_at,
        first_party=tuple(domains),
        personas=tuple(personas),
        allow=tuple(allow),
        waivers=tuple(waivers),
        disabled=frozenset(disabled),
        enabled=frozenset(enabled) - frozenset(disabled),
        labels={site_of(k): v for k, v in labels.items()},
    )


def apply_policy(findings: list[Finding], config: Config, today: date) -> list[Gap]:
    gaps: list[Gap] = []
    used: set[int] = set()
    for finding in findings:
        for allowance in config.allow:
            if allowance.recipient == finding.recipient and finding.category in allowance.categories:
                finding.allowed_reason = allowance.reason
                break
        if finding.allowed_reason:
            continue
        for index, waiver in enumerate(config.waivers):
            if waiver.id == finding.rule_id and waiver.recipient in (None, finding.recipient):
                used.add(index)
                if waiver.expires >= today:
                    finding.waiver_reason = f"{waiver.reason} (expires {waiver.expires})"
                    break
    for index, waiver in enumerate(config.waivers):
        if waiver.expires < today:
            gaps.append(
                Gap(
                    "waiver-expired",
                    f"Waiver for {waiver.id} expired on {waiver.expires}.",
                    blocking=False,
                )
            )
        elif index not in used:
            gaps.append(Gap("waiver-unused", f"Waiver for {waiver.id} matched no finding.", blocking=False))
    return gaps


def decide(findings: list[Finding], gaps: list[Gap], config: Config) -> tuple[Decision, list[str]]:
    active = [f for f in findings if f.counted]
    at_reject = [f for f in active if f.severity >= config.reject_at]
    at_review = [f for f in active if config.review_at <= f.severity < config.reject_at]
    blocking = [g for g in gaps if g.blocking]
    reasons: list[str] = []
    if at_reject:
        reasons.append(f"{len(at_reject)} data flow(s) at or above {config.reject_at.label}.")
    if at_review:
        reasons.append(f"{len(at_review)} data flow(s) between {config.review_at.label} and {config.reject_at.label}.")
    if blocking:
        reasons.append(f"{len(blocking)} coverage gap(s): " + "; ".join(sorted({g.code for g in blocking})) + ".")
    if at_reject:
        return Decision.REJECT, reasons
    if at_review or blocking:
        return Decision.REVIEW, reasons
    return Decision.APPROVE, ["No unapproved personal-data flows and no blocking coverage gaps."]
