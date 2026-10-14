"""Who receives the data: registrable domains, first-party scope and recognisable vendors."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from publicsuffixlist import PublicSuffixList

# Informational labels for widely known services; matching never depends on this list.
KNOWN_VENDORS = {
    "google-analytics.com": "Google Analytics",
    "analytics.google.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google Ads (DoubleClick)",
    "googlesyndication.com": "Google AdSense",
    "facebook.com": "Meta",
    "facebook.net": "Meta Pixel",
    "linkedin.com": "LinkedIn",
    "licdn.com": "LinkedIn",
    "tiktok.com": "TikTok",
    "hotjar.com": "Hotjar",
    "hotjar.io": "Hotjar",
    "clarity.ms": "Microsoft Clarity",
    "bing.com": "Microsoft Advertising",
    "segment.io": "Segment",
    "segment.com": "Segment",
    "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude",
    "fullstory.com": "FullStory",
    "intercom.io": "Intercom",
    "sentry.io": "Sentry",
    "nr-data.net": "New Relic",
    "newrelic.com": "New Relic",
    "datadoghq.com": "Datadog",
    "datadoghq.eu": "Datadog",
}


@lru_cache(maxsize=1)
def _psl() -> PublicSuffixList:
    return PublicSuffixList()


def site_of(host: str) -> str:
    """Registrable domain (eTLD+1), or the host itself for IPs and single-label names."""
    host = host.lower().strip(".").strip("[]")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    site = _psl().privatesuffix(host)
    return str(site) if site else host


class Recipients:
    def __init__(self, first_party: list[str], labels: dict[str, str] | None = None) -> None:
        self.first_party = sorted({site_of(domain) for domain in first_party if domain.strip()})
        self._labels = {**KNOWN_VENDORS, **(labels or {})}

    def is_first_party(self, host: str) -> bool:
        return site_of(host) in self.first_party

    def label(self, host: str) -> str | None:
        site = site_of(host)
        host = host.lower()
        for candidate in (host, site):
            if candidate in self._labels:
                return self._labels[candidate]
        return None
