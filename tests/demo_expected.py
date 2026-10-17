"""Data flows the fictional demo must produce, shared by the tests and the CI recording checks."""

EXPECTED = {
    ("PFI-PERSONA", "legacy-ads.test", "query", "critical", "open"),
    ("PFI-PRECISE-LOCATION", "geo-widgets.test", "query", "high", "open"),
    ("PFI-PERSONA", "pixel-tracker.test", "query", "high", "open"),
    ("PFI-DE-KVNR", "session-cam.test", "body", "high", "open"),
    ("PFI-HEALTH-FIELD", "session-cam.test", "body", "high", "open"),
    ("PFI-PERSONA", "analytics-vendor.test", "body", "medium", "open"),
    ("PFI-PERSONA", "chat-widget.test", "websocket", "medium", "open"),
    ("PFI-PERSONA", "replay-vendor.test", "body", "medium", "open"),
    ("PFI-IBAN", "payments-processor.test", "body", "high", "allowed"),
    ("PFI-PERSONA", "payments-processor.test", "body", "medium", "allowed"),
    ("PFI-DE-KVNR", "shop.example", "body", "low", "open"),
    ("PFI-HEALTH-FIELD", "shop.example", "body", "low", "open"),
    ("PFI-PERSONA", "shop.example", "body", "info", "open"),
    ("PFI-PERSONA", "shop.example", "header", "info", "open"),
}
