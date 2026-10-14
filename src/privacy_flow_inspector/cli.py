from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from privacy_flow_inspector import __version__, output
from privacy_flow_inspector.detectors import DETECTORS
from privacy_flow_inspector.engine import inspect
from privacy_flow_inspector.model import Decision, InspectorError, clean_text
from privacy_flow_inspector.policy import load_config

EXIT_OK = 0
EXIT_GATE = 1
EXIT_USAGE = 2
_FAIL_LEVELS = {
    "reject": {Decision.REJECT},
    "review": {Decision.REJECT, Decision.REVIEW},
    "never": set(),
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privacy-flow-inspector",
        description="Find personal data that leaves the browser in recorded HAR traffic. Works offline.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="inspect one or more HAR files")
    scan.add_argument("har", nargs="+", type=Path, help="HAR files (Chrome, Firefox, Playwright, ...)")
    scan.add_argument("--config", type=Path, help="TOML config with first party, personas and policy")
    scan.add_argument("--json", type=Path, metavar="FILE", help="write the full JSON report")
    scan.add_argument("--sarif", type=Path, metavar="FILE", help="write SARIF 2.1.0")
    scan.add_argument("--markdown", type=Path, metavar="FILE", help="write a Markdown summary")
    scan.add_argument(
        "--redact-dir",
        type=Path,
        metavar="DIR",
        help="write <name>.redacted.har copies without detected values, credentials or response bodies",
    )
    scan.add_argument(
        "--fail-on",
        choices=sorted(_FAIL_LEVELS),
        default="reject",
        help="decision that produces exit status 1 (default: %(default)s)",
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="do not print the summary")
    commands.add_parser("rules", help="list detectors")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
    if args.command == "rules":
        for detector in DETECTORS.values():
            category = detector.category.value if detector.category else "(persona)"
            print(f"{detector.id:22} {category:18} {detector.confidence:10} {detector.title}")
        return EXIT_OK
    try:
        names = [path.name for path in args.har]
        if len(set(names)) != len(names):
            raise InspectorError("HAR file names must be unique")
        for path in args.har:
            if not path.is_file():
                raise InspectorError(f"HAR file not found: {path}")
        config = load_config(args.config)
        salt = os.environ.get("PFI_FINGERPRINT_KEY")
        result = inspect(args.har, config, fingerprint_key=salt.encode() if salt else None)
        report = result.report
        cwd = Path.cwd()
        prefixes = {path.name: output.har_prefix(path, cwd) for path in args.har}
        renders: tuple[tuple[Path | None, Callable[[], str]], ...] = (
            (args.json, lambda: output.to_json(report)),
            (args.sarif, lambda: output.to_sarif(report, prefixes)),
            (args.markdown, lambda: output.to_markdown(report)),
        )
        for path, render in renders:
            if path is not None:
                output.write_atomic(path, render())
        if args.redact_dir is not None:
            for har in args.har:
                target = args.redact_dir / f"{har.stem}.redacted.har"
                output.redact_har(har, target, result.redactions.get(har.name, set()))
    except (InspectorError, OSError) as error:
        print(f"privacy-flow-inspector: error: {clean_text(str(error), 500)}", file=sys.stderr)
        return EXIT_USAGE
    if not args.quiet:
        sys.stdout.write(output.to_text(report))
    return EXIT_GATE if report.decision in _FAIL_LEVELS[args.fail_on] else EXIT_OK
