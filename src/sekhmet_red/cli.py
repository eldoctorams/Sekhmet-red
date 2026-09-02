from __future__ import annotations

import argparse
import json
import sys

from .reporters import write_json, write_sarif
from .scanner import compare_reports, load_report, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sekhmet", description="SEKHMET RED MCP and agent-tool security scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan source, manifests and tool metadata")
    scan.add_argument("target")
    scan.add_argument("--json", dest="json_output")
    scan.add_argument("--sarif", dest="sarif_output")
    scan.add_argument("--baseline")
    scan.add_argument("--fail-on", choices=("critical", "high", "medium", "never"), default="high")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = scan_path(args.target)
    if args.json_output:
        write_json(report, args.json_output)
    if args.sarif_output:
        write_sarif(report, args.sarif_output)
    payload = report.to_dict()
    if args.baseline:
        payload["baseline_comparison"] = compare_reports(load_report(args.baseline), report)
    print(json.dumps(payload, indent=2))
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = levels.get(args.fail_on, 99)
    return int(any(levels[item.severity.value] >= threshold for item in report.findings))


if __name__ == "__main__":
    sys.exit(main())

