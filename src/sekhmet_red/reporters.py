from __future__ import annotations

import json
from pathlib import Path

from .models import ScanReport


def write_json(report: ScanReport, output: str | Path) -> None:
    Path(output).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")


def write_sarif(report: ScanReport, output: str | Path) -> None:
    rules = {}
    results = []
    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title.replace(" ", "_"),
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation},
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning"}.get(
                    finding.severity.value, "note"
                ),
                "message": {"text": finding.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}, "region": {"startLine": finding.line}}}],
                "fingerprints": {"sekhmetRed/v1": finding.fingerprint},
            }
        )
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "SEKHMET RED", "version": "0.1.0", "rules": list(rules.values())}}, "results": results}],
    }
    Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")

