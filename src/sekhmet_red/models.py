from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 12,
    Severity.LOW: 5,
    Severity.INFO: 0,
}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    path: str
    line: int
    evidence: str
    remediation: str
    confidence: float
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass(slots=True)
class ScanReport:
    target: str
    target_digest: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    engine: str = "sekhmet-red/0.1.0"

    @property
    def risk_score(self) -> int:
        penalty = sum(SEVERITY_WEIGHT[item.severity] for item in self.findings)
        return max(0, 100 - penalty)

    @property
    def verdict(self) -> str:
        if any(item.severity is Severity.CRITICAL for item in self.findings):
            return "BLOCK"
        if any(item.severity is Severity.HIGH for item in self.findings):
            return "REVIEW"
        return "PASS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "https://sekhmet.red/schema/report/v1",
            "engine": self.engine,
            "generated_at": self.generated_at,
            "target": self.target,
            "target_digest": self.target_digest,
            "files_scanned": self.files_scanned,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "summary": {
                severity.value: sum(
                    item.severity is severity for item in self.findings
                )
                for severity in Severity
            },
            "findings": [item.to_dict() for item in self.findings],
        }

