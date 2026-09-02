from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import Finding, ScanReport
from .rules import RULES

TEXT_SUFFIXES = {
    ".cjs", ".env", ".html", ".js", ".json", ".md", ".mjs", ".py", ".toml",
    ".ts", ".tsx", ".yaml", ".yml",
}
IGNORED_PARTS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}
MAX_FILE_BYTES = 1_000_000


def _iter_files(target: Path):
    candidates = [target] if target.is_file() else target.rglob("*")
    for path in candidates:
        if not path.is_file() or any(part in IGNORED_PARTS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > MAX_FILE_BYTES:
            continue
        yield path


def _fingerprint(rule_id: str, path: str, evidence: str) -> str:
    return hashlib.sha256(f"{rule_id}\0{path}\0{evidence}".encode()).hexdigest()[:20]


def scan_path(target: str | Path) -> ScanReport:
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    findings: list[Finding] = []
    digest = hashlib.sha256()
    files_scanned = 0
    for path in sorted(_iter_files(root)):
        raw = path.read_bytes()
        digest.update(str(path.relative_to(root) if root.is_dir() else path.name).encode())
        digest.update(raw)
        text = raw.decode("utf-8", errors="replace")
        files_scanned += 1
        relative = str(path.relative_to(root) if root.is_dir() else path.name)
        for rule in RULES:
            for match in rule.pattern.finditer(text):
                evidence = " ".join(match.group(0).split())[:180]
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        message=rule.message,
                        path=relative,
                        line=text.count("\n", 0, match.start()) + 1,
                        evidence=evidence,
                        remediation=rule.remediation,
                        confidence=rule.confidence,
                        fingerprint=_fingerprint(rule.id, relative, evidence),
                    )
                )
    return ScanReport(
        target=str(root),
        target_digest=digest.hexdigest(),
        findings=findings,
        files_scanned=files_scanned,
    )


def compare_reports(baseline: dict, current: ScanReport) -> dict:
    old = {item["fingerprint"] for item in baseline.get("findings", [])}
    new = {item.fingerprint for item in current.findings}
    return {
        "new": sorted(new - old),
        "resolved": sorted(old - new),
        "unchanged": sorted(old & new),
        "rug_pull_detected": bool(new - old),
    }


def load_report(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

