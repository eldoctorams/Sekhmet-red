from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    confidence: float


RULES = (
    Rule(
        "SR-PI-001",
        "Embedded instruction override",
        Severity.HIGH,
        "prompt-injection",
        re.compile(r"(?i)(ignore|disregard|override).{0,35}(previous|system|developer).{0,20}(instruction|prompt)"),
        "Content appears to instruct an agent to override trusted instructions.",
        "Remove executable instructions from untrusted tool metadata and enforce instruction/data separation.",
        0.94,
    ),
    Rule(
        "SR-PI-002",
        "Secret exfiltration instruction",
        Severity.CRITICAL,
        "data-exfiltration",
        re.compile(r"(?i)(send|upload|post|exfiltrat).{0,45}(secret|token|api.?key|credential|environment variable)"),
        "Content requests transmission of secrets or credentials.",
        "Block the tool, rotate potentially exposed credentials, and restrict egress destinations.",
        0.97,
    ),
    Rule(
        "SR-SEC-001",
        "Hardcoded credential material",
        Severity.CRITICAL,
        "secrets",
        re.compile(r"(?i)(api[_-]?key|secret|access[_-]?token|password)\s*[=:]\s*['\"][A-Za-z0-9_\-/.+=]{12,}['\"]"),
        "A probable secret is hardcoded in source or configuration.",
        "Revoke the credential, move it to a secret manager, and add secret scanning to CI.",
        0.96,
    ),
    Rule(
        "SR-EXEC-001",
        "Dynamic shell execution",
        Severity.HIGH,
        "code-execution",
        re.compile(r"(?i)(shell\s*=\s*true|os\.system\s*\(|eval\s*\(|exec\s*\(|child_process\.exec\s*\()"),
        "The implementation contains a high-risk dynamic execution primitive.",
        "Replace shell execution with allowlisted argument arrays and validate all user-controlled values.",
        0.90,
    ),
    Rule(
        "SR-FS-001",
        "Unbounded filesystem access",
        Severity.HIGH,
        "over-permission",
        re.compile(r"(?i)(read|write|delete).{0,30}(any file|entire filesystem|all files|arbitrary path|root directory)"),
        "Tool metadata claims broad or arbitrary filesystem access.",
        "Constrain access to an explicit workspace and enforce canonical path checks.",
        0.86,
    ),
    Rule(
        "SR-NET-001",
        "Unrestricted outbound request",
        Severity.MEDIUM,
        "network-egress",
        re.compile(r"(?i)(requests\.(get|post)|fetch\s*\(|httpx\.(get|post)).{0,120}(url|endpoint|target)"),
        "Network access may accept a user-controlled destination.",
        "Apply scheme, hostname, IP-range and redirect allowlists before making outbound requests.",
        0.73,
    ),
    Rule(
        "SR-SUP-001",
        "Floating package execution",
        Severity.MEDIUM,
        "supply-chain",
        re.compile(r"(?i)(npx|uvx|pipx\s+run|docker\s+run)\s+(?![^\n]*(@|==|:)[0-9])[^\n]+"),
        "A package or image may execute without an immutable version pin.",
        "Pin a reviewed version or digest and verify its provenance before execution.",
        0.82,
    ),
    Rule(
        "SR-DESER-001",
        "Unsafe deserialization",
        Severity.CRITICAL,
        "deserialization",
        re.compile(r"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\([^\n]*Loader\s*=\s*yaml\.Loader|marshal\.loads?\s*\()"),
        "Untrusted input may reach an unsafe deserialization primitive.",
        "Use safe formats and safe loaders; never deserialize attacker-controlled native objects.",
        0.95,
    ),
)

