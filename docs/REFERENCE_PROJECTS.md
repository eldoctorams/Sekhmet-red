# Reference projects and clean-room integration decisions

Research reviewed on 2026-09-02. SEKHMET RED borrows architectural lessons, not uncredited code.

| Project | License | Strength adopted as a design lesson | SEKHMET RED decision |
|---|---|---|---|
| [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 | Multiple analyzers, offline artifacts and SARIF | Start with a deterministic offline engine and open analyzer boundary |
| [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | Apache-2.0 | Wide surface coverage and operational Web UI | Unify MCP, agent-tool and supply-chain views in a focused command interface |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | MIT | Reproducible dynamic prompt-injection benchmarks | Keep dynamic attacks in synthetic suites with explicit utility/security measures |

## Differentiation

1. Evidence fingerprints are first-class output, not presentation-only metadata.
2. Approved-baseline comparison exposes post-review security drift and potential rug pulls.
3. The core alpha performs zero network calls and requires no vendor API key.
4. Safe synthetic fixtures are shipped beside every attack class.
5. Findings include confidence, evidence location and actionable remediation.

## License policy

Future vendored or modified third-party code must retain its original notices and be recorded in `THIRD_PARTY_NOTICES.md`. Dependencies must be pinned and reviewed. Conceptual inspiration alone is linked here for transparency.
