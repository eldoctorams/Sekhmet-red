# MCP RedFlag

> A reproducible red-team benchmark for MCP servers and Agent Skills.

[![Status: Design](https://img.shields.io/badge/status-design--phase-ef4444)](#project-status)
[![License: MIT](https://img.shields.io/badge/license-MIT-0ea5e9)](LICENSE)
[![Security](https://img.shields.io/badge/security-responsible%20use-22c55e)](SECURITY.md)

MCP RedFlag is being designed as an adversarial lab—not merely another static scanner. It will measure how agent systems behave when tools, manifests, resources and supply-chain components become hostile, then produce evidence-backed, CI-friendly findings.

## Why this matters

Agent ecosystems introduce new trust boundaries: tool descriptions can contain hidden instructions, schemas can change, permissions can be excessive, and secrets can leak through tool calls. Teams need repeatable tests and comparable scores before deployment.

## Planned capabilities

- Curated attack cases for prompt injection, tool poisoning, rug pulls, secret leakage and over-permission.
- Isolated test harnesses for stdio, HTTP and SSE transports.
- Deterministic evidence bundles with inputs, outputs, hashes and timestamps.
- Severity scoring mapped to OWASP guidance and export to JSON/SARIF.
- CI gates, regression baselines and human-readable reports.
- A public benchmark corpus with safe mock targets—never real victim systems.

## Differentiator

Most projects focus on detection. MCP RedFlag will combine a **benchmark specification**, **safe adversarial fixtures**, **runtime behavior measurement** and **reproducible evidence**. The goal is to answer: “Did the agent actually change its behavior under attack, and can another researcher reproduce the result?”

## Project status

**Design phase.** The repository currently defines scope, safety boundaries and the MVP. No production-ready scanner is claimed yet.

## First release target

```bash
mcp-redflag run ./examples/vulnerable-server
mcp-redflag report --format sarif
```

The first public alpha will include a small safe corpus, a Python CLI, JSON evidence schema and GitHub Actions example.

## Documentation

- [Roadmap](ROADMAP.md)
- [Reference projects and gap analysis](docs/REFERENCE_PROJECTS.md)
- [Contributing](CONTRIBUTING.md)
- [Security and responsible use](SECURITY.md)

## Author

**Dr. Ahmed Mohamed El Sayed** — OSINT, digital forensics, cybercrime investigation and AI-powered investigation systems.

[Website](https://drahmedelsayed.com/) · [LinkedIn](https://www.linkedin.com/in/eldoctorams/) · [GitHub](https://github.com/eldoctorams)

## License

MIT. Defensive research and authorized testing only.
