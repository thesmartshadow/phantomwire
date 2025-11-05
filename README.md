# Phantomwire

[![PyPI](https://img.shields.io/pypi/v/phantomwire.svg)](https://pypi.org/project/phantomwire/)
[![CI](https://github.com/phantomwire/phantomwire/actions/workflows/ci.yml/badge.svg)](https://github.com/phantomwire/phantomwire/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-80%25+-brightgreen.svg)](#testing)

Phantomwire is a defensive-offensive cybersecurity toolkit focused on auditable operations.
It offers HTTP/TLS/JWT analysis, lightweight PCAP summarisation, DNS inspection, and a plugin
system for custom checks. All active operations require explicit consent to ensure safe and
ethical usage.

## Features

- Unified evidence model (`Target → Evidence → Finding`) for consistent reporting.
- Safe-mode with explicit consent tokens controlling network operations.
- HTTP security header analysis, TLS certificate auditing, JWT linting, and PCAP sessionisation.
- Reporting in JSON, Markdown, and SARIF for integration with CI pipelines.
- Plugin framework discoverable via entry points.
- Minimal dependencies with optional extras for advanced capabilities.

## Safety Model

Phantomwire never performs active network operations unless both of the following are true:

1. The target host is within the configured allowed scopes.
2. The environment variable `PHANTOMWIRE_CONSENT` is set to `I_HAVE_PERMISSION`.

Use `phantom --consent --allowed-scope example.org ...` to opt in for the current process.
Always secure evidence, keep logs, and ensure legal authorization before operating on any
non-lab environment.

## Installation

```bash
pip install phantomwire
# optional extras
pip install "phantomwire[web,crypto,pcap,dns]"
```

## Quickstart

```bash
# Analyze HTTP headers
phantom --consent --allowed-scope example.com scan http https://example.com

# Audit TLS configuration
phantom --consent --allowed-scope example.com audit tls example.com:443

# Lint a JWT token
phantom jwt lint "<token>"

# Inspect a PCAP file
phantom inspect pcap sample.pcap

# Generate Markdown report
phantom --consent --allowed-scope example.com --format md --output report.md scan http https://example.com
```

## Reporting Formats

```json
{
  "target": {"locator": "https://example.com"},
  "findings": [
    {"id": "HTTP-H-001", "severity": "Medium", "title": "Missing strict-transport-security header"}
  ]
}
```

```markdown
# Phantomwire Security Report

| ID | Severity | Title |
| --- | --- | --- |
| HTTP-H-001 | Medium | Missing strict-transport-security header |
```

SARIF output is compatible with GitHub Advanced Security and other CI systems.

## CLI Overview

Run `phantom --help` for full usage. Top-level commands include:

- `scan http <url>` — HTTP security headers.
- `audit tls <host>:<port>` — TLS certificate and cipher checks.
- `jwt lint <token>` — JWT claim analysis and signature verification.
- `inspect pcap <path>` — Sessionize PCAP captures.
- `dns resolve <host>` — Consent-gated DNS lookups.
- `plugins list|run` — Discover or execute plugins.

Exit codes: `0` success, `2` when high-severity findings exist, `1` for operational errors.

## Development

```bash
git clone https://github.com/phantomwire/phantomwire.git
cd phantomwire
pip install -e .[dev]
pre-commit install
pytest
```

Use `python -m build` to create release artifacts. Pull requests must pass `ruff`, `mypy`, and
`pytest` on Python 3.10+.

## Ethical Use

Phantomwire is designed for responsible security testing. Do not use it on systems you do not
own or operate without written permission. Evidence collection is auditable and should be
stored securely to prevent misuse.

## License

MIT License. See [LICENSE](LICENSE) for details.
