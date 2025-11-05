"""Command line interface for Phantomwire."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable, Sequence

from ..appsec.http_headers import analyze as analyze_http
from ..appsec.jwt_lint import JWTError
from ..appsec.jwt_lint import lint as lint_jwt
from ..appsec.tls_audit import inspect as inspect_tls
from ..core.config import load_config
from ..core.models import Evidence, Finding, ScanResult, Target
from ..core.pipeline import run_pipeline
from ..core.registry import discover_plugins, load_builtin_example, load_plugin
from ..core.safemode import CONSENT_ENV, CONSENT_TOKEN, safe_mode
from ..dns.resolv import resolve as resolve_dns
from ..net.pcap import sessionize
from ..reporting import to_json, to_markdown, to_sarif

_FORMATTERS = {
    "json": to_json,
    "md": to_markdown,
    "sarif": to_sarif,
}


def _merge_config(args: argparse.Namespace) -> None:
    if args.consent:
        os.environ[CONSENT_ENV] = CONSENT_TOKEN
    config = load_config(
        cli_allowed_scopes=args.allowed_scope,
        cli_verbose=args.verbose,
    )
    safe_mode.merge_allowed(config.allowed_scopes)
    if args.verbose:
        print(f"[phantomwire] Allowed scopes: {sorted(config.allowed_scopes)}", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phantom",
        description="Phantomwire - defensive-offensive cybersecurity toolkit",
    )
    parser.add_argument("--output", type=Path, help="Write report to file", default=None)
    parser.add_argument("--format", choices=sorted(_FORMATTERS), default="json")
    parser.add_argument("--allowed-scope", dest="allowed_scope", action="append", default=[])
    parser.add_argument(
        "--consent",
        action="store_true",
        help="Acknowledge authorized testing scope",
    )
    parser.add_argument("--verbose", action="store_true")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run HTTP analyses")
    scan_sub = scan_parser.add_subparsers(dest="scan_command", required=True)
    http_parser = scan_sub.add_parser("http", help="Analyze HTTP security headers")
    http_parser.add_argument("url")

    audit_parser = subparsers.add_parser("audit", help="Perform audits")
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)
    tls_parser = audit_sub.add_parser("tls", help="Inspect TLS configuration")
    tls_parser.add_argument("endpoint", help="host:port pair")

    jwt_parser = subparsers.add_parser("jwt", help="JWT utilities")
    jwt_sub = jwt_parser.add_subparsers(dest="jwt_command", required=True)
    jwt_lint_parser = jwt_sub.add_parser("lint", help="Lint a JWT token")
    jwt_lint_parser.add_argument("token")
    jwt_lint_parser.add_argument("--jwk")

    inspect_parser = subparsers.add_parser("inspect", help="Inspect network captures")
    inspect_sub = inspect_parser.add_subparsers(dest="inspect_command", required=True)
    pcap_parser = inspect_sub.add_parser("pcap", help="Summarize a PCAP file")
    pcap_parser.add_argument("path", type=Path)

    plugins_parser = subparsers.add_parser("plugins", help="Interact with plugins")
    plugins_sub = plugins_parser.add_subparsers(dest="plugins_command", required=True)
    plugins_sub.add_parser("list", help="List installed plugins")
    plugins_run = plugins_sub.add_parser("run", help="Run a specific plugin")
    plugins_run.add_argument("name")
    plugins_run.add_argument(
        "--kv",
        action="append",
        default=[],
        help="Key=value arguments passed to the plugin",
    )

    dns_parser = subparsers.add_parser("dns", help="DNS lookups")
    dns_lookup = dns_parser.add_subparsers(dest="dns_command", required=True)
    dns_resolve = dns_lookup.add_parser("resolve", help="Resolve a hostname")
    dns_resolve.add_argument("host")

    return parser


def _extract_kv(pairs: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"Invalid key=value pair: {pair}")
        key, value = pair.split("=", 1)
        result[key] = value
    return result


def _write_output(path: Path | None, content: str) -> None:
    if path is None:
        print(content)
    else:
        path.write_text(content, encoding="utf-8")
        print(f"Report written to {path}", file=sys.stderr)


def _highest_severity(findings: Iterable[Finding]) -> str | None:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    highest = 0
    level: str | None = None
    for finding in findings:
        score = order.get(finding.severity, 0)
        if score > highest:
            highest = score
            level = finding.severity
    return level


def _render(result: ScanResult, fmt: str) -> str:
    formatter = _FORMATTERS[fmt]
    return formatter(result)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _merge_config(args)

        if args.command == "scan" and args.scan_command == "http":
            target = Target(locator=args.url, host=None)
            findings = analyze_http(target)
            result = run_pipeline(target, [lambda: findings])
            output = _render(result, args.format)
            _write_output(args.output, output)
            severity = _highest_severity(result.findings)
            return 2 if severity in {"High", "Critical"} else 0

        if args.command == "audit" and args.audit_command == "tls":
            if ":" not in args.endpoint:
                raise ValueError("TLS endpoint must be host:port")
            host, port_str = args.endpoint.split(":", 1)
            port = int(port_str)
            target = Target(locator=f"tls://{host}:{port}", host=host, port=port)
            findings = inspect_tls(host, port)
            result = run_pipeline(target, [lambda: findings])
            output = _render(result, args.format)
            _write_output(args.output, output)
            severity = _highest_severity(result.findings)
            return 2 if severity in {"High", "Critical"} else 0

        if args.command == "jwt" and args.jwt_command == "lint":
            target = Target(locator="jwt", host=None)
            findings = lint_jwt(args.token, args.jwk)
            result = run_pipeline(target, [lambda: findings])
            output = _render(result, args.format)
            _write_output(args.output, output)
            severity = _highest_severity(result.findings)
            return 2 if severity in {"High", "Critical"} else 0

        if args.command == "inspect" and args.inspect_command == "pcap":
            target = Target(locator=str(args.path), host=None)
            summary = sessionize(args.path)
            stages = []
            if isinstance(summary, list):
                findings = summary
                stages.append(lambda: findings)
            else:
                evidence = summary
                stages.append(lambda: [Evidence(kind=evidence.kind, data=evidence.data)])
            result = run_pipeline(target, stages)
            output = _render(result, args.format)
            _write_output(args.output, output)
            severity = _highest_severity(result.findings)
            return 2 if severity in {"High", "Critical"} else 0

        if args.command == "plugins":
            if args.plugins_command == "list":
                print("Installed plugins:")
                discovered = discover_plugins()
                for name in sorted(discovered.keys()):
                    print(f"- {name}")
                example = load_builtin_example()
                print(f"- {example.name} (builtin example)")
                return 0
            if args.plugins_command == "run":
                params = _extract_kv(args.kv)
                try:
                    plugin = load_plugin(args.name)
                except KeyError:
                    if args.name == load_builtin_example().name:
                        plugin = load_builtin_example()
                    else:
                        raise
                output = plugin.run(**params)
                if output is None:
                    print("Plugin executed without findings.")
                    return 0
                items = list(output if isinstance(output, Iterable) else [output])
                findings = [item for item in items if isinstance(item, Finding)]
                evidence_items = [item for item in items if isinstance(item, Evidence)]
                target = Target(locator=f"plugin://{args.name}")
                stages = []
                if findings:
                    stages.append(lambda: findings)
                if evidence_items:
                    stages.append(lambda: evidence_items)
                result = run_pipeline(target, stages)
                print(_render(result, args.format))
                severity = _highest_severity(result.findings)
                return 2 if severity in {"High", "Critical"} else 0

        if args.command == "dns" and args.dns_command == "resolve":
            evidence = resolve_dns(args.host)
            target = Target(locator=f"dns://{args.host}", host=args.host)
            result = run_pipeline(
                target,
                [lambda evidence=evidence: [Evidence(kind=evidence.kind, data=evidence.data)]],
            )
            output = _render(result, args.format)
            _write_output(args.output, output)
            return 0

        parser.error("Unsupported command")
    except (ValueError, PermissionError, JWTError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
