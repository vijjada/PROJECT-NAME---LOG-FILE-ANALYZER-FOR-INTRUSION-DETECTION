import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from appsec_log_analyzer.detector import detect
from appsec_log_analyzer.parser import parse_lines


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="appsec-log-analyzer",
        description="Analyze local Apache or SSH logs for defensive AppSec signals.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("samples/sample_apache.log.txt"),
        help="Local Apache or SSH log file (default: bundled Apache sample).",
    )
    parser.add_argument(
        "--format", choices=("auto", "apache", "ssh"), default="auto"
    )
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--request-threshold", type=int, default=10)
    parser.add_argument("--auth-failure-threshold", type=int, default=5)
    parser.add_argument("--probe-threshold", type=int, default=5)
    parser.add_argument("--json-out", type=Path, help="Write a JSON report to this path.")
    parser.add_argument(
        "--redact-ips",
        action="store_true",
        help="Mask source IPs to /24 (IPv4) or /64 (IPv6) in the JSON report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if min(
            args.window_seconds,
            args.request_threshold,
            args.auth_failure_threshold,
            args.probe_threshold,
        ) < 1:
            raise ValueError("Detection thresholds and window must be positive.")
        with args.input.open(encoding="utf-8", errors="replace") as log_file:
            result = parse_lines(log_file, args.format)
        alerts = detect(
            result.events,
            window_seconds=args.window_seconds,
            request_threshold=args.request_threshold,
            auth_failure_threshold=args.auth_failure_threshold,
            probe_threshold=args.probe_threshold,
        )
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print("AppSec Log Analyzer")
    print(f"Input: {args.input}")
    print(
        f"Format: {result.log_format} | Lines: {result.total_lines} | "
        f"Parsed: {result.parsed_lines} | Ignored: {result.ignored_lines}"
    )
    print(f"Alerts: {len(alerts)}")
    if alerts:
        for alert in alerts:
            print(
                f"[{alert.severity.upper()}] {alert.category} | "
                f"source={alert.source_ip} | {alert.timestamp.isoformat()} | "
                f"{alert.summary}"
            )
            if alert.indicators:
                print(f"  Indicators: {', '.join(alert.indicators)}")
    else:
        print("No configured detection rules were triggered.")
    print("Review alerts as leads, not proof of malicious activity.")

    if args.json_out:
        document = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input": args.input.name,
            "format": result.log_format,
            "summary": {
                "total_lines": result.total_lines,
                "parsed_lines": result.parsed_lines,
                "ignored_lines": result.ignored_lines,
                "alert_count": len(alerts),
            },
            "alerts": [alert.to_dict(args.redact_ips) for alert in alerts],
        }
        try:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(
                json.dumps(document, indent=2) + "\n", encoding="utf-8"
            )
        except OSError as error:
            print(f"Error writing JSON report: {error}", file=sys.stderr)
            return 2
        print(f"JSON report: {args.json_out}")
    return 0
