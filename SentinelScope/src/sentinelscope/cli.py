"""Command-line interface for SentinelScope."""

import argparse
import json
from pathlib import Path

from .core import analyze_file


def render_text(report: dict) -> str:
    summary = report["summary"]
    rows = [
        "SentinelScope | Offline Log Triage",
        "=" * 36,
        f"Lines analyzed: {summary['lines_analyzed']}",
        f"SSH logins: {summary['ssh_failed_logins']} failed, {summary['ssh_successful_logins']} successful",
        f"Unique IPs: {summary['unique_ips']} | IOC matches: {summary['ioc_hits']}",
        f"Suspicious events: {summary['suspicious_events']}",
        "",
        "Potential brute-force sources (5+ failures):",
    ]
    sources = report["brute_force_sources"]
    rows.extend([f"  {item['source_ip']}  {item['failed_attempts']} failures  [{item['severity']}]" for item in sources] or ["  None detected"])
    rows.extend(["", "IOC matches:"])
    rows.extend([f"  line {hit['line']}: {hit['indicator']}" for hit in report["ioc_hits"]] or ["  None detected"])
    rows.append("\nReview findings in context; this heuristic report is not a verdict.")
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze local authentication or application logs offline.")
    parser.add_argument("log", type=Path, help="path to a text log file")
    parser.add_argument("--iocs", type=Path, help="optional text file with one indicator per line")
    parser.add_argument("--json", dest="json_path", type=Path, help="write the complete report as JSON")
    args = parser.parse_args(argv)
    if not args.log.is_file():
        parser.error(f"log file not found: {args.log}")
    if args.iocs and not args.iocs.is_file():
        parser.error(f"indicator file not found: {args.iocs}")
    report = analyze_file(args.log, args.iocs)
    print(render_text(report))
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nJSON report saved to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
