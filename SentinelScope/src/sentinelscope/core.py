"""Small, dependency-free analysis engine for local log files."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import ipaddress
import re
from pathlib import Path
from typing import Iterable

SSH_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\da-fA-F:.]+) port (\d+)")
SSH_ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\da-fA-F:.]+) port (\d+)")
GENERIC_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
SUSPICIOUS_PATTERNS = {
    "privilege-escalation": re.compile(r"\b(?:sudo|su)\b.*\b(?:root|wheel)\b", re.I),
    "web-shell-or-command": re.compile(r"\b(?:cmd=|shell_exec|/bin/(?:ba)?sh\s+-c|powershell\s+-enc)\b", re.I),
    "account-change": re.compile(r"\b(?:useradd|adduser|passwd\s+-|usermod)\b", re.I),
}


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def analyze_lines(lines: Iterable[str], indicators: Iterable[str] = ()) -> dict:
    """Analyze text lines without executing or transmitting their contents."""
    iocs = {item.strip().lower() for item in indicators if item.strip() and not item.lstrip().startswith("#")}
    events: list[dict] = []
    ip_counts: Counter[str] = Counter()
    suspicious_counts: Counter[str] = Counter()
    ioc_hits: list[dict] = []
    failed_by_ip: Counter[str] = Counter()
    successful_by_ip: Counter[str] = Counter()

    for number, raw in enumerate(lines, start=1):
        line = raw.rstrip("\r\n")
        failed = SSH_FAILED.search(line)
        accepted = SSH_ACCEPTED.search(line)
        if failed:
            user, source, port = failed.groups()
            source = _valid_ip(source)
            if source:
                failed_by_ip[source] += 1
                events.append({"line": number, "type": "ssh_failed_login", "source_ip": source, "user": user, "port": int(port)})
        elif accepted:
            user, source, port = accepted.groups()
            source = _valid_ip(source)
            if source:
                successful_by_ip[source] += 1
                events.append({"line": number, "type": "ssh_successful_login", "source_ip": source, "user": user, "port": int(port)})

        valid_ips = {_valid_ip(match.group()) for match in GENERIC_IPV4.finditer(line)}
        for ip in valid_ips - {None}:
            ip_counts[ip] += 1
        lowered = line.lower()
        for indicator in iocs:
            if indicator in lowered:
                ioc_hits.append({"line": number, "indicator": indicator})
        for name, pattern in SUSPICIOUS_PATTERNS.items():
            if pattern.search(line):
                suspicious_counts[name] += 1
                events.append({"line": number, "type": name})

    threshold = 5
    brute_force = [
        {"source_ip": ip, "failed_attempts": count, "severity": "high" if successful_by_ip[ip] else "medium",
         "successful_logins": successful_by_ip[ip]}
        for ip, count in failed_by_ip.items() if count >= threshold
    ]
    brute_force.sort(key=lambda item: (-item["failed_attempts"], item["source_ip"]))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "lines_analyzed": number if 'number' in locals() else 0,
            "ssh_failed_logins": sum(failed_by_ip.values()),
            "ssh_successful_logins": sum(successful_by_ip.values()),
            "unique_ips": len(ip_counts),
            "ioc_hits": len(ioc_hits),
            "suspicious_events": sum(suspicious_counts.values()),
            "potential_brute_force_sources": len(brute_force),
        },
        "top_ips": [{"ip": ip, "occurrences": count} for ip, count in ip_counts.most_common(10)],
        "brute_force_sources": brute_force,
        "ioc_hits": ioc_hits,
        "suspicious_event_counts": dict(sorted(suspicious_counts.items())),
        "events": events,
    }


def analyze_file(log_path: Path, indicators_path: Path | None = None) -> dict:
    indicators = indicators_path.read_text(encoding="utf-8", errors="replace").splitlines() if indicators_path else []
    with log_path.open(encoding="utf-8", errors="replace") as stream:
        return analyze_lines(stream, indicators)
