# SentinelScope 🔎

**Offline log triage for blue-team practice.** SentinelScope scans a local text log, summarizes SSH authentication activity, highlights repeated failed logins, matches supplied indicators of compromise (IOCs), and flags a few suspicious command patterns. It uses only Python's standard library and never sends log data over the network.

> This is a learning and triage aid. Findings are heuristic and need human review. The sample indicators use documentation-only IP ranges and `.test` domains; replace them only with data you are authorized to analyze.

## Features

- Detects successful and failed SSH logins
- Groups repeated failures by source IP (5 or more is a potential brute-force pattern)
- Matches exact text indicators from a local file
- Counts selected privilege, account-change, and command-line patterns
- Prints a readable summary and can save a detailed JSON report
- Includes safe sample logs and unit tests; no external dependencies

## Quick start

Python 3.10 or newer is required.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
sentinelscope sample_data/auth.log --iocs sample_data/iocs.txt --json reports/sample-report.json
```

Without installing the command, run it from this folder:

```bash
PYTHONPATH=src python -m sentinelscope sample_data/auth.log --iocs sample_data/iocs.txt
```

Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m sentinelscope sample_data/auth.log --iocs sample_data/iocs.txt --json reports\report.json
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Use your own data

```bash
sentinelscope /path/to/auth.log --iocs /path/to/indicators.txt --json reports/triage.json
```

An indicator file contains one string per line. Blank lines and lines beginning with `#` are ignored. The matcher is case-insensitive substring matching; keep indicator lists trusted and small, and review every reported match in its surrounding log context.

## Example output

```text
SentinelScope | Offline Log Triage
====================================
Lines analyzed: 8
SSH logins: 5 failed, 1 successful
Unique IPs: 2 | IOC matches: 5
Suspicious events: 0

Potential brute-force sources (5+ failures):
  203.0.113.45  5 failures  [medium]
```

## Project layout

```text
src/sentinelscope/   analysis engine and CLI
sample_data/         synthetic RFC 5737 log and indicators
tests/               standard-library unit tests
```

## Scope and privacy

SentinelScope reads only the file paths passed to it, writes JSON only when requested, and has no network, scanning, exploit, persistence, or credential collection features. Avoid committing real logs or sensitive indicators to a public repository.

## License

MIT. See [LICENSE](LICENSE).
