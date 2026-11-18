# AppSec Log Analyzer

A small, local-first Python prototype that analyzes Apache access logs and SSH
authentication logs for suspicious authentication and web-request patterns.
The repository's original Java implementation is archived in `legacy/java/`;
the Python package is the active project.

## What it detects

- Bursts of HTTP 401/403 responses or SSH authentication failures per source IP.
- High HTTP request volume in a configurable sliding time window.
- Repeated requests for common sensitive paths and exposed configuration files.
- Request strings resembling path traversal, SQL injection, or XSS probes.
- Bursts of HTTP 5xx responses, as a diagnostic signal rather than proof of attack.
- JSON reports, optional source-IP masking, and counts of parsed/ignored lines.

Detection rules are simple heuristics for a classroom demo. Alerts require
human review; they are not proof that a request succeeded or was malicious.
This tool does not block traffic, contact external services, or retain raw log
lines in its report.

## Application-security relevance

The project is focused on defensive application monitoring:

- **OWASP Top 10 2021 A07 — Identification and Authentication Failures:** flags
  repeated failed web and SSH authentication events.
- **OWASP Top 10 2021 A09 — Security Logging and Monitoring Failures:** turns
  local application and authentication logs into reviewable alerts.
- Request-pattern checks provide examples for monitoring suspicious web/API
  inputs; they do not replace application security testing or input validation.

The Apache/HTTP log analysis is the primary AppSec component. SSH analysis is
included as a related authentication-log example.

## Requirements

- Python 3.10 or later (standard library only at runtime).
- pytest for development tests.

Create an environment and install the test dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

## Run the prototype

Analyze the bundled Apache demo log and write a JSON report:

```bash
python -m appsec_log_analyzer \
  --input samples/sample_apache.log.txt \
  --format auto \
  --json-out reports/apache-report.json
```

Analyze the bundled SSH demo:

```bash
python -m appsec_log_analyzer \
  --input samples/sample_ssh.log.txt \
  --format ssh \
  --json-out reports/ssh-report.json
```

Mask source IPs in the JSON report and change detection parameters:

```bash
python -m appsec_log_analyzer \
  --input samples/sample_apache.log.txt \
  --window-seconds 60 \
  --auth-failure-threshold 5 \
  --request-threshold 10 \
  --probe-threshold 5 \
  --redact-ips \
  --json-out reports/redacted-report.json
```

Run tests:

```bash
python -m pytest -q
```

## Project structure

```text
appsec_log_analyzer/   Python parsers, detection rules, and CLI
tests/                 Parser, detection, and behavior tests
samples/               Synthetic logs using documentation-only IP ranges
legacy/java/           Archived Java implementation
docs/                  Original project report
```

## Input and privacy notes

- Supports Apache Common/Combined access-log lines and OpenSSH authentication
  messages. `--format auto` can parse a file containing either or both.
- Input files are read locally. Do not upload sensitive production logs.
- Reports include source IPs by default for investigation. Use `--redact-ips`
  before sharing; it masks addresses to IPv4 `/24` or IPv6 `/64`.
- SSH syslog lines lack a year, so the parser assumes the current year.
- Parsed URLs and user names are not copied into alert output; path indicators
  are limited to configured sensitive paths.

## Limitations

This is a prototype, not a SIEM, WAF, IDS/IPS, or incident-response system.
Thresholds are configurable but not tuned for a particular service. NAT,
proxies, shared clients, malformed logs, clock skew, and application-specific
routes can affect results. Input-pattern signatures are illustrative and can
produce false positives and false negatives. No traffic is blocked and no
automated remediation is performed.

## Legacy report

The original research report is preserved at
[`docs/legacy-java-report.pdf`](docs/legacy-java-report.pdf).

## License

MIT. See [LICENSE](LICENSE).
