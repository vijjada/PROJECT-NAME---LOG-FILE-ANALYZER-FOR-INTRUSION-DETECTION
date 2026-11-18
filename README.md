# 🛡️ AppSec Log Analyzer

> **A Python-based Application Security tool that analyzes Apache & SSH logs to detect intrusion attempts, brute-force attacks, and suspicious web request patterns.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-10%20Passed-brightgreen)
![OWASP](https://img.shields.io/badge/OWASP-A07%20%7C%20A09-red)

---

## 📐 System Architecture

```mermaid
flowchart LR
    subgraph Input["📂 Log Sources"]
        A["Apache Access Logs"]
        S["SSH Auth Logs"]
    end

    subgraph Engine["⚙️ Analysis Engine"]
        P["parser.py\nRegex Parsing"]
        D["detector.py\nSliding-Window\nDetection"]
        M["models.py\nEvent & Alert\nDataclasses"]
    end

    subgraph Output["📊 Output"]
        CLI["CLI Report\nTerminal Output"]
        JSON["JSON Report\nStructured Data"]
    end

    A --> P
    S --> P
    P --> M
    M --> D
    D --> CLI
    D --> JSON
```

---

## 🔍 Detection Pipeline

```mermaid
flowchart TD
    RAW["Raw Log Line"] --> PARSE{"Format Detection\nauto / apache / ssh"}
    PARSE -->|Apache| APACHE["Parse IP, Method,\nPath, Status Code"]
    PARSE -->|SSH| SSH["Parse IP, User,\nAuth Result"]
    APACHE --> EVENT["Event Object"]
    SSH --> EVENT
    EVENT --> GROUP["Group by\nSource IP"]
    GROUP --> W1["Auth Failure\nBurst Detection"]
    GROUP --> W2["Request Rate\nSpike Detection"]
    GROUP --> W3["Sensitive Path\nProbe Detection"]
    GROUP --> W4["Injection Pattern\nMatching"]
    GROUP --> W5["Server Error\nBurst Detection"]
    W1 --> ALERT["🚨 Alert Generation"]
    W2 --> ALERT
    W3 --> ALERT
    W4 --> ALERT
    W5 --> ALERT
    ALERT --> REPORT["📋 Report\nwith IP Redaction"]

    style RAW fill:#1a1a2e,color:#fff
    style ALERT fill:#d32f2f,color:#fff
    style REPORT fill:#00796b,color:#fff
```

---

## 🎯 OWASP Top 10 Mapping

```mermaid
flowchart LR
    subgraph OWASP["OWASP Top 10 2021"]
        A07["A07: Identification &\nAuthentication Failures"]
        A09["A09: Security Logging &\nMonitoring Failures"]
        A03["A03: Injection"]
    end

    subgraph Detections["Our Detections"]
        D1["Auth Failure Burst\nper Source IP"]
        D2["Sensitive Path Probing\n/.env, /admin, /wp-admin"]
        D3["SQLi / XSS / Path\nTraversal Signatures"]
        D4["Request Rate Spike\nSliding Window"]
        D5["Automated Log Parsing\n→ Structured Alerts"]
    end

    A07 --- D1
    A07 --- D4
    A09 --- D5
    A09 --- D2
    A03 --- D3

    style A07 fill:#c62828,color:#fff
    style A09 fill:#e65100,color:#fff
    style A03 fill:#ad1457,color:#fff
```

---

## 🚨 What It Detects

| Alert Category | Severity | Description |
|---|---|---|
| `authentication_failure_burst` | 🔴 HIGH | Brute-force: repeated HTTP 401/403 or SSH auth failures per IP |
| `sensitive_path_probe` | 🔴 HIGH | Scanning for `/.env`, `/admin`, `/wp-admin`, `/phpmyadmin`, `/debug` |
| `sensitive_resource_probe` | 🔴 HIGH | Direct access to config/repo paths (`/.env`, `/.git`, `/actuator`) |
| `path_traversal_probe` | 🔴 HIGH | `../../etc/passwd` style directory traversal |
| `sql_injection_probe` | 🔴 HIGH | `UNION SELECT`, `OR 1=1`, `DROP TABLE` patterns |
| `xss_probe` | 🔴 HIGH | `<script>`, `javascript:`, `onerror=` injection |
| `request_rate_spike` | 🟡 MEDIUM | Unusual request volume in sliding time window |
| `server_error_burst` | 🟡 MEDIUM | Cluster of HTTP 5xx errors (may indicate exploitation) |

---

## 📁 Project Structure

```mermaid
flowchart TD
    ROOT["appsec-log-analyzer/"]
    ROOT --> PKG["appsec_log_analyzer/"]
    ROOT --> TESTS["tests/"]
    ROOT --> SAMPLES["samples/"]
    ROOT --> DOCS["docs/"]
    ROOT --> LEGACY["legacy/java/"]
    ROOT --> CI[".github/workflows/"]

    PKG --> INIT["__init__.py"]
    PKG --> MAIN["__main__.py"]
    PKG --> PARSER["parser.py\nApache + SSH parsing"]
    PKG --> DETECTOR["detector.py\nDetection engine"]
    PKG --> MODELS["models.py\nEvent & Alert models"]
    PKG --> CLIM["cli.py\nCLI interface"]

    TESTS --> TP["test_parser.py\n4 tests"]
    TESTS --> TD["test_detector.py\n6 tests"]

    SAMPLES --> SA["sample_apache.log.txt"]
    SAMPLES --> SS["sample_ssh.log.txt"]

    DOCS --> PDF["legacy-java-report.pdf"]
    DOCS --> PPT["Presentation.pptx"]

    CI --> YML["security.yml\npytest + Bandit + pip-audit"]

    style ROOT fill:#0B1D3A,color:#fff
    style PKG fill:#00796b,color:#fff
    style TESTS fill:#1565c0,color:#fff
    style CI fill:#6a1b9a,color:#fff
```

---

## ⚡ Quick Start

```bash
# Clone and setup
git clone https://github.com/vijjada/PROJECT-NAME---LOG-FILE-ANALYZER-FOR-INTRUSION-DETECTION.git
cd PROJECT-NAME---LOG-FILE-ANALYZER-FOR-INTRUSION-DETECTION
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

# Run tests
python -m pytest -v

# Analyze Apache logs
python -m appsec_log_analyzer \
  --input samples/sample_apache.log.txt \
  --json-out reports/apache-report.json

# Analyze SSH logs
python -m appsec_log_analyzer \
  --input samples/sample_ssh.log.txt \
  --format ssh \
  --json-out reports/ssh-report.json

# Redact IPs before sharing
python -m appsec_log_analyzer \
  --input samples/sample_apache.log.txt \
  --redact-ips \
  --json-out reports/redacted-report.json
```

---

## 🔧 CLI Options

| Flag | Default | Description |
|---|---|---|
| `--input` | `samples/sample_apache.log.txt` | Log file to analyze |
| `--format` | `auto` | Log format: `auto`, `apache`, or `ssh` |
| `--window-seconds` | `60` | Sliding window duration for detection |
| `--auth-failure-threshold` | `5` | Auth failures before alerting |
| `--request-threshold` | `10` | Requests before rate-spike alert |
| `--probe-threshold` | `5` | Distinct sensitive paths before alerting |
| `--json-out` | *(none)* | Write structured JSON report |
| `--redact-ips` | `false` | Mask IPs to /24 (IPv4) or /64 (IPv6) |

---

## 🧪 CI/CD Security Pipeline

```mermaid
flowchart LR
    PUSH["git push / PR"] --> GHA["GitHub Actions"]
    GHA --> TEST["pytest\n10 tests"]
    GHA --> BANDIT["Bandit\nSAST Scanner"]
    GHA --> AUDIT["pip-audit\nDependency Check"]
    TEST -->|✅ Pass| DONE["✅ Merge Ready"]
    BANDIT -->|✅ No Issues| DONE
    AUDIT -->|✅ No CVEs| DONE

    style PUSH fill:#1a1a2e,color:#fff
    style DONE fill:#2e7d32,color:#fff
    style GHA fill:#6a1b9a,color:#fff
```

---

## 🔒 Security & Privacy Notes

- **No network calls** — all analysis is local, offline, stdlib-only at runtime
- **No real passwords or credentials** stored anywhere in the codebase
- **IP redaction** available via `--redact-ips` before sharing reports
- **Synthetic sample logs** use RFC 5737 documentation-only IP ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)
- **Bandit-clean** — zero security findings in static analysis

---

## ⚠️ Limitations

This is a **classroom prototype**, not a production SIEM, WAF, or IDS/IPS.

- Thresholds are configurable but not tuned for any specific service
- NAT, proxies, shared clients, and clock skew can affect results
- Injection signatures are illustrative and may produce false positives/negatives
- No traffic is blocked; no automated remediation is performed
- Alerts are **leads for human review**, not proof of malicious activity

---

## 📄 Legacy

The original Java implementation is archived in [`legacy/java/`](legacy/java/).
The original research report is at [`docs/legacy-java-report.pdf`](docs/legacy-java-report.pdf).

---

## 👨‍💻 Author

**Vijjada Prem Sai**

## 📜 License

MIT — See [LICENSE](LICENSE)
