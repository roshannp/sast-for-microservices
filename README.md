# Owasp-Agentic-Scanner

A GPT-4o powered security agent that audits your entire microservices org for OWASP Web Top 10, API Top 10, and LLM Top 10 vulnerabilities — not just one repo at a time.

Most SAST tools scan in isolation. This agent scans your whole environment, correlates findings across services, digs through git commit history, checks every dependency against CVE databases, and writes its own executive summary. It reasons, adapts, and remembers between scans.

<img width="1624" height="988" alt="Screenshot 2026-03-27 at 10 10 01 PM" src="https://github.com/user-attachments/assets/0d424de9-cee0-469e-83c8-73e3abd1d617" />

---

## Why This Agent

| Feature | Traditional SAST | This Agent |
|---|---|---|
| Scope | Single repo | Entire org / all microservices |
| False positives | Many | GPT-4o reads code context and scores confidence 1–10 |
| Cross-service patterns | No | Shared secrets, CORS spread, systemic issues across repos |
| CVE scanning | No | OSV.dev (PyPI + Maven, free, no key needed) |
| Git history | No | Finds secrets that were deleted years ago |
| Accountability | No | git blame per finding — who introduced it and when |
| Diff mode | No | Only alerts on new findings since the last scan |
| Output | Raw findings list | Executive summary + interactive HTML dashboard |

---

## OWASP Coverage

- **Web Top 10 (2021)** — Injection, Broken Access Control, Cryptographic Failures, SSRF, Security Misconfiguration, Vulnerable Components, and more
- **API Top 10 (2023)** — BOLA, Mass Assignment, Broken Authentication, Unrestricted Resource Consumption, Improper Inventory Management
- **LLM / AI Top 10 (2025)** — Prompt Injection, Insecure Output Handling, Excessive Agency, Sensitive Data Exposure, Supply Chain vulnerabilities

40+ rules across Python, Java, and Kotlin.

---

## Pipeline

```
LIST → SCAN → REVIEW → CVE → HISTORY → BLAME → CORRELATE → REPORT
```

Each step has a specific objective. The agent decides order and depth based on what it finds — if it spots AI/LLM code it goes deeper on LLM Top 10, if it finds a shared secret it flags every service affected.

**Step breakdown:**

- **LIST** — discover all repos in the org via GitHub API (paginated) or local folder walk
- **SCAN** — clone each repo and run 40+ OWASP regex rules across every `.py`, `.java`, `.kt`, `.yml`, `.xml` file
- **REVIEW** — read ±15 lines of context around each hit, filter false positives, assign confidence score 1–10
- **CVE** — parse `requirements.txt` and `pom.xml`, query OSV.dev for known CVEs with CVSS scores
- **HISTORY** — run `git log -S <pattern>` (pickaxe search) across full commit history for secrets that were deleted
- **BLAME** — run `git blame --porcelain` on confirmed findings to identify the author and commit
- **CORRELATE** — detect systemic patterns: same secret across 5 services, CORS wildcard in every gateway, MD5 used org-wide
- **REPORT** — generate executive summary in plain English, produce HTML dashboard and JSON report

---

## Installation

```bash
pip install openai requests
```

No other dependencies. CVE data comes from [OSV.dev](https://osv.dev) — free, no account required.

---

## Usage

```bash
# Scan a GitHub org
python owasp_agent_v2.py \
  --org your-org \
  --github-token ghp_xxx \
  --openai-key sk-xxx

# Scan local repos — no GitHub token needed
python owasp_agent_v2.py \
  --local ./path/to/repos \
  --openai-key sk-xxx

# Use environment variables to avoid passing keys on the command line
export GITHUB_TOKEN=ghp_xxx
export OPENAI_API_KEY=sk-xxx
python owasp_agent_v2.py --org your-org
```

---

## Output

```
owasp_v2_dashboard.html   — interactive dashboard, open in any browser
owasp_v2_report.json      — machine-readable findings with confidence scores
owasp_memory.json         — scan fingerprints for diff mode (auto-updated)
```

The dashboard includes:
- GPT-4o executive summary written in plain English
- A–F risk grade per repo and overall org score
- Severity breakdown chart and OWASP category heatmap
- Filterable findings table with confidence scores and git blame info
- CVE tab — every vulnerable dependency with CVE ID, severity, and CVSS score
- New-findings-only toggle for tracking remediation progress between scans

---

## CLI Reference

```
--org              GitHub org name (auto-detected from folder name with --local)
--github-token     GitHub PAT with repo scope (or set GITHUB_TOKEN env var)
--openai-key       OpenAI API key (or set OPENAI_API_KEY env var)
--local            Path to a local folder containing repo directories
--repos            Comma-separated list of specific repos to scan
--exclude          Comma-separated list of repos to skip
--output           HTML output path (default: owasp_v2_dashboard.html)
--json-out         JSON output path (default: owasp_v2_report.json)
--memory-file      Scan memory path (default: owasp_memory.json)
--max-repos        Max repos to scan (default: 50)
--max-steps        Max agent iterations (default: 80)
```

---

## Test Environment

A setup script is included that creates 5 intentionally vulnerable microservice repos to validate the agent end-to-end.

```bash
chmod +x setup_vulnerable_repos.sh
./setup_vulnerable_repos.sh

python owasp_agent_v2.py --local ./vuln-org --openai-key sk-xxx
```

**What the test environment contains:**

- `auth-service` — hardcoded AWS keys committed then deleted, SQL injection, command injection, MD5 password hashing
- `payment-service` — SSRF, pickle deserialization, CORS wildcard, unsafe yaml.load, BOLA
- `ai-api-service` — all LLM Top 10: prompt injection, `eval(llm_response)`, excessive agency, Anthropic/OpenAI keys in git history
- `order-service` (Java/Spring) — SQL injection, ObjectInputStream deserialization, JWT with no expiry, Runtime.exec()
- `api-gateway` — CORS wildcard, SSRF, secrets written to logs, stale API versioning

Cross-service patterns intentionally embedded: the same `INTERNAL_API_KEY` and `JWT_SECRET` appear across all 5 services to test systemic correlation.

---

## Troubleshooting

**Agent stops early or misses repos**
Increase `--max-steps` (default 80). Large orgs with many repos may need 150+.

**GPT-4o rate limit errors**
The agent backs off automatically, but on very large scans consider using `--max-repos` to batch the work.

**No CVE results for dependencies**
OSV.dev requires an internet connection. Verify with `curl https://api.osv.dev/v1/query` from your machine.

**Commit history scan finds nothing**
Ensure you are not using shallow clones. The agent always clones with full history — if you pre-cloned repos with `--depth=1` the pickaxe search will be limited to that depth.

**Token only shows student or unrelated repos**
Use `--repos repo1,repo2` to target specific repos explicitly, or `--exclude` to skip repos by name.

---

## Requirements

- Python 3.8+
- `pip install openai requests`
- OpenAI API key (GPT-4o access required)
- GitHub PAT with `repo` scope (GitHub org mode only — not needed for `--local`)

---

## Files

| File | Description |
|---|---|
| `owasp_agent_v2.py` | Main agent — GPT-4o powered ReAct loop, recommended |
| `owasp_agent.py` | v1 — deterministic multi-repo scanner, no LLM required |
| `setup_vulnerable_repos.sh` | Builds a test environment with 5 intentionally vulnerable microservices |

---

## Disclaimer

This tool is built for authorized security assessments, internal security reviews, and educational purposes only. Do not run it against systems or organizations you do not own or have explicit written permission to test. Any actions taken using this tool are solely your responsibility.
