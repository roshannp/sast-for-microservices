# OWASP Multi-Repo Security Scanner Agent

A cross-service security scanner that goes beyond typical single-repo SAST tools.
Instead of running one repo at a time, this agent **discovers every repository** in
your GitHub organisation, scans them all, and then **correlates findings across your
entire microservice estate** to surface systemic vulnerabilities.

---

## Why This Is Different From a Normal SAST Scanner

| Feature | Normal SAST | This Agent |
|---|---|---|
| Scans multiple repos automatically | No | Yes — entire GitHub org |
| Finds copy-pasted vulnerabilities across services | No | Yes |
| Detects the same secret in multiple repos | No | Yes |
| OWASP Web Top 10 | Usually | Yes |
| OWASP API Top 10 | Rarely | Yes |
| OWASP AI / LLM Top 10 | Almost never | Yes |
| Cross-service heatmap | No | Yes |
| HTML dashboard | Sometimes | Yes (rich, filterable) |

---

## What It Checks

### OWASP Web Top 10 (2021)
- **A01** Broken Access Control — missing auth decorators, IDOR patterns
- **A02** Cryptographic Failures — MD5/SHA1, hardcoded secrets, HTTP URLs
- **A03** Injection — SQLi, command injection, SSTI, LDAP injection, eval()
- **A05** Security Misconfiguration — DEBUG=True, CORS wildcard, ALLOWED_HOSTS *
- **A07** Auth Failures — JWT `algorithm=none`, signature disabled, no expiry, default creds
- **A08** Integrity Failures — pickle, yaml.load, Java ObjectInputStream
- **A09** Logging Failures — passwords/secrets logged to stdout
- **A10** SSRF — unvalidated user-controlled URLs in HTTP requests

### OWASP API Top 10 (2023)
- **API1** BOLA — object fetched by user-supplied ID without ownership check
- **API3** Mass Assignment — direct request body binding, @RequestBody without @Valid
- **API4** Resource Consumption — queries with no pagination
- **API9** Inventory — stale versioned API endpoints (v1, v2, ...)

### OWASP LLM / AI Top 10 (2025)
- **LLM01** Prompt Injection — user input directly in f-string prompts, string concat into LLM calls
- **LLM02** Insecure Output — LLM response passed to eval()/exec() or rendered as raw HTML
- **LLM05** Supply Chain — models loaded from external sources without pinned revision hash
- **LLM06** Sensitive Disclosure — secrets/PII embedded in system prompts
- **LLM08** Excessive Agency — agents with file system, shell, or DB write tools
- **LLM09** Overreliance — LLM output used without validation

### Cross-Service Correlation (unique to this agent)
- Same vulnerability pattern in 2+ repos → systemic pattern alert
- Identical hardcoded secret across multiple repos → shared secret alert
- Multiple AI services with unsafe output handling → org-wide AI risk
- CORS wildcard across multiple API services → mesh-wide exposure
- Repos with zero findings → scanner gap warning

---

## Installation

```bash
pip install requests     # only needed for GitHub API mode
# git must be installed for cloning
```

No other dependencies. The HTML dashboard and all scanning logic is pure Python.

---

## Usage

### Scan an entire GitHub organisation
```bash
python owasp_agent.py --org acme-corp --token ghp_xxxxxxxxxx
```

### Scan specific microservices only
```bash
python owasp_agent.py --org acme-corp \
  --repos auth-service,order-service,ai-api,payment-svc \
  --token ghp_xxxxxxxxxx
```

### GitHub Enterprise
```bash
python owasp_agent.py \
  --org acme-corp \
  --token ghp_xxx \
  --github-url https://github.acme.com/api/v3
```

### Scan repos already cloned locally (no GitHub token required)
```bash
# If your repos are already on disk:
python owasp_agent.py --local /workspace/microservices --org acme-corp
```

### Use environment variable for token
```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxx
python owasp_agent.py --org acme-corp
```

### Exclude specific repos
```bash
python owasp_agent.py --org acme-corp --token ghp_xxx \
  --exclude legacy-monolith,docs-site,infra-terraform
```

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--org` | required | GitHub org name or username |
| `--token` | `$GITHUB_TOKEN` | GitHub Personal Access Token |
| `--repos` | all | Comma-separated list of repo names |
| `--exclude` | none | Comma-separated repos to skip |
| `--github-url` | `https://api.github.com` | GitHub Enterprise API URL |
| `--local` | none | Path to folder of pre-cloned repos |
| `--output` | `owasp_dashboard.html` | HTML dashboard output path |
| `--json-out` | `owasp_report.json` | JSON report output path |
| `--max-repos` | 100 | Cap on how many repos to scan |

---

## Output

### HTML Dashboard (`owasp_dashboard.html`)
An interactive dashboard with:
- **Summary stats** — total findings by severity
- **Three charts** — findings by framework, severity breakdown, riskiest repos
- **Cross-service insights panel** — systemic patterns, shared secrets, org-wide issues
- **Repository × OWASP heatmap** — visual matrix of which repos have which issues
- **Per-repo risk score cards** — A-F grade with score bar
- **Filterable findings table** — filter by severity, category, repo name, or finding text

### JSON Report (`owasp_report.json`)
Machine-readable output suitable for piping into JIRA, Slack, CI gates, or SIEM tools.
Structure:
```json
{
  "scan_time": "...",
  "org": "acme-corp",
  "total_repos": 12,
  "total_findings": 87,
  "severity_summary": { "CRITICAL": 4, "HIGH": 23, ... },
  "cross_service_insights": [ ... ],
  "repos": {
    "auth-service": [
      { "rule_id": "W-A07-001", "title": "...", "severity": "CRITICAL", ... }
    ]
  }
}
```

---

## Supported Languages

| Language | Extension |
|---|---|
| Python | `.py` |
| Java | `.java` |
| Kotlin | `.kt`, `.kts` |

Support for Go, TypeScript, Ruby, C# can be added by extending the `RULES` list
with additional `lang` values and appropriate regex patterns.

---

## Adding Custom Rules

Rules are plain Python dicts in the `RULES` list. Add your own:

```python
{
    "rule_id":        "CUSTOM-001",
    "title":          "Hardcoded Internal API URL",
    "pattern":        r'https://internal\.acme\.com/api',
    "severity":       MEDIUM,
    "category":       "api",           # "web" | "api" | "ai"
    "owasp_category": "API9:2023 - Improper Inventory Management",
    "description":    "Internal URL hardcoded - use service discovery or env config.",
    "lang":           ["py", "java", "kt"],
    # optional: skip match if this pattern is found in surrounding lines
    "negative_lookahead": r'# noqa|# nosec',
}
```

---

## GitHub Token Permissions

The token needs:
- `repo` scope for private repositories
- `public_repo` scope for public repositories only

For GitHub Enterprise, the token should have `read:org` if scanning org repos.

---

## Suppressing False Positives

Add a comment on the flagged line to have it ignored by the negative lookahead:

```python
hashlib.md5(data).hexdigest()  # nosec - non-security use, file integrity only
```

Or add `# nosec` / `# noqa` to your custom rules' `negative_lookahead` field.

---

## Integrating Into CI/CD

```yaml
# .github/workflows/owasp-scan.yml
- name: OWASP Multi-Repo Scan
  run: |
    pip install requests
    python owasp_agent.py \
      --org ${{ github.repository_owner }} \
      --token ${{ secrets.GITHUB_TOKEN }} \
      --output owasp_dashboard.html

- name: Upload Dashboard
  uses: actions/upload-artifact@v3
  with:
    name: owasp-dashboard
    path: owasp_dashboard.html
```

---

## Architecture

```
owasp_agent.py
├── Finding            — data class for a single vulnerability hit
├── RULES              — 40+ regex-based checks across Web / API / AI
├── RepoScanner        — scans each file, applies rules, deduplicates
├── GitHubClient       — paginates GitHub API to discover/clone repos
├── CrossServiceAnalyzer — correlates findings across all repos
├── risk_score()       — calculates A-F grade per repo
├── generate_dashboard()  — produces interactive HTML with Chart.js
└── main()             — CLI orchestrator tying it all together
```
