#!/usr/bin/env python3
"""
OWASP Multi-Repo Security AGENT v2
====================================
A true GPT-4o powered agentic security scanner.

What makes this a real agent (not just a script):
  - GPT-4o brain decides WHAT to scan, in WHAT order, and HOW deep
  - Reads actual code context to reason about false positives
  - Adapts: finds AI code -> digs deeper on LLM Top 10
  - Checks all dependencies against CVE databases (OSV.dev, free)
  - Remembers previous scans -> only alerts on NEW findings
  - Writes its own executive summary in plain English
  - Visible real-time reasoning: see the agent think

Usage:
  python owasp_agent_v2.py --org acme-corp --github-token ghp_xxx --openai-key sk-xxx
  python owasp_agent_v2.py --local /path/to/repos --org acme-corp --openai-key sk-xxx
  GITHUB_TOKEN=ghp_xxx OPENAI_API_KEY=sk-xxx python owasp_agent_v2.py --org acme-corp

Output:
  owasp_v2_dashboard.html  -- enhanced interactive dashboard with confidence scores
  owasp_v2_report.json     -- machine-readable findings with LLM analysis
  owasp_memory.json        -- scan history for diff mode (auto-updated)
"""

import os, re, sys, json, subprocess, tempfile, argparse, time, uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

# ─────────────────────────────────────────────
# SEVERITY
# ─────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"
SEVERITY_RANK = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4}

# ─────────────────────────────────────────────
# FINDING MODEL  (enhanced with confidence)
# ─────────────────────────────────────────────
class Finding:
    def __init__(self, rule_id, title, description, severity, category,
                 file_path, line_number, code_snippet, owasp_category,
                 confidence=None, llm_analysis=None, is_new=True):
        self.rule_id        = rule_id
        self.title          = title
        self.description    = description
        self.severity       = severity
        self.category       = category
        self.file_path      = file_path
        self.line_number    = line_number
        self.code_snippet   = (code_snippet or "").strip()
        self.owasp_category = owasp_category
        self.confidence     = confidence      # 1-10 from LLM, None = unreviewed
        self.llm_analysis   = llm_analysis    # LLM's reasoning string
        self.is_new         = is_new          # False = seen in previous scan

    @property
    def fingerprint(self):
        return f"{self.rule_id}::{self.file_path}::{self.line_number}"

    def to_dict(self):
        return {
            "rule_id":        self.rule_id,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity,
            "category":       self.category,
            "file_path":      self.file_path,
            "line_number":    self.line_number,
            "code_snippet":   self.code_snippet,
            "owasp_category": self.owasp_category,
            "confidence":     self.confidence,
            "llm_analysis":   self.llm_analysis,
            "is_new":         self.is_new,
        }

# ─────────────────────────────────────────────
# CVE FINDING MODEL
# ─────────────────────────────────────────────
class CVEFinding:
    def __init__(self, package, version, ecosystem, cve_id, summary, severity, aliases):
        self.package    = package
        self.version    = version
        self.ecosystem  = ecosystem
        self.cve_id     = cve_id
        self.summary    = summary
        self.severity   = severity
        self.aliases    = aliases

    def to_dict(self):
        return {
            "package":   self.package,
            "version":   self.version,
            "ecosystem": self.ecosystem,
            "cve_id":    self.cve_id,
            "summary":   self.summary,
            "severity":  self.severity,
            "aliases":   self.aliases,
        }

# ─────────────────────────────────────────────
# OWASP RULES  (40+ checks across Web/API/AI)
# ─────────────────────────────────────────────
RULES = [
    # ── OWASP Web Top 10 ──────────────────────────────────────────────────
    {"rule_id":"W-A01-001","title":"Broken Access Control - No Auth Decorator",
     "pattern":r'@(?:app|router|blueprint)\.(?:route|get|post|put|delete|patch)\s*\([^)]+\)\s*\ndef\s+\w+\s*\(',
     "severity":HIGH,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"Route without an authentication decorator immediately following it.",
     "lang":["py"],"negative_lookahead":r'@(?:login_required|jwt_required|requires_auth|authenticated|authorize)'},
    {"rule_id":"W-A01-002","title":"IDOR - Object ID From Request Without Ownership Check",
     "pattern":r'(?:user_id|userId|owner_id)\s*=\s*(?:request\.|req\.|params\.|args\.)',
     "severity":HIGH,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"Object ID taken from request without verifying caller ownership.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A02-001","title":"Weak Crypto - MD5",
     "pattern":r'hashlib\.md5\s*\(',"severity":HIGH,"category":"web",
     "owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"MD5 is broken. Use SHA-256 or stronger.",
     "lang":["py"]},
    {"rule_id":"W-A02-J001","title":"Weak Crypto - MD5 (Java)",
     "pattern":r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
     "severity":HIGH,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"MD5 is broken. Use SHA-256 or stronger.","lang":["java","kt"]},
    {"rule_id":"W-A02-002","title":"Weak Crypto - SHA-1",
     "pattern":r'hashlib\.sha1\s*\(',"severity":MEDIUM,"category":"web",
     "owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"SHA-1 deprecated. Use SHA-256.","lang":["py"]},
    {"rule_id":"W-A02-003","title":"Hardcoded Credential or Secret",
     "pattern":r'(?:SECRET_KEY|PASSWORD|PASSWD|API_KEY|AUTH_TOKEN|PRIVATE_KEY|DB_PASS|ACCESS_KEY|CLIENT_SECRET)\s*=\s*["\'][^"\']{6,}["\']',
     "severity":CRITICAL,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Hardcoded credentials in source. Rotate and use a secrets manager.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A02-004","title":"Plaintext HTTP URL",
     "pattern":r'"http://(?!localhost|127\.0\.0\.1)',
     "severity":MEDIUM,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Non-HTTPS URL - traffic may be intercepted.","lang":["py","java","kt"]},
    {"rule_id":"W-A03-001","title":"SQL Injection - String Concat in Query",
     "pattern":r'(?:execute|cursor\.execute)\s*\(\s*(?:["\'][^"\']*["\']\s*\+|f["\'][^"\']*\{(?:user|input|param|request|data|query|search|name|id))',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"SQL query built with string concat/f-strings. Use parameterised queries.","lang":["py"]},
    {"rule_id":"W-A03-J001","title":"SQL Injection (Java)",
     "pattern":r'(?:createQuery|createNativeQuery|prepareStatement|executeQuery|executeUpdate)\s*\([^)]*\+\s*(?:request|param|input|body|user|query)',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"SQL query built with string concat. Use PreparedStatement.","lang":["java","kt"]},
    {"rule_id":"W-A03-002","title":"Command Injection - subprocess shell=True",
     "pattern":r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"subprocess with shell=True expands metacharacters.","lang":["py"]},
    {"rule_id":"W-A03-003","title":"Command Injection - os.system()",
     "pattern":r'os\.system\s*\(',"severity":HIGH,"category":"web",
     "owasp_category":"A03:2021 - Injection",
     "description":"os.system() passes to shell - injection risk.","lang":["py"]},
    {"rule_id":"W-A03-J002","title":"Command Injection - Runtime.exec() (Java)",
     "pattern":r'Runtime\.getRuntime\(\)\.exec\s*\(',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"Runtime.exec() with user input = OS command injection.","lang":["java","kt"]},
    {"rule_id":"W-A03-004","title":"SSTI - render_template_string",
     "pattern":r'render_template_string\s*\(',"severity":HIGH,"category":"web",
     "owasp_category":"A03:2021 - Injection",
     "description":"render_template_string with user input = SSTI.","lang":["py"]},
    {"rule_id":"W-A03-005","title":"Code Injection - eval() With Variable",
     "pattern":r'\beval\s*\(\s*(?!["\'])',"severity":CRITICAL,"category":"web",
     "owasp_category":"A03:2021 - Injection",
     "description":"eval() with variable = RCE if user-controlled.","lang":["py"]},
    {"rule_id":"W-A05-001","title":"Misconfiguration - DEBUG=True",
     "pattern":r'\bDEBUG\s*=\s*True\b',"severity":HIGH,"category":"web",
     "owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"DEBUG=True exposes stack traces and internals.","lang":["py"]},
    {"rule_id":"W-A05-002","title":"Misconfiguration - CORS Wildcard",
     "pattern":r'(?:allow_origins|CORS_ORIGIN|Access-Control-Allow-Origin|allowedOrigins)\s*[=:]\s*["\']?\*["\']?|origins\s*=\s*\[["\']\*["\']',
     "severity":HIGH,"category":"web","owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"CORS wildcard allows any origin.","lang":["py","java","kt"]},
    {"rule_id":"W-A07-001","title":"Auth Failure - JWT algorithm=none",
     "pattern":r'algorithm\s*=\s*["\']none["\']',
     "severity":CRITICAL,"category":"web",
     "owasp_category":"A07:2021 - Identification and Authentication Failures",
     "description":"JWT none algorithm disables signature verification.","lang":["py","java","kt"]},
    {"rule_id":"W-A07-002","title":"Auth Failure - JWT Verification Disabled",
     "pattern":r'(?:verify\s*=\s*False|["\']verify_signature["\']\s*:\s*False)',
     "severity":CRITICAL,"category":"web",
     "owasp_category":"A07:2021 - Identification and Authentication Failures",
     "description":"JWT signature verification disabled.","lang":["py"]},
    {"rule_id":"W-A08-001","title":"Insecure Deserialization - pickle.loads()",
     "pattern":r'pickle\.(?:load|loads)\s*\(',"severity":CRITICAL,"category":"web",
     "owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"pickle on untrusted data = RCE.","lang":["py"]},
    {"rule_id":"W-A08-002","title":"Insecure Deserialization - yaml.load() Unsafe",
     "pattern":r'\byaml\.load\s*\(',"severity":HIGH,"category":"web",
     "owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"yaml.load() without SafeLoader = RCE. Use yaml.safe_load().",
     "lang":["py"],"negative_lookahead":r'(?:SafeLoader|yaml\.safe_load)'},
    {"rule_id":"W-A08-J001","title":"Insecure Deserialization - Java ObjectInputStream",
     "pattern":r'new\s+ObjectInputStream\s*\(',"severity":CRITICAL,"category":"web",
     "owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"Java deserialization on untrusted data = RCE.","lang":["java","kt"]},
    {"rule_id":"W-A09-001","title":"Logging Failure - Sensitive Data in Logs",
     "pattern":r'(?:log(?:ger)?|logging|print)\b.{0,30}(?:password|secret|token|api_key|passwd)',
     "severity":HIGH,"category":"web","owasp_category":"A09:2021 - Security Logging Failures",
     "description":"Sensitive data may be written to logs.","lang":["py","java","kt"]},
    {"rule_id":"W-A10-001","title":"SSRF - User-Controlled URL in HTTP Request",
     "pattern":r'requests?\s*\.(?:get|post|put|delete|patch)\s*\(\s*(?:url\s*=\s*)?(?:request\.|req\.|args\.|data\.|params\.)',
     "severity":HIGH,"category":"web","owasp_category":"A10:2021 - Server-Side Request Forgery",
     "description":"HTTP request to user-controlled URL = SSRF.","lang":["py"]},
    {"rule_id":"W-A10-J001","title":"SSRF - URL From User Input (Java)",
     "pattern":r'new\s+URL\s*\(\s*(?:request|param|input|body)',
     "severity":HIGH,"category":"web","owasp_category":"A10:2021 - Server-Side Request Forgery",
     "description":"URL from user input = SSRF.","lang":["java","kt"]},
    # ── OWASP API Top 10 ──────────────────────────────────────────────────
    {"rule_id":"API-001-001","title":"BOLA - Object Fetched by Request ID Without Ownership Check",
     "pattern":r'(?:get_object_or_404|session\.get|db\.query)\s*\([^)]*(?:id\s*=\s*(?:request\.|req\.|args\.)|pk\s*=\s*(?:request\.|req\.))',
     "severity":CRITICAL,"category":"api","owasp_category":"API1:2023 - Broken Object Level Authorization",
     "description":"Object fetched by request ID without ownership check (BOLA/IDOR).","lang":["py"]},
    {"rule_id":"API-003-001","title":"Mass Assignment - Direct Request Body Binding",
     "pattern":r'(?:\.model_validate\(request|from_orm\(request|\.update\(\*\*request\.json|\.update\(\*\*data\b)',
     "severity":HIGH,"category":"api","owasp_category":"API3:2023 - Broken Object Property Level Authorization",
     "description":"Request body bound to model without field whitelisting.","lang":["py"]},
    {"rule_id":"API-003-J001","title":"Mass Assignment - @RequestBody Without @Valid",
     "pattern":r'public\s+\S+\s+\w+\s*\(\s*@RequestBody\s+(?!\S*@Valid)',
     "severity":HIGH,"category":"api","owasp_category":"API3:2023 - Broken Object Property Level Authorization",
     "description":"@RequestBody without @Valid skips bean validation.","lang":["java","kt"]},
    {"rule_id":"API-004-001","title":"No Pagination - Returns All Records",
     "pattern":r'(?:\.all\(\)|\.fetchall\(\)|\.find\s*\(\s*\{\s*\})',
     "severity":MEDIUM,"category":"api","owasp_category":"API4:2023 - Unrestricted Resource Consumption",
     "description":"Query with no pagination can exhaust resources.",
     "lang":["py"],"negative_lookahead":r'(?:limit|paginate|page_size|per_page)'},
    {"rule_id":"API-009-001","title":"Stale API Version Endpoint",
     "pattern":r'(?:/v[0-9]+/|/api/v[0-9]+/|prefix\s*=\s*["\'][^"\']*v[0-9])',
     "severity":LOW,"category":"api","owasp_category":"API9:2023 - Improper Inventory Management",
     "description":"Versioned endpoint - ensure deprecated versions are decommissioned.",
     "lang":["py","java","kt"]},
    # ── OWASP LLM / AI Top 10 ─────────────────────────────────────────────
    {"rule_id":"AI-LLM01-001","title":"Prompt Injection - User Input in f-string Prompt",
     "pattern":r'(?:prompt|system_prompt|content|messages?)\s*=\s*f["\'][^"\']*\{(?:user|input|query|request|body|text|message)',
     "severity":CRITICAL,"category":"ai","owasp_category":"LLM01:2025 - Prompt Injection",
     "description":"User input directly interpolated into LLM prompt.","lang":["py"]},
    {"rule_id":"AI-LLM01-002","title":"Prompt Injection - String Concat into LLM Call",
     "pattern":r'(?:\.invoke|\.complete|\.chat|\.create|\.generate)\s*\([^)]*(?:\+\s*(?:user|input|query|request)|(?:user|input|query)\s*\+)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM01:2025 - Prompt Injection",
     "description":"LLM called with string-concatenated user input.","lang":["py"]},
    {"rule_id":"AI-LLM01-J001","title":"Prompt Injection - User Input in LLM Prompt (Java)",
     "pattern":r'(?:prompt|message|content)\s*[+=]\s*.*(?:request|input|body|param)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM01:2025 - Prompt Injection",
     "description":"User input concatenated into LLM prompt.","lang":["java","kt"]},
    {"rule_id":"AI-LLM02-001","title":"Insecure Output - LLM Response in eval()",
     "pattern":r'\beval\s*\([^)]*(?:response|completion|output|result|content|llm|gpt|claude|gemini)',
     "severity":CRITICAL,"category":"ai","owasp_category":"LLM02:2025 - Insecure Output Handling",
     "description":"LLM output passed to eval() = RCE.","lang":["py"]},
    {"rule_id":"AI-LLM02-002","title":"Insecure Output - LLM Response in exec()",
     "pattern":r'\bexec\s*\([^)]*(?:response|completion|output|result|content|llm|gpt|claude|gemini)',
     "severity":CRITICAL,"category":"ai","owasp_category":"LLM02:2025 - Insecure Output Handling",
     "description":"LLM output passed to exec() = RCE.","lang":["py"]},
    {"rule_id":"AI-LLM02-003","title":"Insecure Output - LLM Response as Raw HTML",
     "pattern":r'(?:render_template_string|mark_safe|Markup)\s*\([^)]*(?:response|completion|output|result)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM02:2025 - Insecure Output Handling",
     "description":"LLM output rendered as unescaped HTML = XSS.","lang":["py"]},
    {"rule_id":"AI-LLM05-001","title":"Supply Chain - Unverified External Model",
     "pattern":r'(?:from_pretrained|hub\.load|AutoModel\.from_pretrained|AutoTokenizer\.from_pretrained)\s*\(\s*["\'][^"\']+["\']',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM05:2025 - Supply Chain Vulnerabilities",
     "description":"Model loaded without pinned revision hash.",
     "lang":["py"],"negative_lookahead":r'(?:revision\s*=|sha\s*=)'},
    {"rule_id":"AI-LLM06-001","title":"Sensitive Data in LLM System Prompt",
     "pattern":r'(?:system_prompt|prompt_template|system_message)\s*=\s*["\'][^"\']*(?:password|secret|api_key|private_key)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM06:2025 - Sensitive Information Disclosure",
     "description":"Secrets/PII embedded in LLM system prompt.","lang":["py"]},
    {"rule_id":"AI-LLM08-001","title":"Excessive Agency - LLM With Shell/File Tools",
     "pattern":r'(?:tools|functions)\s*=.{0,200}(?:bash|shell|execute|run_code|subprocess|os\.system)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM08:2025 - Excessive Agency",
     "description":"LLM agent granted shell/file system capabilities.","lang":["py"]},
    {"rule_id":"AI-LLM09-001","title":"Overreliance - LLM Output Used Without Validation",
     "pattern":r'(?:response|completion|output|result)\s*=\s*(?:client|llm|chain|agent|model)\.(?:invoke|complete|chat|generate|run)\s*\(',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM09:2025 - Overreliance",
     "description":"LLM output used directly without validation.",
     "lang":["py"],"negative_lookahead":r'(?:if\s|assert|validate|check|verify|sanitize|parse)'},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A01 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A01-003","title":"Path Traversal - Directory Traversal Sequence",
     "pattern":r'(?:open|read|send_file|send_from_directory|render_template)\s*\([^)]*(?:\.\./|\.\.\\\\)',
     "severity":CRITICAL,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"Path traversal sequence in file operation — sanitize and validate all file paths.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A01-004","title":"Path Traversal - User-Controlled File Path",
     "pattern":r'(?:open|Path|FileInputStream|new\s+File)\s*\([^)]*(?:request\.|req\.|args\.|params\.|getParameter)',
     "severity":HIGH,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"File path derived from user input without sanitization.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A01-005","title":"Hardcoded Role Check - Admin Bypass Risk",
     "pattern":r'if\s+(?:user|username|role|request\.\w+)\s*==\s*["\'](?:admin|root|superuser|administrator)["\']',
     "severity":HIGH,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"Hardcoded role string comparison is fragile and trivially bypassed.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A01-006","title":"Missing CSRF Protection on State-Changing Route",
     "pattern":r'@(?:app|router|blueprint)\.(?:post|put|delete|patch)\s*\([^)]+\)',
     "severity":MEDIUM,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"State-changing route may lack CSRF protection.",
     "lang":["py"],"negative_lookahead":r'(?:csrf|CSRFProtect|WTForms|csrf_exempt|csrf_protect)'},
    {"rule_id":"W-A01-007","title":"Admin Endpoint Without Auth Check",
     "pattern":r'@(?:app|router|blueprint)\.route\s*\(["\'][^"\']*(?:admin|manage|internal|dashboard)',
     "severity":HIGH,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"Admin/internal route without visible auth decorator.",
     "lang":["py"],"negative_lookahead":r'@(?:login_required|admin_required|requires_auth|jwt_required|permission_required)'},
    {"rule_id":"W-A01-J002","title":"Missing @PreAuthorize on Admin Spring Endpoint",
     "pattern":r'@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\([^)]*(?:admin|manage|internal)',
     "severity":HIGH,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"Admin endpoint in Spring controller without @PreAuthorize or @Secured.",
     "lang":["java","kt"],"negative_lookahead":r'@(?:PreAuthorize|Secured|RolesAllowed)'},
    {"rule_id":"W-A01-008","title":"Insecure File Upload - No Extension Validation",
     "pattern":r'(?:request\.files|MultipartFile|upload|save)\s*\(',
     "severity":HIGH,"category":"web","owasp_category":"A01:2021 - Broken Access Control",
     "description":"File upload without extension/MIME validation — may allow executable upload.",
     "lang":["py","java","kt"],"negative_lookahead":r'(?:extension|mimetype|content_type|allowedTypes|whitelist|endswith)'},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A02 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A02-005","title":"Weak Crypto - DES/3DES (Java)",
     "pattern":r'(?:Cipher\.getInstance|KeyGenerator\.getInstance)\s*\(\s*["\'](?:DES|DESede|3DES)',
     "severity":HIGH,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"DES and 3DES are deprecated and broken. Use AES-256-GCM.",
     "lang":["java","kt"]},
    {"rule_id":"W-A02-006","title":"Weak Crypto - ECB Mode",
     "pattern":r'Cipher\.getInstance\s*\(\s*["\'][^"\']*\/ECB\/',
     "severity":HIGH,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"ECB mode leaks block patterns. Use AES-GCM or AES-CBC with random IV.",
     "lang":["java","kt"]},
    {"rule_id":"W-A02-007","title":"Insecure Randomness - random Module Used for Security",
     "pattern":r'(?:random\.random|random\.randint|random\.choice|random\.randrange|random\.token)\s*\(',
     "severity":MEDIUM,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Python random module is not cryptographically secure. Use secrets module.",
     "lang":["py"]},
    {"rule_id":"W-A02-008","title":"TLS Verification Disabled",
     "pattern":r'verify\s*=\s*False',
     "severity":HIGH,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"TLS certificate verification disabled — vulnerable to MITM attacks.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A02-009","title":"Hardcoded Encryption Key or IV",
     "pattern":r'(?:^|\s)(?:iv|salt|nonce|aes_key|enc_key)\s*=\s*b?["\'][^"\']{8,}["\']',
     "severity":HIGH,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Hardcoded cryptographic material weakens encryption.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A02-010","title":"Base64 Used as Encryption",
     "pattern":r'base64\.(?:b64encode|encodebytes)\s*\([^)]*(?:password|secret|token|key)',
     "severity":MEDIUM,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Base64 is encoding, not encryption — provides zero confidentiality.",
     "lang":["py"]},
    {"rule_id":"W-A02-011","title":"Weak RSA Key Size (Java)",
     "pattern":r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']',
     "severity":MEDIUM,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Verify RSA key is at least 2048 bits. 1024 and 512 are broken.",
     "lang":["java","kt"],"negative_lookahead":r'initialize\s*\(\s*(?:2048|3072|4096)'},
    {"rule_id":"W-A02-012","title":"Plain Hash for Password - No KDF",
     "pattern":r'hashlib\.(?:sha256|sha512|sha1|md5)\s*\([^)]*(?:password|passwd|pwd)',
     "severity":HIGH,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Raw SHA/MD5 for passwords is vulnerable to rainbow tables. Use bcrypt/argon2/scrypt.",
     "lang":["py"]},
    {"rule_id":"W-A02-013","title":"Weak PBKDF2 Iteration Count",
     "pattern":r'pbkdf2_hmac\s*\([^)]*iterations\s*=\s*(\d+)',
     "severity":HIGH,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"PBKDF2 with fewer than 600,000 iterations (NIST 2023) is too weak.",
     "lang":["py"],"negative_lookahead":r'iterations\s*=\s*[6-9]\d{5,}'},
    {"rule_id":"W-A02-014","title":"Sensitive Data in Environment Config - Plaintext",
     "pattern":r'os\.environ\.get\s*\(\s*["\'](?:DB_PASS|DATABASE_URL|SECRET_KEY|PRIVATE_KEY)["\']',
     "severity":LOW,"category":"web","owasp_category":"A02:2021 - Cryptographic Failures",
     "description":"Verify these env vars are populated from a secrets manager, not hardcoded in .env files committed to source.",
     "lang":["py"]},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A03 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A03-006","title":"NoSQL Injection - MongoDB Query From User Input",
     "pattern":r'(?:find|find_one|update_one|delete_one|aggregate)\s*\(\s*\{[^}]*(?:request\.|req\.|args\.|params\.|data\.)',
     "severity":HIGH,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"MongoDB query built from user input — NoSQL operator injection risk.",
     "lang":["py"]},
    {"rule_id":"W-A03-007","title":"LDAP Injection - Filter Built From User Input",
     "pattern":r'(?:ldap|LDAP).*(?:search|filter)\s*\([^)]*(?:request\.|req\.|args\.|user|input)',
     "severity":HIGH,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"LDAP search filter with user input — inject * or ) to bypass auth.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A03-008","title":"XXE - Insecure XML Parser (Python)",
     "pattern":r'(?:etree\.parse|etree\.fromstring|minidom\.parse|parseString)\s*\(',
     "severity":HIGH,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"Python XML parser with default settings allows external entity expansion (XXE).",
     "lang":["py"],"negative_lookahead":r'defusedxml'},
    {"rule_id":"W-A03-J003","title":"XXE - DocumentBuilderFactory Without Hardening (Java)",
     "pattern":r'DocumentBuilderFactory\.newInstance\s*\(\s*\)',
     "severity":HIGH,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"DocumentBuilderFactory without disabling external entities is XXE-vulnerable.",
     "lang":["java","kt"],"negative_lookahead":r'(?:setFeature|FEATURE_SECURE_PROCESSING|XMLConstants)'},
    {"rule_id":"W-A03-009","title":"Log Injection - Raw User Input in Log Statement",
     "pattern":r'(?:logger|logging|log)\.\w+\s*\([^)]*(?:request\.|req\.|args\.|params\.|input|user_input)',
     "severity":MEDIUM,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"Unsanitized user input in log messages enables log forging.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A03-J004","title":"JNDI Injection - Log4Shell Expression Pattern",
     "pattern":r'\$\{(?:jndi|java|env|sys|lower|upper|:-)',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"JNDI lookup expression — Log4Shell (CVE-2021-44228) pattern detected.",
     "lang":["java","kt"]},
    {"rule_id":"W-A03-J005","title":"SpEL Injection - Expression Parser With User Input",
     "pattern":r'(?:ExpressionParser|SpelExpressionParser|parseExpression)\s*\([^)]*(?:request|input|param|body)',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"Spring SpEL parser with user input enables RCE.",
     "lang":["java","kt"]},
    {"rule_id":"W-A03-J006","title":"Command Injection - ProcessBuilder With User Input",
     "pattern":r'new\s+ProcessBuilder\s*\([^)]*(?:request|input|param|body|user)',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"ProcessBuilder with user-controlled input enables OS command injection.",
     "lang":["java","kt"]},
    {"rule_id":"W-A03-010","title":"XSS - User Input Marked Safe Without Sanitization",
     "pattern":r'(?:Markup|mark_safe)\s*\([^)]*(?:request\.|req\.|args\.|params\.|user|input)',
     "severity":HIGH,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"User input rendered as raw HTML without sanitization — XSS.",
     "lang":["py"]},
    {"rule_id":"W-A03-011","title":"SQL Injection - % String Format in Query",
     "pattern":r'["\'](?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*%[sd][^"\']*["\']\s*%',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"SQL query built with % string formatting — SQL injection.",
     "lang":["py"]},
    {"rule_id":"W-A03-012","title":"Code Injection - exec() With Variable",
     "pattern":r'\bexec\s*\(\s*(?!["\'])',"severity":CRITICAL,"category":"web",
     "owasp_category":"A03:2021 - Injection",
     "description":"exec() with variable input = RCE if user-controlled.",
     "lang":["py"]},
    {"rule_id":"W-A03-013","title":"SSTI - Jinja2 Template From User Input",
     "pattern":r'Environment\s*\([^)]*\).*from_string\s*\([^)]*(?:request|input|user)',
     "severity":CRITICAL,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"Jinja2 template created from user input enables SSTI/RCE.",
     "lang":["py"]},
    {"rule_id":"W-A03-014","title":"Header Injection - User Input in HTTP Response Header",
     "pattern":r'(?:response\.headers|set_header|add_header)\s*\[[^\]]+\]\s*=\s*(?:request\.|req\.|args\.|params\.)',
     "severity":HIGH,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"User input written to response header enables header injection / redirect.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A03-015","title":"XPath Injection - User Input in XPath Query",
     "pattern":r'(?:xpath|XPath|selectNodes|evaluate)\s*\([^)]*(?:request|input|param|user)',
     "severity":HIGH,"category":"web","owasp_category":"A03:2021 - Injection",
     "description":"XPath query built from user input — XPath injection risk.",
     "lang":["py","java","kt"]},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A04 Insecure Design
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A04-001","title":"Insecure Design - No Rate Limiting on Auth Endpoint",
     "pattern":r'@(?:app|router|blueprint)\.(?:route|post)\s*\(["\'][^"\']*(?:login|signin|auth|token|password)',
     "severity":MEDIUM,"category":"web","owasp_category":"A04:2021 - Insecure Design",
     "description":"Auth endpoint without rate limiting is vulnerable to brute force.",
     "lang":["py"],"negative_lookahead":r'(?:limiter|rate_limit|throttle|RateLimit|slowapi|Limiter)'},
    {"rule_id":"W-A04-002","title":"Insecure Design - Numeric Input Without Bounds Check",
     "pattern":r'(?:amount|quantity|price|balance|count)\s*=\s*(?:request\.|req\.|data\.|args\.|int\s*\()',
     "severity":MEDIUM,"category":"web","owasp_category":"A04:2021 - Insecure Design",
     "description":"Numeric value from user input without positive/bounds validation.",
     "lang":["py","java","kt"],"negative_lookahead":r'(?:> 0|>0|>= 0|abs\(|max\(|min\(|assert)'},
    {"rule_id":"W-A04-003","title":"Insecure Design - Password Reset Without Expiry",
     "pattern":r'def\s+(?:reset_password|forgot_password|send_reset|generate_reset)\s*\(',
     "severity":MEDIUM,"category":"web","owasp_category":"A04:2021 - Insecure Design",
     "description":"Password reset function — verify token has short TTL and single-use enforcement.",
     "lang":["py","java","kt"],"negative_lookahead":r'(?:expires|expiry|timedelta|ttl|exp|timeout)'},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A05 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A05-003","title":"Misconfiguration - Default Credentials in Source",
     "pattern":r'(?:password|passwd|secret)\s*=\s*["\'](?:admin|root|test|default|guest|password|changeme|123456|qwerty)["\']',
     "severity":CRITICAL,"category":"web","owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"Default/common password found in source. Rotate before deploying.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A05-004","title":"Misconfiguration - Stack Trace Returned to Client",
     "pattern":r'(?:traceback\.format_exc|traceback\.print_exc|e\.printStackTrace)\s*\(',
     "severity":MEDIUM,"category":"web","owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"Full stack trace returned to user reveals internal implementation details.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A05-005","title":"Misconfiguration - Swagger/API Docs Exposed",
     "pattern":r'(?:swagger-ui|/swagger|/api-docs|/openapi\.json|springfox|SwaggerUI)',
     "severity":MEDIUM,"category":"web","owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"API documentation endpoint may be publicly accessible in production.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A05-006","title":"Misconfiguration - S3 Bucket Public Access",
     "pattern":r'(?:ACL\s*=\s*["\']public-read|public-read-write|AllUsers|PublicRead)',
     "severity":CRITICAL,"category":"web","owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"S3 bucket or object configured with public ACL — data exposure risk.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A05-007","title":"Misconfiguration - allow_origins Wildcard in Production CORS",
     "pattern":r'allow_origins\s*=\s*\[["\']?\*["\']?\]',
     "severity":HIGH,"category":"web","owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"CORS allow_origins=[*] enables cross-site credential theft.",
     "lang":["py"]},
    {"rule_id":"W-A05-008","title":"Misconfiguration - Debug Server Startup",
     "pattern":r'(?:app\.run|uvicorn\.run)\s*\([^)]*debug\s*=\s*True',
     "severity":HIGH,"category":"web","owasp_category":"A05:2021 - Security Misconfiguration",
     "description":"Debug mode enabled at server startup — never use in production.",
     "lang":["py"]},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A07 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A07-003","title":"Auth Failure - JWT Issued Without Expiry Claim",
     "pattern":r'jwt\.encode\s*\([^)]*\)',
     "severity":HIGH,"category":"web","owasp_category":"A07:2021 - Identification and Authentication Failures",
     "description":"JWT issued without exp claim — tokens never expire.",
     "lang":["py"],"negative_lookahead":r'(?:exp|expires|expiry|timedelta|datetime)'},
    {"rule_id":"W-A07-004","title":"Auth Failure - Session Token in URL Parameter",
     "pattern":r'(?:session_id|sessionid|JSESSIONID|auth_token)\s*=\s*(?:request\.|req\.)(?:args|params|query)\.',
     "severity":HIGH,"category":"web","owasp_category":"A07:2021 - Identification and Authentication Failures",
     "description":"Session ID in URL appears in server logs and Referer headers.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A07-005","title":"Auth Failure - Password Compared in Plaintext",
     "pattern":r'(?:password|passwd)\s*==\s*(?:request\.|req\.|data\.|args\.)\w+',
     "severity":CRITICAL,"category":"web","owasp_category":"A07:2021 - Identification and Authentication Failures",
     "description":"Password compared as plaintext string — must use constant-time hash comparison.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A07-J002","title":"Auth Failure - JWT Without Expiry (Java)",
     "pattern":r'Jwts\.builder\s*\(\s*\)',
     "severity":MEDIUM,"category":"web","owasp_category":"A07:2021 - Identification and Authentication Failures",
     "description":"Review JWT builder for missing .expiration() call.",
     "lang":["java","kt"],"negative_lookahead":r'\.expiration\s*\(|\.setExpiration\s*\('},
    {"rule_id":"W-A07-006","title":"Auth Failure - Predictable Token Generation",
     "pattern":r'(?:token|session_id|csrf_token)\s*=\s*str\s*\(\s*(?:int|uuid\.uuid1|time\.time|random)',
     "severity":HIGH,"category":"web","owasp_category":"A07:2021 - Identification and Authentication Failures",
     "description":"Token generated from predictable source — use secrets.token_urlsafe().",
     "lang":["py"]},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A08 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A08-003","title":"Insecure Deserialization - marshal.loads()",
     "pattern":r'marshal\.loads?\s*\(',"severity":CRITICAL,"category":"web",
     "owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"marshal.loads on untrusted data enables arbitrary code execution.",
     "lang":["py"]},
    {"rule_id":"W-A08-004","title":"Insecure Deserialization - jsonpickle.decode()",
     "pattern":r'jsonpickle\.(?:decode|loads)\s*\(',"severity":CRITICAL,"category":"web",
     "owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"jsonpickle.decode on untrusted input = RCE via __reduce__.",
     "lang":["py"]},
    {"rule_id":"W-A08-005","title":"Insecure Deserialization - shelve With User Input",
     "pattern":r'shelve\.open\s*\([^)]*(?:request\.|req\.|args\.|params\.|user|input)',
     "severity":HIGH,"category":"web","owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"shelve uses pickle internally — unsafe with user-controlled keys.",
     "lang":["py"]},
    {"rule_id":"W-A08-J002","title":"Insecure Deserialization - XStream Without Whitelist",
     "pattern":r'(?:XStream|xstream).*(?:fromXML|fromJSON)\s*\(',
     "severity":CRITICAL,"category":"web","owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"XStream deserialization without class whitelist enables RCE.",
     "lang":["java","kt"],"negative_lookahead":r'(?:addPermission|allowTypes|setupDefaultSecurity)'},
    {"rule_id":"W-A08-006","title":"Integrity Failure - Downloaded File Without Checksum",
     "pattern":r'(?:urllib\.request\.urlretrieve|requests\.get\s*\([^)]+\)\.content)',
     "severity":MEDIUM,"category":"web","owasp_category":"A08:2021 - Software and Data Integrity Failures",
     "description":"File downloaded without integrity verification (SHA256 checksum).",
     "lang":["py"],"negative_lookahead":r'(?:sha256|md5sum|checksum|verify|hash)'},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A09 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A09-002","title":"Logging Failure - Exception Message Returned to Client",
     "pattern":r'(?:return|jsonify|Response)\s*\([^)]*str\s*\(\s*(?:e|err|error|exception)\s*\)',
     "severity":MEDIUM,"category":"web","owasp_category":"A09:2021 - Security Logging Failures",
     "description":"Raw exception message returned to client leaks internal details.",
     "lang":["py"]},
    {"rule_id":"W-A09-003","title":"Logging Failure - Auth Function Missing Audit Log",
     "pattern":r'def\s+(?:login|signin|authenticate|verify_token|check_password)\s*\([^)]*\)',
     "severity":LOW,"category":"web","owasp_category":"A09:2021 - Security Logging Failures",
     "description":"Auth function without visible audit logging of success/failure.",
     "lang":["py","java","kt"],"negative_lookahead":r'(?:log|audit|logger|LOG|print)'},
    {"rule_id":"W-A09-J001","title":"Logging Failure - printStackTrace Instead of Logger",
     "pattern":r'\.printStackTrace\s*\(\s*\)',"severity":MEDIUM,"category":"web",
     "owasp_category":"A09:2021 - Security Logging Failures",
     "description":"printStackTrace bypasses structured logging — use a logger.",
     "lang":["java","kt"]},
    {"rule_id":"W-A09-004","title":"Logging Failure - Credentials Logged at DEBUG Level",
     "pattern":r'(?:log\.debug|LOG\.debug|logger\.debug)\s*\([^)]*(?:password|secret|token|key|credential)',
     "severity":HIGH,"category":"web","owasp_category":"A09:2021 - Security Logging Failures",
     "description":"Credential logged at debug level — may appear in log files.",
     "lang":["py","java","kt"]},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — Web A10 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"W-A10-002","title":"SSRF - urllib With User-Controlled URL",
     "pattern":r'urllib\.(?:request\.urlopen|urlopen)\s*\([^)]*(?:request\.|req\.|args\.|params\.)',
     "severity":HIGH,"category":"web","owasp_category":"A10:2021 - Server-Side Request Forgery",
     "description":"urllib with user-controlled URL enables SSRF.",
     "lang":["py"]},
    {"rule_id":"W-A10-003","title":"SSRF - httpx/aiohttp With User-Controlled URL",
     "pattern":r'(?:httpx|aiohttp\.ClientSession\(\))\.(?:get|post|put|delete)\s*\([^)]*(?:request\.|req\.|args\.|params\.)',
     "severity":HIGH,"category":"web","owasp_category":"A10:2021 - Server-Side Request Forgery",
     "description":"Async HTTP client with user-controlled URL enables SSRF.",
     "lang":["py"]},
    {"rule_id":"W-A10-004","title":"SSRF - Cloud Metadata IP Detected",
     "pattern":r'(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)',
     "severity":CRITICAL,"category":"web","owasp_category":"A10:2021 - Server-Side Request Forgery",
     "description":"Cloud metadata service address in source — SSRF test or intentional bypass.",
     "lang":["py","java","kt"]},
    {"rule_id":"W-A10-J002","title":"SSRF - HttpURLConnection With User Input",
     "pattern":r'new\s+URL\s*\([^)]*\).*openConnection\s*\(\s*\)',
     "severity":HIGH,"category":"web","owasp_category":"A10:2021 - Server-Side Request Forgery",
     "description":"HttpURLConnection URL may be user-controlled — validate before connecting.",
     "lang":["java","kt"]},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — API Top 10 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"API-001-002","title":"BOLA - Dynamic Object ID in URL Path",
     "pattern":r'@(?:app|router|blueprint)\.(?:get|post|put|delete)\s*\(["\'][^"\']*<(?:int:)?(?:id|user_id|account_id|order_id|resource_id)',
     "severity":HIGH,"category":"api","owasp_category":"API1:2023 - Broken Object Level Authorization",
     "description":"Dynamic object ID in URL — verify the caller owns the referenced object.",
     "lang":["py"]},
    {"rule_id":"API-001-003","title":"BOLA - GraphQL Resolver Without Auth Context",
     "pattern":r'def\s+resolve_\w+\s*\(\s*self[^)]*\)',
     "severity":MEDIUM,"category":"api","owasp_category":"API1:2023 - Broken Object Level Authorization",
     "description":"GraphQL resolver — verify authorization context is checked before returning data.",
     "lang":["py"],"negative_lookahead":r'(?:context|info\.context|auth|permission|login_required|is_authenticated)'},
    {"rule_id":"API-002-001","title":"Broken Auth - API Key Passed as Query Parameter",
     "pattern":r'[?&](?:api_key|apikey|access_token|auth_token|token)\s*=',
     "severity":HIGH,"category":"api","owasp_category":"API2:2023 - Broken Authentication",
     "description":"API key in query string is logged in server logs and visible in browser history.",
     "lang":["py","java","kt"]},
    {"rule_id":"API-002-002","title":"Broken Auth - Long Hardcoded Token in Source",
     "pattern":r'(?:api_key|api_token|access_token|bearer)\s*=\s*["\'][A-Za-z0-9_\-\.]{30,}["\']',
     "severity":CRITICAL,"category":"api","owasp_category":"API2:2023 - Broken Authentication",
     "description":"Hardcoded API token. Rotate immediately and move to environment variables.",
     "lang":["py","java","kt"]},
    {"rule_id":"API-002-003","title":"Broken Auth - Sensitive Endpoint Without Auth Decorator",
     "pattern":r'@(?:app|router)\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']*(?:user|account|payment|order|admin|profile)',
     "severity":HIGH,"category":"api","owasp_category":"API2:2023 - Broken Authentication",
     "description":"Sensitive API endpoint without visible auth decorator.",
     "lang":["py"],"negative_lookahead":r'(?:login_required|jwt_required|requires_auth|authenticate|token_required|Depends)'},
    {"rule_id":"API-003-002","title":"Excessive Data Exposure - Serializing Full Model Object",
     "pattern":r'(?:jsonify|json\.dumps)\s*\([^)]*\.__dict__|to_dict\s*\(\s*\)|vars\s*\(\s*\w+\s*\)',
     "severity":MEDIUM,"category":"api","owasp_category":"API3:2023 - Broken Object Property Level Authorization",
     "description":"Full model object serialized to response — may leak internal fields.",
     "lang":["py"]},
    {"rule_id":"API-004-002","title":"Resource Consumption - No Request Body Size Limit",
     "pattern":r'(?:request\.get_json|request\.data|request\.body|request\.stream)',
     "severity":LOW,"category":"api","owasp_category":"API4:2023 - Unrestricted Resource Consumption",
     "description":"Request body read without size limit — DoS via large payload.",
     "lang":["py","java","kt"],"negative_lookahead":r'(?:MAX_CONTENT_LENGTH|content_length|max_size|limit|MAX_UPLOAD)'},
    {"rule_id":"API-004-003","title":"Resource Consumption - HTTP Call Without Timeout",
     "pattern":r'requests?\s*\.(?:get|post|put|delete|patch)\s*\([^)]+\)',
     "severity":MEDIUM,"category":"api","owasp_category":"API4:2023 - Unrestricted Resource Consumption",
     "description":"HTTP call without timeout — hangs indefinitely if upstream stalls.",
     "lang":["py"],"negative_lookahead":r'timeout\s*='},
    {"rule_id":"API-005-001","title":"Broken Function Auth - Privileged Action Without Role Check",
     "pattern":r'def\s+(?:delete_user|reset_all|create_admin|promote_user|ban_user|admin_\w+|purge_\w+)\s*\(',
     "severity":HIGH,"category":"api","owasp_category":"API5:2023 - Broken Function Level Authorization",
     "description":"Privileged function — verify role/permission enforcement.",
     "lang":["py","java","kt"],"negative_lookahead":r'(?:admin_required|role|permission|authorize|is_admin|requires_role|PreAuthorize)'},
    {"rule_id":"API-006-001","title":"Sensitive Business Flow - Unbounded Bulk Operation",
     "pattern":r'for\s+\w+\s+in\s+(?:request\.|req\.|data\.|body\.)\w+\s*:',
     "severity":MEDIUM,"category":"api","owasp_category":"API6:2023 - Unrestricted Access to Sensitive Business Flows",
     "description":"Unbounded loop over user-supplied list — bulk abuse possible.",
     "lang":["py","java","kt"],"negative_lookahead":r'(?:len\(|limit|max_|MAX_|[:50]|[:100])'},
    {"rule_id":"API-007-001","title":"SSRF - Unvalidated Webhook or Callback URL",
     "pattern":r'(?:webhook_url|callback_url|notify_url|redirect_uri|return_url)\s*=\s*(?:request\.|req\.|args\.|data\.)\w+',
     "severity":HIGH,"category":"api","owasp_category":"API7:2023 - Server Side Request Forgery",
     "description":"Webhook/callback URL taken from user input without domain validation.",
     "lang":["py","java","kt"]},
    {"rule_id":"API-008-001","title":"API Misconfiguration - Exception Object in JSON Response",
     "pattern":r'(?:return|jsonify)\s*\([^)]*(?:traceback|stack_trace|__dict__|vars\s*\(\s*e)',
     "severity":MEDIUM,"category":"api","owasp_category":"API8:2023 - Security Misconfiguration",
     "description":"Exception internals serialized into API response.",
     "lang":["py"]},
    {"rule_id":"API-009-002","title":"Improper Inventory - Debug Endpoint in Production Code",
     "pattern":r'@(?:app|router|blueprint)\.(?:route|get|post)\s*\(["\'][^"\']*(?:/debug|/test|/dev|/_internal|/healthz)',
     "severity":MEDIUM,"category":"api","owasp_category":"API9:2023 - Improper Inventory Management",
     "description":"Debug/test/internal endpoint in production codebase.",
     "lang":["py"]},
    {"rule_id":"API-010-001","title":"Unsafe API Consumption - External Response Without Schema Validation",
     "pattern":r'(?:response|resp)\.json\s*\(\s*\)\s*(?:\.get|\[)["\']',
     "severity":LOW,"category":"api","owasp_category":"API10:2023 - Unsafe Consumption of APIs",
     "description":"Third-party API response accessed without schema validation.",
     "lang":["py"],"negative_lookahead":r'(?:validate|schema|parse|pydantic|marshmallow|TypeAdapter)'},
    {"rule_id":"API-010-002","title":"Unsafe API Consumption - Auth Claims From External API",
     "pattern":r'(?:response|resp)\.json\s*\(\s*\)(?:\.get|\[)["\'](?:role|admin|is_admin|permissions|scope)["\']',
     "severity":HIGH,"category":"api","owasp_category":"API10:2023 - Unsafe Consumption of APIs",
     "description":"Authorization claims trusted from external API without local verification.",
     "lang":["py"]},

    # ══════════════════════════════════════════════════════════════════════
    # EXPANDED RULES — LLM / AI Top 10 Additional
    # ══════════════════════════════════════════════════════════════════════
    {"rule_id":"AI-LLM01-003","title":"Prompt Injection - Override Pattern in Source Strings",
     "pattern":r'(?:ignore|forget|disregard)\s+(?:previous|all|your)\s+(?:instructions|rules|prompt|system)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM01:2025 - Prompt Injection",
     "description":"Classic prompt injection override phrase found in source — may be in test data or user-facing strings.",
     "lang":["py","java","kt"]},
    {"rule_id":"AI-LLM01-004","title":"Prompt Injection - External Data Injected Into LLM Context",
     "pattern":r'(?:messages|context|prompt)\s*\+?=\s*.*(?:fetch|requests\.|urlopen|read_file|open\s*\()',
     "severity":HIGH,"category":"ai","owasp_category":"LLM01:2025 - Prompt Injection",
     "description":"External/file data appended to LLM context without sanitization — indirect prompt injection.",
     "lang":["py"]},
    {"rule_id":"AI-LLM01-005","title":"Prompt Injection - Role-Play Override in Prompt Template",
     "pattern":r'(?:you are now|act as|pretend you are|roleplay as|new persona|DAN mode)',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM01:2025 - Prompt Injection",
     "description":"Role-play override instruction in prompt template or test data.",
     "lang":["py","java","kt"]},
    {"rule_id":"AI-LLM02-004","title":"Insecure Output - LLM Response Passed to subprocess",
     "pattern":r'subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*(?:response|completion|output|result|llm|gpt)',
     "severity":CRITICAL,"category":"ai","owasp_category":"LLM02:2025 - Insecure Output Handling",
     "description":"LLM output passed to subprocess — OS command injection via prompt.",
     "lang":["py"]},
    {"rule_id":"AI-LLM02-005","title":"Insecure Output - LLM Response Used in SQL Query",
     "pattern":r'(?:execute|cursor\.execute)\s*\([^)]*(?:response|completion|output|result|llm)',
     "severity":CRITICAL,"category":"ai","owasp_category":"LLM02:2025 - Insecure Output Handling",
     "description":"LLM output embedded in SQL query — SQL injection via adversarial prompt.",
     "lang":["py"]},
    {"rule_id":"AI-LLM02-006","title":"Insecure Output - LLM Response Written to File",
     "pattern":r'(?:\.write|\.writelines)\s*\([^)]*(?:response|completion|output|result|llm)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM02:2025 - Insecure Output Handling",
     "description":"LLM output written to file without content validation.",
     "lang":["py"]},
    {"rule_id":"AI-LLM03-001","title":"Training Data Poisoning - User Input Fed to Training Pipeline",
     "pattern":r'(?:fine_tune|finetune|training_data|train_data|dataset\.add|dataset\.append)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM03:2025 - Training Data Poisoning",
     "description":"User-contributed data fed into training pipeline without curation/filtering.",
     "lang":["py"]},
    {"rule_id":"AI-LLM04-001","title":"Model DoS - Unbounded or Extreme Token Limit",
     "pattern":r'max_tokens\s*=\s*(?:None|-1|[5-9]\d{3,}|\d{5,})',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM04:2025 - Model Denial of Service",
     "description":"No token limit or extremely high limit set — resource exhaustion risk.",
     "lang":["py"]},
    {"rule_id":"AI-LLM04-002","title":"Model DoS - LLM Call Without Timeout",
     "pattern":r'(?:client|llm|openai|anthropic|model)\.(?:chat\.completions\.create|invoke|complete|generate)\s*\([^)]+\)',
     "severity":LOW,"category":"ai","owasp_category":"LLM04:2025 - Model Denial of Service",
     "description":"LLM API call without timeout — hangs indefinitely on model failure.",
     "lang":["py"],"negative_lookahead":r'timeout\s*='},
    {"rule_id":"AI-LLM05-002","title":"Supply Chain - Model Downloaded From Arbitrary URL",
     "pattern":r'(?:torch\.hub\.load|urllib\.request|requests\.get)\s*\([^)]*(?:model|weights|checkpoint)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM05:2025 - Supply Chain Vulnerabilities",
     "description":"Model weights fetched from URL without integrity check.",
     "lang":["py"],"negative_lookahead":r'(?:sha256|checksum|verify|hash)'},
    {"rule_id":"AI-LLM06-002","title":"Sensitive Data - PII in LLM Prompt",
     "pattern":r'(?:prompt|content|message)\s*=.*(?:ssn|social_security|credit_card|dob|date_of_birth|passport_number)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM06:2025 - Sensitive Information Disclosure",
     "description":"PII directly embedded in LLM prompt — data leakage to model provider.",
     "lang":["py"]},
    {"rule_id":"AI-LLM06-003","title":"Sensitive Data - System Prompt Written to Logs",
     "pattern":r'(?:log|print|logger)\s*\([^)]*(?:system_prompt|prompt_template|system_message)',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM06:2025 - Sensitive Information Disclosure",
     "description":"System prompt logged — reveals application instructions and business logic.",
     "lang":["py"]},
    {"rule_id":"AI-LLM06-004","title":"Sensitive Data - Database Credentials in LLM Context",
     "pattern":r'(?:prompt|context|messages)\s*=.*(?:DB_PASS|DATABASE_URL|connection_string|db_password)',
     "severity":CRITICAL,"category":"ai","owasp_category":"LLM06:2025 - Sensitive Information Disclosure",
     "description":"Database credentials included in LLM context window.",
     "lang":["py"]},
    {"rule_id":"AI-LLM07-001","title":"Insecure Plugin - Tool Function Without Input Validation",
     "pattern":r'@tool\s*\n\s*def\s+\w+\s*\(\s*\w+\s*:\s*str\s*\)',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM07:2025 - Insecure Plugin Design",
     "description":"LangChain/agent tool function accepting raw string without validation.",
     "lang":["py"],"negative_lookahead":r'(?:validate|sanitize|strip|escape|re\.|isinstance|allowed)'},
    {"rule_id":"AI-LLM07-002","title":"Insecure Plugin - Tool With Unrestricted File System Access",
     "pattern":r'(?:tools|functions)\s*=.{0,300}(?:read_file|write_file|open\(|Path\(|os\.listdir)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM07:2025 - Insecure Plugin Design",
     "description":"LLM plugin with unrestricted file system read/write access.",
     "lang":["py"]},
    {"rule_id":"AI-LLM08-002","title":"Excessive Agency - LLM With Database Write Tool",
     "pattern":r'(?:tools|functions)\s*=.{0,300}(?:db\.commit|session\.commit|insert_into|execute_write|db\.execute)',
     "severity":CRITICAL,"category":"ai","owasp_category":"LLM08:2025 - Excessive Agency",
     "description":"LLM agent has database write capability — data destruction risk if prompt-injected.",
     "lang":["py"]},
    {"rule_id":"AI-LLM08-003","title":"Excessive Agency - LLM With Messaging/Email Tool",
     "pattern":r'(?:tools|functions)\s*=.{0,300}(?:send_email|send_message|smtp|twilio|send_sms|slack_post)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM08:2025 - Excessive Agency",
     "description":"LLM agent can send messages — phishing or data exfiltration if hijacked.",
     "lang":["py"]},
    {"rule_id":"AI-LLM08-004","title":"Excessive Agency - Agent Running Without Human Approval",
     "pattern":r'(?:agent|chain)\.(?:run|invoke|execute)\s*\([^)]*\)',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM08:2025 - Excessive Agency",
     "description":"Agent executes autonomously — verify human-in-the-loop for destructive actions.",
     "lang":["py"],"negative_lookahead":r'(?:confirm|approval|human_approval|review|checkpoint|interrupt)'},
    {"rule_id":"AI-LLM09-002","title":"Overreliance - Security Decision Delegated to LLM",
     "pattern":r'(?:if|return|assert)\s+.*(?:client|llm|model)\.(?:invoke|complete|chat|generate)\s*\([^)]*(?:safe|allow|permit|authorized|valid|approve)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM09:2025 - Overreliance",
     "description":"Authorization or security gating delegated to LLM output — unreliable.",
     "lang":["py"]},
    {"rule_id":"AI-LLM09-003","title":"Overreliance - LLM Output in Financial Calculation",
     "pattern":r'(?:price|amount|total|fee|cost|balance)\s*=\s*.*(?:response|completion|output|llm)\.(?:content|text|choices)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM09:2025 - Overreliance",
     "description":"Financial value derived directly from LLM output — verify independently.",
     "lang":["py"]},
    {"rule_id":"AI-LLM10-001","title":"Model Theft - Model Weights Exposed via API Endpoint",
     "pattern":r'@(?:app|router)\.(?:get|post)\s*\(["\'][^"\']*(?:model|weights|checkpoint|parameters|export)',
     "severity":HIGH,"category":"ai","owasp_category":"LLM10:2025 - Model Theft",
     "description":"Endpoint may expose model weights or enable model extraction.",
     "lang":["py"],"negative_lookahead":r'(?:login_required|jwt_required|auth|token|permission)'},
    {"rule_id":"AI-LLM10-002","title":"Model Theft - No Rate Limiting on Inference Endpoint",
     "pattern":r'@(?:app|router)\.(?:get|post)\s*\(["\'][^"\']*(?:predict|inference|generate|complete|chat|embed)',
     "severity":MEDIUM,"category":"ai","owasp_category":"LLM10:2025 - Model Theft",
     "description":"Inference endpoint without rate limiting enables model extraction via repeated queries.",
     "lang":["py"],"negative_lookahead":r'(?:limiter|rate_limit|throttle|RateLimit|slowapi)'},
]

EXTENSION_MAP = {".py":"py",".java":"java",".kt":"kt",".kts":"kt"}
SKIP_DIRS = {".git","node_modules","venv",".venv","__pycache__","dist","build",
             "target",".gradle","vendor",".idea",".vscode",".pytest_cache","migrations"}


# ─────────────────────────────────────────────
# REGEX SCANNER  (same fast engine as v1)
# ─────────────────────────────────────────────
class RepoScanner:
    def __init__(self):
        self._compiled = []
        for rule in RULES:
            try:
                pat = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE | re.DOTALL)
                neg = re.compile(rule["negative_lookahead"], re.IGNORECASE) \
                      if rule.get("negative_lookahead") else None
                self._compiled.append((rule, pat, neg))
            except re.error:
                pass

    def scan_file(self, file_path: Path, repo_root: Path) -> List[Finding]:
        lang = EXTENSION_MAP.get(file_path.suffix.lower())
        if not lang:
            return []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []
        lines    = content.split("\n")
        rel_path = str(file_path.relative_to(repo_root))
        findings = []
        for rule, pat, neg in self._compiled:
            if lang not in rule.get("lang", []):
                continue
            seen = set()
            for m in pat.finditer(content):
                ln = content[:m.start()].count("\n") + 1
                if ln in seen:
                    continue
                seen.add(ln)
                code = lines[ln-1] if ln <= len(lines) else ""
                if neg:
                    ctx = "\n".join(lines[max(0,ln-6):min(len(lines),ln+5)])
                    if neg.search(ctx):
                        continue
                findings.append(Finding(
                    rule_id=rule["rule_id"], title=rule["title"],
                    description=rule["description"], severity=rule["severity"],
                    category=rule["category"], file_path=rel_path,
                    line_number=ln, code_snippet=code,
                    owasp_category=rule["owasp_category"],
                ))
        return findings

    def scan_repo(self, repo_path: Path) -> List[Finding]:
        all_f = []
        for fp in repo_path.rglob("*"):
            if not fp.is_file():
                continue
            if any(p in SKIP_DIRS for p in fp.parts):
                continue
            if fp.suffix.lower() in EXTENSION_MAP:
                all_f.extend(self.scan_file(fp, repo_path))
        return all_f


# ─────────────────────────────────────────────
# CVE CHECKER  (OSV.dev — free, no key needed)
# ─────────────────────────────────────────────
class CVEChecker:
    OSV_URL = "https://api.osv.dev/v1/query"

    def check_package(self, name: str, version: str, ecosystem: str) -> List[CVEFinding]:
        if not HAS_REQUESTS:
            return []
        try:
            resp = requests.post(self.OSV_URL, json={
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version
            }, timeout=10)
            if resp.status_code != 200:
                return []
            vulns = resp.json().get("vulns", [])
            findings = []
            for v in vulns[:5]:  # cap at 5 per package
                sev = HIGH
                for s in v.get("severity", []):
                    if s.get("score", 0) >= 9.0:
                        sev = CRITICAL
                        break
                    elif s.get("score", 0) >= 7.0:
                        sev = HIGH
                findings.append(CVEFinding(
                    package   = name,
                    version   = version,
                    ecosystem = ecosystem,
                    cve_id    = v.get("id", ""),
                    summary   = v.get("summary", "")[:200],
                    severity  = sev,
                    aliases   = v.get("aliases", [])[:3],
                ))
            return findings
        except Exception:
            return []

    def scan_requirements(self, repo_path: Path) -> List[CVEFinding]:
        all_cves = []
        # Python requirements.txt
        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            for line in req_file.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # parse name==version, name>=version, etc.
                m = re.match(r'^([A-Za-z0-9_.\-]+)[=><~!]+([A-Za-z0-9_.\-]+)', line)
                if m:
                    pkg, ver = m.group(1), m.group(2)
                    cves = self.check_package(pkg, ver, "PyPI")
                    all_cves.extend(cves)
                    time.sleep(0.05)  # be gentle on the API

        # Java pom.xml (basic)
        pom = repo_path / "pom.xml"
        if pom.exists():
            content = pom.read_text(errors="ignore")
            deps = re.findall(r'<artifactId>([^<]+)</artifactId>\s*(?:<[^<]+>\s*)*<version>([^<]+)</version>', content)
            for artifact, version in deps[:20]:  # cap at 20
                cves = self.check_package(artifact, version, "Maven")
                all_cves.extend(cves)
                time.sleep(0.05)

        return all_cves


# ─────────────────────────────────────────────
# SCAN MEMORY  (diff mode)
# ─────────────────────────────────────────────
class ScanMemory:
    def __init__(self, memory_file: str = "owasp_memory.json"):
        self.path = Path(memory_file)
        self._data = self._load()

    def _load(self) -> Dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text())
            except Exception:
                pass
        return {"scans": []}

    def get_previous_fingerprints(self, org: str) -> set:
        """Return set of finding fingerprints from the most recent scan of this org."""
        for scan in reversed(self._data.get("scans", [])):
            if scan.get("org") == org:
                fps = set()
                for repo_findings in scan.get("findings", {}).values():
                    fps.update(f.get("fingerprint","") for f in repo_findings)
                return fps
        return set()

    def save(self, org: str, repo_results: Dict[str, List[Finding]],
             cve_results: Dict[str, List[CVEFinding]]):
        scan_record = {
            "scan_id":   str(uuid.uuid4())[:8],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "org":       org,
            "findings":  {
                name: [{"fingerprint": f.fingerprint, **f.to_dict()} for f in fl]
                for name, fl in repo_results.items()
            },
            "cve_findings": {
                name: [c.to_dict() for c in cl]
                for name, cl in cve_results.items()
            },
        }
        self._data.setdefault("scans", []).append(scan_record)
        # Keep only last 10 scans
        self._data["scans"] = self._data["scans"][-10:]
        self.path.write_text(json.dumps(self._data, indent=2))
        return scan_record["scan_id"]


# ─────────────────────────────────────────────
# TOOL IMPLEMENTATIONS  (what the agent calls)
# ─────────────────────────────────────────────

_scanner     = RepoScanner()
_cve_checker = CVEChecker()
_cloned_repos: Dict[str, Path] = {}   # repo_name -> local path
_repo_results: Dict[str, List[Finding]]    = {}
_cve_results:  Dict[str, List[CVEFinding]] = {}


def tool_list_repositories(org: str, token: str, github_url: str) -> str:
    """List repositories in the org."""
    if not HAS_REQUESTS:
        return json.dumps({"error": "requests not installed"})
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}",
                             "Accept": "application/vnd.github.v3+json"})
    repos, page = [], 1
    base = github_url.rstrip("/")
    while True:
        try:
            r = session.get(f"{base}/orgs/{org}/repos",
                            params={"per_page":100,"page":page,"type":"all"})
            if r.status_code == 404:
                r = session.get(f"{base}/users/{org}/repos",
                                params={"per_page":100,"page":page,"type":"all"})
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            return json.dumps({"error": str(e)})
        if not data:
            break
        repos.extend(data)
        page += 1

    result = [{"name": r["name"], "clone_url": r["clone_url"],
               "language": r.get("language","unknown"),
               "size_kb": r.get("size",0),
               "archived": r.get("archived",False)}
              for r in repos if not r.get("archived")]
    return json.dumps({"repos": result, "total": len(result)})


def tool_scan_repository(repo_name: str, clone_url: str,
                          token: str, tmp_dir: Path,
                          prev_fingerprints: set) -> str:
    """Clone and scan a repo. Returns findings summary."""
    dest = tmp_dir / repo_name
    if not dest.exists():
        auth_url = clone_url.replace("https://", f"https://x-access-token:{token}@")
        r = subprocess.run(["git","clone", auth_url, str(dest)],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return json.dumps({"error": f"Clone failed: {r.stderr[:200]}"})

    _cloned_repos[repo_name] = dest
    findings = _scanner.scan_repo(dest)

    # Mark new vs seen
    for f in findings:
        f.is_new = f.fingerprint not in prev_fingerprints

    _repo_results[repo_name] = findings

    summary = {
        "repo": repo_name,
        "total_findings": len(findings),
        "new_findings": sum(1 for f in findings if f.is_new),
        "by_severity": {s: sum(1 for f in findings if f.severity==s)
                        for s in [CRITICAL,HIGH,MEDIUM,LOW]},
        "by_category": {c: sum(1 for f in findings if f.category==c)
                        for c in ["web","api","ai"]},
        "findings": [
            {"id": i, "rule_id": f.rule_id, "severity": f.severity,
             "title": f.title, "file": f.file_path, "line": f.line_number,
             "owasp": f.owasp_category, "is_new": f.is_new}
            for i, f in enumerate(findings)
        ]
    }
    return json.dumps(summary)


def tool_read_code_context(repo_name: str, file_path: str,
                            line_number: int, context_lines: int = 15) -> str:
    """Read code context around a finding for false positive analysis."""
    repo_path = _cloned_repos.get(repo_name)
    if not repo_path:
        return json.dumps({"error": f"Repo {repo_name} not cloned yet"})
    full_path = repo_path / file_path
    if not full_path.exists():
        return json.dumps({"error": f"File not found: {file_path}"})
    try:
        lines = full_path.read_text(encoding="utf-8", errors="ignore").split("\n")
    except Exception as e:
        return json.dumps({"error": str(e)})

    start = max(0, line_number - context_lines - 1)
    end   = min(len(lines), line_number + context_lines)
    context_lines_out = []
    for i, line in enumerate(lines[start:end], start=start+1):
        marker = " --> " if i == line_number else "     "
        context_lines_out.append(f"{i:4d}{marker}{line}")

    return json.dumps({
        "repo":         repo_name,
        "file":         file_path,
        "flagged_line": line_number,
        "context":      "\n".join(context_lines_out),
        "total_lines":  len(lines),
    })


def tool_check_dependencies(repo_name: str) -> str:
    """Check repo dependencies against OSV.dev CVE database."""
    repo_path = _cloned_repos.get(repo_name)
    if not repo_path:
        return json.dumps({"error": f"Repo {repo_name} not cloned"})

    cves = _cve_checker.scan_requirements(repo_path)
    _cve_results[repo_name] = cves

    return json.dumps({
        "repo":          repo_name,
        "total_cves":    len(cves),
        "critical":      sum(1 for c in cves if c.severity == CRITICAL),
        "high":          sum(1 for c in cves if c.severity == HIGH),
        "findings":      [c.to_dict() for c in cves],
    })


def tool_scan_commit_history(repo_name: str,
                              patterns: List[str] = None,
                              max_commits: int = 500) -> str:
    """
    Scan git commit history for secrets/patterns that may have been
    added and later deleted (still permanently in git history).
    Uses `git log -p -S <pattern>` (pickaxe search).
    """
    repo_path = _cloned_repos.get(repo_name)
    if not repo_path:
        return json.dumps({"error": f"Repo {repo_name} not cloned yet"})

    default_patterns = [
        "SECRET_KEY", "PASSWORD", "API_KEY", "PRIVATE_KEY", "ACCESS_KEY",
        "AUTH_TOKEN", "DB_PASS", "CLIENT_SECRET", "STRIPE_KEY", "AWS_SECRET",
    ]
    search_patterns = patterns or default_patterns

    findings = []
    seen_commits = set()

    for pattern in search_patterns:
        try:
            result = subprocess.run(
                ["git", "log", f"--max-count={max_commits}", "--all",
                 "--oneline", f"-S{pattern}", "--format=%H|%an|%ae|%ad|%s"],
                cwd=str(repo_path),
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.strip().splitlines():
                if not line.strip() or "|" not in line:
                    continue
                parts = line.split("|", 4)
                if len(parts) < 5:
                    continue
                commit_hash, author, email, date, subject = parts
                commit_hash = commit_hash.strip()
                if commit_hash in seen_commits:
                    continue
                seen_commits.add(commit_hash)

                # Get the diff for this commit to show the actual secret context
                diff_result = subprocess.run(
                    ["git", "show", "--stat", commit_hash],
                    cwd=str(repo_path),
                    capture_output=True, text=True, timeout=30
                )
                findings.append({
                    "pattern":     pattern,
                    "commit":      commit_hash[:10],
                    "author":      author.strip(),
                    "email":       email.strip(),
                    "date":        date.strip(),
                    "subject":     subject.strip(),
                    "files_changed": diff_result.stdout[:500],
                    "severity":    CRITICAL,
                    "note":        "Pattern found in commit history — may be deleted from current code but still in git history"
                })
        except subprocess.TimeoutExpired:
            findings.append({"error": f"Timeout scanning for pattern: {pattern}"})
        except Exception as e:
            findings.append({"error": str(e)})

    # Also check for secrets in current HEAD diff vs all branches
    try:
        branch_result = subprocess.run(
            ["git", "branch", "-a"],
            cwd=str(repo_path), capture_output=True, text=True, timeout=10
        )
        branches = [b.strip().lstrip("* ") for b in branch_result.stdout.splitlines()]
    except Exception:
        branches = ["main"]

    return json.dumps({
        "repo":           repo_name,
        "commits_with_secrets": len(findings),
        "patterns_searched":    search_patterns,
        "branches_detected":    branches[:10],
        "findings":             findings,
        "warning": (
            "Even if secrets were deleted from current code, "
            "they remain in git history forever unless history is rewritten."
        ) if findings else None
    })


def tool_git_blame_finding(repo_name: str, file_path: str,
                             line_number: int) -> str:
    """
    Run git blame on a specific line to identify WHO introduced
    a vulnerability, WHEN, and in WHICH commit.
    """
    repo_path = _cloned_repos.get(repo_name)
    if not repo_path:
        return json.dumps({"error": f"Repo {repo_name} not cloned"})

    full_path = repo_path / file_path
    if not full_path.exists():
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        # Blame the specific line
        result = subprocess.run(
            ["git", "blame", "-L", f"{line_number},{line_number}",
             "--porcelain", str(full_path)],
            cwd=str(repo_path),
            capture_output=True, text=True, timeout=30
        )
        out = result.stdout

        # Parse porcelain blame output
        commit  = out[:40] if len(out) >= 40 else "unknown"
        author  = next((l[7:] for l in out.splitlines() if l.startswith("author ")), "unknown")
        email   = next((l[13:] for l in out.splitlines() if l.startswith("author-mail ")), "")
        time_ts = next((l[12:] for l in out.splitlines() if l.startswith("author-time ")), "")
        summary = next((l[8:] for l in out.splitlines() if l.startswith("summary ")), "")

        # Convert timestamp
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(int(time_ts), tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            dt = time_ts

        # Get the commit message in full
        log_result = subprocess.run(
            ["git", "log", "-1", "--format=%B", commit.strip()],
            cwd=str(repo_path), capture_output=True, text=True, timeout=15
        )

        return json.dumps({
            "repo":           repo_name,
            "file":           file_path,
            "line":           line_number,
            "introduced_by":  author.strip(),
            "email":          email.strip().strip("<>"),
            "commit":         commit.strip()[:10],
            "date":           dt,
            "commit_message": (log_result.stdout.strip() or summary)[:200],
            "insight": f"This vulnerability was introduced by {author.strip()} on {dt} in commit {commit.strip()[:10]}"
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "git blame timed out"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def tool_finish_report(executive_summary: str,
                        critical_findings: List[str],
                        recommended_actions: List[str]) -> str:
    """Agent calls this when done. Stores the LLM summary."""
    return json.dumps({
        "status":               "complete",
        "executive_summary":    executive_summary,
        "critical_findings":    critical_findings,
        "recommended_actions":  recommended_actions,
    })


# ─────────────────────────────────────────────
# OPENAI TOOL DEFINITIONS
# ─────────────────────────────────────────────
TOOL_DEFS = [
    {
        "type": "function",
        "function": {
            "name": "list_repositories",
            "description": "List all repositories in the GitHub org with their languages and sizes. Call this first.",
            "parameters": {
                "type": "object",
                "properties": {
                    "org": {"type": "string", "description": "GitHub org or username"}
                },
                "required": ["org"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_repository",
            "description": (
                "Clone and scan a repository for OWASP security issues. "
                "Returns findings categorised by severity. "
                "Call this for each repository you want to scan."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_name":  {"type": "string", "description": "Repository name"},
                    "clone_url":  {"type": "string", "description": "HTTPS clone URL from list_repositories"}
                },
                "required": ["repo_name", "clone_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_code_context",
            "description": (
                "Read the code surrounding a finding to determine if it's a real vulnerability "
                "or a false positive (e.g. test code, commented out, benign usage). "
                "Always call this for CRITICAL and HIGH findings before confirming them."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_name":     {"type": "string"},
                    "file_path":     {"type": "string", "description": "Relative file path from scan result"},
                    "line_number":   {"type": "integer", "description": "Line number from scan result"},
                    "context_lines": {"type": "integer", "description": "Lines of context each side (default 15)", "default": 15}
                },
                "required": ["repo_name", "file_path", "line_number"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_dependencies",
            "description": (
                "Check a repository's dependencies (requirements.txt, pom.xml) against the "
                "OSV.dev CVE database for known vulnerabilities. "
                "Call this for every scanned repository."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_name": {"type": "string"}
                },
                "required": ["repo_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_commit_history",
            "description": (
                "Search the full git commit history of a repo for secrets or sensitive patterns "
                "that may have been added and later deleted — they remain in git history forever. "
                "Call this after scan_repository for any repo that had hardcoded credential findings, "
                "or for security-sensitive repos (auth, payment, api-gateway)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_name": {"type": "string"},
                    "patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Secret patterns to search for. Leave empty to use defaults (SECRET_KEY, PASSWORD, API_KEY, etc.)"
                    },
                    "max_commits": {
                        "type": "integer",
                        "description": "Max commits to scan (default 500)",
                        "default": 500
                    }
                },
                "required": ["repo_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "git_blame_finding",
            "description": (
                "Run git blame on a specific file and line to find out WHO introduced "
                "a vulnerability, WHEN, and in WHICH commit. "
                "Call this for confirmed Critical or High findings to identify the source."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_name":   {"type": "string"},
                    "file_path":   {"type": "string", "description": "Relative file path"},
                    "line_number": {"type": "integer", "description": "Line number of the vulnerability"}
                },
                "required": ["repo_name", "file_path", "line_number"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "finish_report",
            "description": (
                "Call this ONLY when you have finished scanning all repositories and checking all dependencies. "
                "Provide an executive summary, list of the most critical confirmed findings, "
                "and prioritised remediation recommendations."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "executive_summary": {
                        "type": "string",
                        "description": "2-4 paragraph plain-English summary of the security posture across all microservices"
                    },
                    "critical_findings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Top confirmed critical/high findings as plain English sentences"
                    },
                    "recommended_actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Prioritised remediation steps"
                    }
                },
                "required": ["executive_summary", "critical_findings", "recommended_actions"]
            }
        }
    }
]


# ─────────────────────────────────────────────
# AGENT LOOP
# ─────────────────────────────────────────────
SYSTEM_PROMPT = """You are an elite security engineer conducting a comprehensive OWASP security audit across a microservices architecture.

Your mission:
1. Call list_repositories to see all repos
2. Scan every repository using scan_repository (prioritise: auth, payment, user-data, ai, llm, api-gateway)
3. For every CRITICAL or HIGH finding, call read_code_context to confirm it is real (not test code, commented out, or benign)
4. Call check_dependencies for every repo to find CVE vulnerabilities in dependencies
5. Call scan_commit_history for any repo that had hardcoded credential findings, OR for security-sensitive repos (auth, payment, gateway) — secrets deleted from code live in git history forever
6. For every confirmed Critical finding, call git_blame_finding to identify who introduced it and when
7. After all repos are done, call finish_report with your executive summary

Key reasoning principles:
- Test files (path contains test/, spec/, __tests__/) reduce confidence — flag but note
- Placeholder credentials ("your-secret-here", "CHANGE_ME", "xxx") are likely benign
- Repos with "ai", "llm", "ml", "gpt" → extra scrutiny on LLM Top 10
- Repos with "auth", "login", "token" → extra scrutiny on A07 Auth failures
- Same vulnerability across multiple repos = systemic issue — flag prominently
- Commit history findings are HIGH severity even if deleted — they're in history forever
- git blame gives you accountability — always run it for confirmed critical findings

You are methodical, thorough, and focused. Begin by listing the repositories."""


def run_agent(org: str, token: str, github_url: str,
              openai_key: str, tmp_dir: Path,
              prev_fingerprints: set, max_iterations: int = 60) -> Dict:
    """
    Main ReAct agent loop. GPT-4o decides what to do next.
    Returns the final report dict when the agent calls finish_report().
    """
    if not HAS_OPENAI:
        raise ImportError("Run: pip install openai")

    client = OpenAI(api_key=openai_key)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    final_report = None

    print(f"\n  {'─'*52}")
    print(f"  🤖  Agent starting  (GPT-4o | max {max_iterations} steps)")
    print(f"  {'─'*52}\n")

    for iteration in range(max_iterations):
        response = client.chat.completions.create(
            model    = "gpt-4o",
            messages = messages,
            tools    = TOOL_DEFS,
            tool_choice = "auto",
        )
        msg = response.choices[0].message
        messages.append(msg)

        # ── No more tool calls = agent finished without calling finish_report ──
        if not msg.tool_calls:
            print(f"\n  💬  Agent message: {msg.content or '(no content)'}")
            break

        # ── Process each tool call ──
        for tc in msg.tool_calls:
            fn_name = tc.function.name
            try:
                args = json.loads(tc.function.arguments)
            except Exception:
                args = {}

            print(f"  ⚡  [{iteration+1:>2}] {fn_name}({', '.join(f'{k}={repr(v)[:40]}' for k,v in args.items())})")

            # ── Dispatch ──
            if fn_name == "list_repositories":
                result = tool_list_repositories(
                    args.get("org", org), token, github_url)

            elif fn_name == "scan_repository":
                result = tool_scan_repository(
                    args["repo_name"], args["clone_url"],
                    token, tmp_dir, prev_fingerprints)
                # Print quick summary
                try:
                    d = json.loads(result)
                    if "total_findings" in d:
                        new = d.get("new_findings", d["total_findings"])
                        cr  = d["by_severity"].get(CRITICAL, 0)
                        hi  = d["by_severity"].get(HIGH, 0)
                        print(f"       → {d['total_findings']} findings ({new} new)  🔴 {cr} crit  🟠 {hi} high")
                except Exception:
                    pass

            elif fn_name == "read_code_context":
                result = tool_read_code_context(
                    args["repo_name"], args["file_path"],
                    args["line_number"], args.get("context_lines", 15))
                print(f"       → Reading {args['file_path']}:{args['line_number']}")

            elif fn_name == "check_dependencies":
                result = tool_check_dependencies(args["repo_name"])
                try:
                    d = json.loads(result)
                    print(f"       → {d.get('total_cves',0)} CVEs found")
                except Exception:
                    pass

            elif fn_name == "finish_report":
                result = tool_finish_report(
                    args.get("executive_summary", ""),
                    args.get("critical_findings", []),
                    args.get("recommended_actions", []),
                )
                final_report = args
                print(f"\n  ✅  Agent called finish_report — scan complete!\n")

            else:
                result = json.dumps({"error": f"Unknown tool: {fn_name}"})

            messages.append({
                "role":         "tool",
                "tool_call_id": tc.id,
                "content":      result,
            })

        if final_report:
            break

    return final_report or {}


# ─────────────────────────────────────────────
# CROSS-SERVICE ANALYZER  (same as v1, post-agent)
# ─────────────────────────────────────────────
def cross_service_insights(repo_results: Dict[str, List[Finding]]) -> List[Dict]:
    insights = []
    rule_repos: Dict[str, List[str]] = defaultdict(list)
    rule_sample: Dict[str, Finding]  = {}
    for repo, findings in repo_results.items():
        for f in findings:
            rule_repos[f.rule_id].append(repo)
            rule_sample.setdefault(f.rule_id, f)

    for rule_id, repos in rule_repos.items():
        unique = list(dict.fromkeys(repos))
        if len(unique) >= 2:
            s = rule_sample[rule_id]
            insights.append({
                "type":"systemic","rule_id":rule_id,
                "title":f"Systemic: {s.title}",
                "description":f"{s.owasp_category} appears in {len(unique)} services — likely shared code. Fix once.",
                "severity":s.severity,"affected_repos":unique,"count":len(repos),
            })

    secret_map: Dict[str, List[str]] = defaultdict(list)
    for repo, findings in repo_results.items():
        for f in findings:
            if "W-A02-003" in f.rule_id and f.code_snippet:
                secret_map[f.code_snippet.strip()].append(repo)
    for _, repos in secret_map.items():
        unique = list(dict.fromkeys(repos))
        if len(unique) >= 2:
            insights.append({
                "type":"shared_secret","rule_id":"CROSS-001",
                "title":"Same Hardcoded Secret in Multiple Services",
                "description":f"Identical credential in {len(unique)} repos. One leak = all compromised.",
                "severity":CRITICAL,"affected_repos":unique,"count":len(repos),
            })

    cors = [r for r,fl in repo_results.items() if any("W-A05-002" in f.rule_id for f in fl)]
    if len(cors) >= 2:
        insights.append({
            "type":"cors_spread","rule_id":"CROSS-002",
            "title":"CORS Wildcard Across Multiple API Services",
            "description":f"CORS wildcard in {len(cors)} services exposes your entire API mesh.",
            "severity":HIGH,"affected_repos":cors,"count":len(cors),
        })

    ai_unsafe = [r for r,fl in repo_results.items() if any(f.rule_id.startswith("AI-LLM02") for f in fl)]
    if len(ai_unsafe) >= 2:
        insights.append({
            "type":"ai_output","rule_id":"CROSS-003",
            "title":"Multiple AI Services With Unsafe LLM Output Handling",
            "description":f"{len(ai_unsafe)} services use LLM output in eval()/exec(). Need shared sanitisation layer.",
            "severity":CRITICAL,"affected_repos":ai_unsafe,"count":len(ai_unsafe),
        })

    insights.sort(key=lambda i: (SEVERITY_RANK.get(i["severity"],99), -len(i["affected_repos"])))
    return insights


# ─────────────────────────────────────────────
# RISK SCORER
# ─────────────────────────────────────────────
def risk_score(findings: List[Finding]) -> Tuple[int, str]:
    s = 100
    for f in findings:
        # Confidence-weighted penalty
        weight = (f.confidence or 5) / 10.0  # unreviewed = 0.5 weight
        s -= int({CRITICAL:15,HIGH:8,MEDIUM:4,LOW:1,INFO:0}.get(f.severity,0) * weight)
    s = max(0, s)
    g = "A" if s>=85 else "B" if s>=70 else "C" if s>=55 else "D" if s>=40 else "F"
    return s, g


# ─────────────────────────────────────────────
# HTML DASHBOARD  (v2: adds confidence, CVEs, LLM summary)
# ─────────────────────────────────────────────
def _e(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

SEV_COLORS = {
    CRITICAL:("#fee2e2","#b91c1c"), HIGH:("#ffedd5","#c2410c"),
    MEDIUM:("#fef9c3","#a16207"),   LOW:("#dbeafe","#1d4ed8"),  INFO:("#f1f5f9","#475569"),
}
CAT_ICON = {"web":"🌐","api":"🔌","ai":"🤖"}
HEATMAP_CATS = [("A01","Access Ctrl"),("A02","Crypto"),("A03","Injection"),
                ("A05","Misconfig"),("A07","Auth"),("A08","Integrity"),
                ("A09","Logging"),("A10","SSRF"),("API1","BOLA"),
                ("API3","MassAssign"),("API4","Resources"),
                ("LLM01","PromptInj"),("LLM02","LLMOutput"),("LLM08","Agency")]


def generate_dashboard(repo_results, cve_results, insights, agent_report,
                        org, scan_time, scan_id):
    total = sum(len(fl) for fl in repo_results.values())
    sev_t = {s:0 for s in [CRITICAL,HIGH,MEDIUM,LOW,INFO]}
    cat_t = {"web":0,"api":0,"ai":0}
    new_t = 0
    for fl in repo_results.values():
        for f in fl:
            sev_t[f.severity] = sev_t.get(f.severity,0)+1
            cat_t[f.category] = cat_t.get(f.category,0)+1
            if f.is_new: new_t += 1

    total_cves = sum(len(cl) for cl in cve_results.values())

    repo_data = []
    for name, fl in repo_results.items():
        sc, gr = risk_score(fl)
        sv = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0}
        ct = {"web":0,"api":0,"ai":0}
        for f in fl:
            if f.severity in sv: sv[f.severity]+=1
            if f.category in ct: ct[f.category]+=1
        repo_data.append({"name":name,"score":sc,"grade":gr,"total":len(fl),
                           "new":sum(1 for f in fl if f.is_new),
                           "sev":sv,"cat":ct,
                           "findings":[f.to_dict() for f in fl],
                           "cves":[c.to_dict() for c in cve_results.get(name,[])]})
    repo_data.sort(key=lambda x: x["score"])

    # Findings rows
    rows = ""
    for rd in repo_data:
        for f in rd["findings"]:
            bg,fg = SEV_COLORS.get(f["severity"],("#f1f5f9","#475569"))
            snip  = _e(f["code_snippet"])[:90]
            conf  = f.get("confidence")
            conf_html = (f'<span class="conf conf-{"hi" if conf>=7 else "mid" if conf>=4 else "lo"}">'
                         f'{"★"*round(conf/2)}{"☆"*(5-round(conf/2))} {conf}/10</span>'
                         if conf else '<span class="conf conf-mid">unreviewed</span>')
            new_badge = '<span class="new-badge">NEW</span>' if f.get("is_new") else ""
            analysis  = _e(f.get("llm_analysis",""))
            rows += (
                f'<tr class="frow" data-sev="{f["severity"]}" '
                f'data-cat="{f["category"]}" data-repo="{_e(rd["name"])}" '
                f'data-new="{str(f.get("is_new",True)).lower()}">'
                f'<td class="td-repo">{_e(rd["name"])}{new_badge}</td>'
                f'<td><span class="badge" style="background:{bg};color:{fg}">{f["severity"]}</span></td>'
                f'<td>{CAT_ICON.get(f["category"],"?")} {f["category"].upper()}</td>'
                f'<td class="td-title">{_e(f["title"])}'
                f'{"<br><small class=analysis>" + analysis + "</small>" if analysis else ""}</td>'
                f'<td class="td-owasp">{_e(f["owasp_category"])}</td>'
                f'<td class="td-loc">{_e(f["file_path"])}:{f["line_number"]}</td>'
                f'<td>{conf_html}</td>'
                f'<td><code class="snip">{snip}{"…" if len(_e(f["code_snippet"]))>90 else ""}</code></td>'
                f'</tr>\n'
            )
    if not rows:
        rows = '<tr><td colspan="8" class="none">No findings detected.</td></tr>'

    # CVE rows
    cve_rows = ""
    for rd in repo_data:
        for c in rd["cves"]:
            bg,fg = SEV_COLORS.get(c["severity"],("#f1f5f9","#475569"))
            aliases = ", ".join(c.get("aliases",[]))
            cve_rows += (
                f'<tr>'
                f'<td class="td-repo">{_e(rd["name"])}</td>'
                f'<td><span class="badge" style="background:{bg};color:{fg}">{c["severity"]}</span></td>'
                f'<td><code>{_e(c["package"])}</code></td>'
                f'<td>{_e(c["version"])}</td>'
                f'<td>{_e(c["ecosystem"])}</td>'
                f'<td class="td-title">{_e(c["cve_id"])}</td>'
                f'<td>{_e(aliases)}</td>'
                f'<td>{_e(c["summary"])}</td>'
                f'</tr>\n'
            )
    if not cve_rows:
        cve_rows = '<tr><td colspan="8" class="none">No CVE vulnerabilities found in dependencies.</td></tr>'

    # Insight cards
    ihtml = ""
    for ins in insights:
        border = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308",
                  "LOW":"#3b82f6","INFO":"#94a3b8"}.get(ins["severity"],"#94a3b8")
        bg     = {"CRITICAL":"#fff5f5","HIGH":"#fff7ed","MEDIUM":"#fefce8",
                  "LOW":"#eff6ff","INFO":"#f8fafc"}.get(ins["severity"],"#f8fafc")
        tags   = "".join(f'<span class="rtag">{_e(r)}</span>' for r in ins["affected_repos"])
        ihtml += (
            f'<div class="icard" style="border-left-color:{border};background:{bg}">'
            f'<div class="ihead"><div>'
            f'<div class="ititle">{_e(ins["title"])}</div>'
            f'<div class="idesc">{_e(ins["description"])}</div>'
            f'<div class="rtags">{tags}</div>'
            f'</div><span class="icnt">{ins["count"]} occurrence{"s" if ins["count"]!=1 else ""}</span>'
            f'</div></div>\n'
        )
    if not ihtml: ihtml = '<p class="muted">No cross-service patterns detected.</p>'

    # Repo cards
    cards = ""
    for rd in repo_data:
        bar_c  = "#22c55e" if rd["score"]>=70 else ("#eab308" if rd["score"]>=40 else "#ef4444")
        gr_c   = {"A":"#16a34a","B":"#2563eb","C":"#ca8a04","D":"#ea580c","F":"#dc2626"}.get(rd["grade"],"#6b7280")
        new_indicator = f'<span style="font-size:10px;color:#8b5cf6;font-weight:700"> +{rd["new"]} new</span>' if rd["new"] else ""
        cards += (
            f'<div class="rcard">'
            f'<div class="rchead"><span class="rcname" title="{_e(rd["name"])}">{_e(rd["name"])}</span>'
            f'<span class="rcgrade" style="color:{gr_c}">{rd["grade"]}</span></div>'
            f'<div class="rcbar"><div style="width:{rd["score"]}%;background:{bar_c};height:4px;border-radius:9px"></div></div>'
            f'<div class="rcsev">'
            f'<span>🔴 {rd["sev"][CRITICAL]}</span><span>🟠 {rd["sev"][HIGH]}</span>'
            f'<span>🟡 {rd["sev"][MEDIUM]}</span><span>🔵 {rd["sev"][LOW]}</span>'
            f'</div>'
            f'<div class="rccat">'
            f'<span>🌐 {rd["cat"]["web"]}</span><span>🔌 {rd["cat"]["api"]}</span>'
            f'<span>🤖 {rd["cat"]["ai"]}</span><span>🛡 {len(rd["cves"])} CVE</span>'
            f'</div>{new_indicator}</div>\n'
        )

    # Heatmap
    hm_head = ('<th class="hmth">Repository</th>' +
               "".join(f'<th class="hmth"><small>{c[0]}</small><br><small style="color:#94a3b8;font-weight:400">{c[1]}</small></th>'
                       for c in HEATMAP_CATS))
    hm_rows = ""
    for rd in repo_data[:20]:
        hm_rows += f'<tr><td class="hmrepo">{_e(rd["name"][:22])}</td>'
        for code, _ in HEATMAP_CATS:
            cnt = sum(1 for f in rd["findings"] if code.lower() in f["owasp_category"].lower())
            if   cnt==0: bg,txt = "#dcfce7",""
            elif cnt<=2: bg,txt = "#fef9c3",str(cnt)
            elif cnt<=5: bg,txt = "#fed7aa",str(cnt)
            else:        bg,txt = "#fca5a5",str(cnt)
            hm_rows += f'<td class="hmcell" style="background:{bg}">{txt}</td>'
        hm_rows += "</tr>\n"

    # Agent executive summary
    summary    = agent_report.get("executive_summary","No summary generated.")
    crit_list  = agent_report.get("critical_findings",[])
    rec_list   = agent_report.get("recommended_actions",[])
    crit_html  = "".join(f'<li>{_e(c)}</li>' for c in crit_list) or "<li>None</li>"
    rec_html   = "".join(f'<li>{_e(r)}</li>' for r in rec_list) or "<li>None</li>"

    top8 = repo_data[:8]
    chart_repos  = json.dumps([r["name"][:18] for r in top8])
    chart_totals = json.dumps([r["total"]     for r in top8])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>OWASP Security Agent v2 — {_e(org)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f1f5f9;color:#1e293b;font-size:14px}}
.hdr{{background:linear-gradient(135deg,#0f172a,#312e81);color:#fff;padding:18px 28px;display:flex;align-items:center;justify-content:space-between}}
.hdr h1{{font-size:19px;font-weight:700}}
.hdr p{{font-size:12px;color:#a5b4fc;margin-top:3px}}
.hdr-r{{text-align:right}}.hdr-r .big{{font-size:32px;font-weight:800}}
.hdr-r small{{font-size:11px;color:#a5b4fc}}
.agent-badge{{background:rgba(139,92,246,.3);border:1px solid #8b5cf6;border-radius:6px;padding:4px 10px;font-size:11px;color:#c4b5fd;margin-top:6px;display:inline-block}}
.wrap{{max-width:1440px;margin:0 auto;padding:22px 28px}}
.sec-title{{font-size:15px;font-weight:700;margin-bottom:12px}}
.sub{{font-size:11px;font-weight:400;color:#64748b;margin-left:6px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px}}
.stat{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:14px 10px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.stat .n{{font-size:28px;font-weight:800}}.stat .l{{font-size:11px;color:#64748b;margin-top:2px}}
.charts{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}}
.chart-card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.chart-label{{font-size:12px;font-weight:600;color:#64748b;margin-bottom:10px}}
/* executive summary */
.summary-card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.summary-body{{font-size:13px;line-height:1.7;color:#334155;margin-bottom:16px}}
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.col-box{{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px}}
.col-box h4{{font-size:12px;font-weight:700;color:#64748b;margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px}}
.col-box ul{{list-style:none;padding:0}}
.col-box li{{font-size:12px;color:#334155;padding:4px 0;border-bottom:1px solid #f1f5f9;line-height:1.5}}
.col-box li:last-child{{border:none}}
.col-box li::before{{content:"→ ";color:#8b5cf6;font-weight:700}}
/* badge */
.badge{{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700}}
.new-badge{{background:#8b5cf6;color:#fff;font-size:10px;font-weight:700;padding:1px 6px;border-radius:99px;margin-left:4px}}
/* confidence */
.conf{{font-size:11px;padding:2px 6px;border-radius:4px}}
.conf-hi{{background:#dcfce7;color:#15803d}}
.conf-mid{{background:#fef9c3;color:#a16207}}
.conf-lo{{background:#fee2e2;color:#b91c1c}}
.analysis{{color:#64748b;font-weight:400;font-size:11px;line-height:1.4;display:block;margin-top:2px}}
/* insights */
.insights{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.icard{{border-left:4px solid #ccc;padding:12px 14px;margin-bottom:10px;border-radius:0 8px 8px 0}}
.icard:last-child{{margin-bottom:0}}
.ihead{{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}}
.ititle{{font-size:13px;font-weight:700;margin-bottom:3px}}
.idesc{{font-size:12px;color:#475569;line-height:1.55}}
.icnt{{font-size:11px;color:#94a3b8;white-space:nowrap}}
.rtags{{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}}
.rtag{{background:#f1f5f9;border:1px solid #e2e8f0;color:#475569;padding:2px 8px;border-radius:99px;font-size:11px}}
/* heatmap */
.hmwrap{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-bottom:20px;overflow-x:auto;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
table.hm{{border-collapse:collapse;font-size:11px}}
.hmth{{padding:5px 8px;font-size:10px;font-weight:700;color:#64748b;text-align:center;white-space:nowrap;border-bottom:2px solid #e2e8f0}}
.hmrepo{{padding:5px 10px;font-weight:600;white-space:nowrap}}
.hmcell{{padding:5px 8px;text-align:center;font-size:11px;font-weight:700;min-width:44px}}
.hm-leg{{display:flex;gap:14px;margin-top:10px;font-size:11px;color:#64748b}}
.hm-leg span{{display:flex;align-items:center;gap:5px}}
.dot{{width:12px;height:12px;border-radius:2px;display:inline-block}}
/* repo cards */
.rgrid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:10px;margin-bottom:20px}}
.rcard{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:12px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.rchead{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
.rcname{{font-size:12px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:120px}}
.rcgrade{{font-size:24px;font-weight:900}}
.rcbar{{width:100%;background:#e2e8f0;border-radius:99px;height:4px;margin-bottom:8px}}
.rcsev{{display:grid;grid-template-columns:1fr 1fr;gap:2px;font-size:11px;font-weight:600;margin-bottom:6px}}
.rccat{{display:flex;justify-content:space-between;font-size:11px;color:#64748b;padding-top:6px;border-top:1px solid #f1f5f9}}
/* tables */
.fwrap{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}}
.filters select,.filters input{{font-size:12px;border:1px solid #e2e8f0;border-radius:7px;padding:5px 10px;background:#f8fafc;color:#1e293b}}
.filters label{{font-size:12px;color:#475569;display:flex;align-items:center;gap:5px;cursor:pointer}}
table.ft{{width:100%;border-collapse:collapse}}
table.ft thead th{{background:#f8fafc;padding:9px 12px;text-align:left;font-size:11px;font-weight:700;color:#64748b;border-bottom:2px solid #e2e8f0}}
table.ft tbody tr{{border-bottom:1px solid #f1f5f9}}table.ft tbody tr:hover{{background:#f8fafc}}
table.ft td{{padding:8px 12px;vertical-align:top}}
.td-repo{{font-weight:700;font-size:12px}}
.td-title{{font-weight:600}}
.td-owasp,.td-loc{{font-size:11px;color:#64748b}}
.snip{{font-size:11px;background:#fef2f2;padding:2px 6px;border-radius:4px;color:#b91c1c;display:block;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}}
.none{{text-align:center;padding:40px;color:#94a3b8}}
.muted{{color:#94a3b8;font-size:13px}}
.tabs{{display:flex;gap:0;margin-bottom:-1px}}
.tab{{padding:8px 18px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid #e2e8f0;border-bottom:none;border-radius:8px 8px 0 0;background:#f8fafc;color:#64748b}}
.tab.active{{background:#fff;color:#1e293b;border-bottom-color:#fff}}
.tab-content{{display:none}}.tab-content.active{{display:block}}
footer{{text-align:center;font-size:11px;color:#94a3b8;padding:24px 0}}
@media(max-width:860px){{.stats{{grid-template-columns:repeat(3,1fr)}}.charts{{grid-template-columns:1fr}}.two-col{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<header class="hdr">
  <div>
    <h1>🛡️ OWASP Security Agent v2</h1>
    <p>Organisation: <strong>{_e(org)}</strong>&nbsp;·&nbsp;Scan ID: {scan_id}&nbsp;·&nbsp;{scan_time}</p>
    <div class="agent-badge">🤖 GPT-4o powered &nbsp;·&nbsp; False positive filtering &nbsp;·&nbsp; CVE scanning &nbsp;·&nbsp; Diff mode</div>
  </div>
  <div class="hdr-r">
    <div class="big">{len(repo_results)}</div>
    <small>Repositories Scanned</small>
  </div>
</header>

<div class="wrap">

<!-- STATS -->
<div class="stats">
  <div class="stat"><div class="n" style="color:#1e293b">{total}</div><div class="l">Total Findings</div></div>
  <div class="stat"><div class="n" style="color:#8b5cf6">{new_t}</div><div class="l">New This Scan</div></div>
  <div class="stat"><div class="n" style="color:#dc2626">{sev_t[CRITICAL]}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n" style="color:#ea580c">{sev_t[HIGH]}</div><div class="l">High</div></div>
  <div class="stat"><div class="n" style="color:#ca8a04">{sev_t[MEDIUM]}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n" style="color:#dc2626">{total_cves}</div><div class="l">CVEs Found</div></div>
</div>

<!-- CHARTS -->
<div class="charts">
  <div class="chart-card"><div class="chart-label">By OWASP Framework</div><canvas id="cCat" height="190"></canvas></div>
  <div class="chart-card"><div class="chart-label">Severity Breakdown</div><canvas id="cSev" height="190"></canvas></div>
  <div class="chart-card"><div class="chart-label">Riskiest Repositories</div><canvas id="cRepo" height="190"></canvas></div>
</div>

<!-- AGENT EXECUTIVE SUMMARY -->
<div class="summary-card">
  <div class="sec-title">🤖 Agent Executive Summary
    <span class="sub">Written by GPT-4o after reviewing all findings and code context</span>
  </div>
  <div class="summary-body">{_e(summary).replace(chr(10),'<br>')}</div>
  <div class="two-col">
    <div class="col-box">
      <h4>⚠️ Critical Confirmed Findings</h4>
      <ul>{crit_html}</ul>
    </div>
    <div class="col-box">
      <h4>🔧 Recommended Actions</h4>
      <ul>{rec_html}</ul>
    </div>
  </div>
</div>

<!-- CROSS-SERVICE INSIGHTS -->
<div class="insights">
  <div class="sec-title">⚡ Cross-Service Insights
    <span class="sub">Systemic patterns spanning multiple microservices</span>
  </div>
  {ihtml}
</div>

<!-- HEATMAP -->
<div class="hmwrap">
  <div class="sec-title">🗺️ Repository × OWASP Category Heatmap</div>
  <table class="hm">
    <thead><tr>{hm_head}</tr></thead>
    <tbody>{hm_rows}</tbody>
  </table>
  <div class="hm-leg">
    <span><span class="dot" style="background:#dcfce7"></span>Clean</span>
    <span><span class="dot" style="background:#fef9c3"></span>1-2</span>
    <span><span class="dot" style="background:#fed7aa"></span>3-5</span>
    <span><span class="dot" style="background:#fca5a5"></span>6+</span>
  </div>
</div>

<!-- REPO CARDS -->
<div class="sec-title">📊 Repository Risk Scores
  <span class="sub">Confidence-weighted &nbsp;·&nbsp; Includes CVE count</span>
</div>
<div class="rgrid">{cards}</div>

<!-- FINDINGS + CVE TABS -->
<div class="fwrap">
  <div class="tabs">
    <div class="tab active" onclick="switchTab('findings',this)">🔍 Security Findings ({total})</div>
    <div class="tab" onclick="switchTab('cves',this)">🛡 CVE Dependencies ({total_cves})</div>
  </div>

  <!-- FINDINGS TAB -->
  <div id="tab-findings" class="tab-content active">
    <div class="filters" style="margin-top:14px">
      <select id="fSev" onchange="filt()">
        <option value="">All Severities</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
      </select>
      <select id="fCat" onchange="filt()">
        <option value="">All Categories</option>
        <option value="web">🌐 Web</option>
        <option value="api">🔌 API</option>
        <option value="ai">🤖 AI</option>
      </select>
      <input id="fRepo" oninput="filt()" placeholder="Filter by repo…" style="width:170px"/>
      <input id="fFind" oninput="filt()" placeholder="Filter by finding…" style="width:200px"/>
      <label><input type="checkbox" id="fNew" onchange="filt()"> New findings only</label>
    </div>
    <div style="overflow-x:auto">
    <table class="ft">
      <thead><tr>
        <th>Repo</th><th>Severity</th><th>Category</th><th>Finding</th>
        <th>OWASP</th><th>Location</th><th>Confidence</th><th>Snippet</th>
      </tr></thead>
      <tbody id="tb">{rows}</tbody>
    </table>
    </div>
  </div>

  <!-- CVE TAB -->
  <div id="tab-cves" class="tab-content">
    <div style="overflow-x:auto;margin-top:14px">
    <table class="ft">
      <thead><tr>
        <th>Repo</th><th>Severity</th><th>Package</th><th>Version</th>
        <th>Ecosystem</th><th>CVE ID</th><th>Aliases</th><th>Summary</th>
      </tr></thead>
      <tbody>{cve_rows}</tbody>
    </table>
    </div>
  </div>
</div>

<footer>
  OWASP Security Agent v2 &nbsp;·&nbsp; GPT-4o powered &nbsp;·&nbsp; {scan_time}<br>
  OWASP Web Top 10 (2021) &nbsp;·&nbsp; OWASP API Top 10 (2023) &nbsp;·&nbsp; OWASP LLM Top 10 (2025) &nbsp;·&nbsp; CVE via OSV.dev
</footer>
</div>

<script>
new Chart(document.getElementById('cCat'),{{
  type:'doughnut',
  data:{{labels:['🌐 Web','🔌 API','🤖 AI/LLM'],
         datasets:[{{data:[{cat_t['web']},{cat_t['api']},{cat_t['ai']}],
                    backgroundColor:['#3b82f6','#10b981','#8b5cf6'],borderWidth:0}}]}},
  options:{{responsive:true,plugins:{{legend:{{position:'bottom',labels:{{font:{{size:11}}}}}}}}}}
}});
new Chart(document.getElementById('cSev'),{{
  type:'bar',
  data:{{labels:['Critical','High','Medium','Low'],
         datasets:[{{data:[{sev_t[CRITICAL]},{sev_t[HIGH]},{sev_t[MEDIUM]},{sev_t[LOW]}],
                    backgroundColor:['#ef4444','#f97316','#eab308','#3b82f6'],
                    borderWidth:0,borderRadius:5}}]}},
  options:{{responsive:true,plugins:{{legend:{{display:false}}}},
            scales:{{y:{{beginAtZero:true,ticks:{{font:{{size:10}}}}}},x:{{ticks:{{font:{{size:10}}}}}}}}}}
}});
const rn={chart_repos},rt={chart_totals};
new Chart(document.getElementById('cRepo'),{{
  type:'bar',
  data:{{labels:rn,datasets:[{{data:rt,backgroundColor:'#ef4444',borderWidth:0,borderRadius:5}}]}},
  options:{{indexAxis:'y',responsive:true,plugins:{{legend:{{display:false}}}},
            scales:{{x:{{beginAtZero:true,ticks:{{font:{{size:10}}}}}},y:{{ticks:{{font:{{size:10}}}}}}}}}}
}});
function filt(){{
  const sev=document.getElementById('fSev').value;
  const cat=document.getElementById('fCat').value;
  const rep=document.getElementById('fRepo').value.toLowerCase();
  const fnd=document.getElementById('fFind').value.toLowerCase();
  const onlyNew=document.getElementById('fNew').checked;
  document.querySelectorAll('.frow').forEach(tr=>{{
    const ok=(!sev||tr.dataset.sev===sev)&&(!cat||tr.dataset.cat===cat)&&
             (!rep||tr.dataset.repo.toLowerCase().includes(rep))&&
             (!fnd||tr.cells[3].textContent.toLowerCase().includes(fnd))&&
             (!onlyNew||tr.dataset.new==='true');
    tr.style.display=ok?'':'none';
  }});
}}
function switchTab(name,el){{
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  el.classList.add('active');
}}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────
# GITHUB CLIENT  (for local mode, repo discovery)
# ─────────────────────────────────────────────
def get_github_repos(org: str, token: str, github_url: str,
                     repo_names: Optional[str], exclude: Optional[str],
                     max_repos: int) -> List[Dict]:
    if not HAS_REQUESTS:
        raise ImportError("pip install requests")
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}",
                             "Accept": "application/vnd.github.v3+json"})
    base = github_url.rstrip("/")

    if repo_names:
        repos = []
        for name in repo_names.split(","):
            r = session.get(f"{base}/repos/{org}/{name.strip()}")
            r.raise_for_status()
            repos.append(r.json())
        return repos

    repos, page = [], 1
    while True:
        try:
            r = session.get(f"{base}/orgs/{org}/repos",
                            params={"per_page":100,"page":page,"type":"all"})
            if r.status_code == 404:
                r = session.get(f"{base}/users/{org}/repos",
                                params={"per_page":100,"page":page,"type":"all"})
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            raise RuntimeError(f"GitHub API error: {e}")
        if not data:
            break
        repos.extend(data)
        page += 1

    excl = set(x.strip() for x in exclude.split(",")) if exclude else set()
    repos = [r for r in repos if r["name"] not in excl and not r.get("archived")]
    return repos[:max_repos]


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="OWASP Multi-Repo Security Agent v2 — GPT-4o powered",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full agent scan of GitHub org
  python owasp_agent_v2.py --org acme-corp --github-token ghp_xxx --openai-key sk-xxx

  # Specific repos
  python owasp_agent_v2.py --org acme-corp --repos auth-svc,ai-api --github-token ghp_xxx --openai-key sk-xxx

  # Scan locally cloned repos (no GitHub token needed)
  python owasp_agent_v2.py --local /workspace/services --org acme-corp --openai-key sk-xxx

  # Use environment variables
  export GITHUB_TOKEN=ghp_xxx
  export OPENAI_API_KEY=sk-xxx
  python owasp_agent_v2.py --org acme-corp
""")
    ap.add_argument("--org",           required=False, default=None)
    ap.add_argument("--github-token",  default=os.getenv("GITHUB_TOKEN"),     help="GitHub PAT")
    ap.add_argument("--openai-key",    default=os.getenv("OPENAI_API_KEY"),    help="OpenAI API key")
    ap.add_argument("--repos",                                                  help="Comma-separated repo names")
    ap.add_argument("--exclude",                                                help="Comma-separated repos to skip")
    ap.add_argument("--github-url",    default="https://api.github.com")
    ap.add_argument("--local",                                                  help="Path to pre-cloned repos directory")
    ap.add_argument("--output",        default="owasp_v2_dashboard.html")
    ap.add_argument("--json-out",      default="owasp_v2_report.json")
    ap.add_argument("--memory-file",   default="owasp_memory.json",            help="Scan memory file for diff mode")
    ap.add_argument("--max-repos",     type=int, default=50)
    ap.add_argument("--max-steps",     type=int, default=80,                   help="Max agent iterations")
    args = ap.parse_args()

    # Default org label to local folder name when using --local
    if not args.org:
        if args.local:
            args.org = Path(args.local).resolve().name
        else:
            ap.error("--org is required when not using --local")

    if not args.openai_key:
        ap.error("--openai-key or OPENAI_API_KEY env var required")
    if not HAS_OPENAI:
        print("ERROR: pip install openai", file=sys.stderr); sys.exit(1)
    if not HAS_REQUESTS and not args.local:
        print("ERROR: pip install requests", file=sys.stderr); sys.exit(1)

    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{'='*58}")
    print(f"  OWASP Multi-Repo Security Agent v2")
    print(f"  Powered by GPT-4o + OSV.dev CVE database")
    print(f"{'='*58}")
    print(f"  Org          : {args.org}")
    print(f"  Scan started : {scan_time}")
    print(f"  Rules        : {len(RULES)} OWASP checks (Web / API / AI)")
    print(f"{'='*58}")

    # Load scan memory for diff mode
    memory = ScanMemory(args.memory_file)
    prev_fps = memory.get_previous_fingerprints(args.org)
    if prev_fps:
        print(f"\n  📂  Diff mode: {len(prev_fps)} fingerprints from previous scan loaded")
    else:
        print(f"\n  📂  First scan for this org — all findings will be marked as new")

    # Set up temp directory
    if args.local:
        local_root = Path(args.local)
        if not local_root.is_dir():
            print(f"ERROR: --local '{args.local}' is not a directory", file=sys.stderr); sys.exit(1)
        # Pre-populate cloned repos from local dirs
        tmp_ctx = None
        tmp_dir = local_root
        for d in local_root.iterdir():
            if d.is_dir() and not d.name.startswith("."):
                _cloned_repos[d.name] = d
        repos_for_agent = [{"name":d.name,"clone_url":f"local://{d}","language":"unknown","size_kb":0}
                            for d in local_root.iterdir() if d.is_dir() and not d.name.startswith(".")]

        # In local mode, scan everything upfront then let agent reason
        print(f"\n  🔍  Pre-scanning {len(_cloned_repos)} local repos...")
        for name, path in _cloned_repos.items():
            print(f"     Scanning {name}...", end="", flush=True)
            fl = _scanner.scan_repo(path)
            for f in fl:
                f.is_new = f.fingerprint not in prev_fps
            _repo_results[name] = fl
            cr = sum(1 for f in fl if f.severity==CRITICAL)
            hi = sum(1 for f in fl if f.severity==HIGH)
            print(f" {len(fl)} findings ({cr} crit / {hi} high)")
    else:
        print(f"\n  🔍  Fetching repo list from GitHub...")
        try:
            repos = get_github_repos(args.org, args.github_token, args.github_url,
                                      args.repos, args.exclude, args.max_repos)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr); sys.exit(1)
        print(f"  ✅  {len(repos)} repos found")
        repos_for_agent = [{"name":r["name"],"clone_url":r["clone_url"],
                             "language":r.get("language","?"),"size_kb":r.get("size",0)}
                            for r in repos]
        tmp_ctx = tempfile.TemporaryDirectory(prefix="owasp_v2_")
        tmp_dir = Path(tmp_ctx.name)

    # Inject repo list into agent context so it can start tool calling
    # We pre-fill the initial user message with the repo list to save one API round-trip
    repo_list_json = json.dumps({"repos": repos_for_agent, "total": len(repos_for_agent)})
    initial_message = (
        f"Begin the security audit for organisation '{args.org}'. "
        f"Here are the repositories available:\n{repo_list_json}\n\n"
        f"Please scan each repository, check all dependencies for CVEs, "
        f"investigate critical findings with read_code_context, and finish with a report."
    )

    # Override list_repositories tool to inject pre-fetched data
    _prefetched_repos = repo_list_json

    # Patch run_agent to use initial message
    from openai import OpenAI as _OAI
    client_oai  = _OAI(api_key=args.openai_key)
    messages    = [
        {"role": "system",  "content": SYSTEM_PROMPT},
        {"role": "user",    "content": initial_message},
    ]
    final_report = {}

    print(f"\n  {'─'*52}")
    print(f"  🤖  Agent loop starting (GPT-4o | max {args.max_steps} steps)")
    print(f"  {'─'*52}\n")

    for iteration in range(args.max_steps):
        response = client_oai.chat.completions.create(
            model="gpt-4o", messages=messages, tools=TOOL_DEFS, tool_choice="auto")
        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            if msg.content:
                print(f"\n  💬  Agent: {msg.content[:300]}")
            break

        for tc in msg.tool_calls:
            fn   = tc.function.name
            try:
                args_d = json.loads(tc.function.arguments)
            except Exception:
                args_d = {}

            print(f"  ⚡  [{iteration+1:>2}] {fn}({', '.join(f'{k}={repr(str(v))[:35]}' for k,v in args_d.items())})")

            if fn == "list_repositories":
                result = _prefetched_repos

            elif fn == "scan_repository":
                rname = args_d.get("repo_name","")
                curl  = args_d.get("clone_url","")
                if args.local:
                    # Already scanned — just return cached results
                    fl = _repo_results.get(rname, [])
                    result = json.dumps({
                        "repo":rname,"total_findings":len(fl),"new_findings":sum(1 for f in fl if f.is_new),
                        "by_severity":{s:sum(1 for f in fl if f.severity==s) for s in [CRITICAL,HIGH,MEDIUM,LOW]},
                        "by_category":{c:sum(1 for f in fl if f.category==c) for c in ["web","api","ai"]},
                        "findings":[{"id":i,"rule_id":f.rule_id,"severity":f.severity,"title":f.title,
                                     "file":f.file_path,"line":f.line_number,"owasp":f.owasp_category,
                                     "is_new":f.is_new} for i,f in enumerate(fl)]
                    })
                else:
                    result = tool_scan_repository(rname, curl, args.github_token, tmp_dir, prev_fps)
                try:
                    d=json.loads(result)
                    if "total_findings" in d:
                        cr=d["by_severity"].get(CRITICAL,0);hi=d["by_severity"].get(HIGH,0)
                        new=d.get("new_findings",d["total_findings"])
                        print(f"       → {d['total_findings']} findings ({new} new)  🔴{cr} 🟠{hi}")
                except Exception: pass

            elif fn == "read_code_context":
                result = tool_read_code_context(
                    args_d.get("repo_name",""), args_d.get("file_path",""),
                    args_d.get("line_number",1), args_d.get("context_lines",15))
                print(f"       → {args_d.get('file_path','')}:{args_d.get('line_number',1)}")

            elif fn == "check_dependencies":
                result = tool_check_dependencies(args_d.get("repo_name",""))
                try:
                    d=json.loads(result);print(f"       → {d.get('total_cves',0)} CVEs found")
                except Exception: pass

            elif fn == "scan_commit_history":
                result = tool_scan_commit_history(
                    args_d.get("repo_name",""),
                    args_d.get("patterns", None),
                    args_d.get("max_commits", 500))
                try:
                    d = json.loads(result)
                    n = d.get("commits_with_secrets", 0)
                    print(f"       → {n} commits with secrets in history")
                except Exception: pass

            elif fn == "git_blame_finding":
                result = tool_git_blame_finding(
                    args_d.get("repo_name",""),
                    args_d.get("file_path",""),
                    args_d.get("line_number", 1))
                try:
                    d = json.loads(result)
                    if "introduced_by" in d:
                        print(f"       → Introduced by {d['introduced_by']} on {d['date']} ({d['commit']})")
                except Exception: pass

            elif fn == "finish_report":
                result = tool_finish_report(
                    args_d.get("executive_summary",""),
                    args_d.get("critical_findings",[]),
                    args_d.get("recommended_actions",[]),
                )
                final_report = args_d
                print(f"\n  ✅  Agent called finish_report — done!\n")
            else:
                result = json.dumps({"error":f"Unknown: {fn}"})

            messages.append({"role":"tool","tool_call_id":tc.id,"content":result})

        if final_report:
            break

    # Clean up temp dir
    if tmp_ctx:
        try: tmp_ctx.cleanup()
        except Exception: pass

    # Cross-service insights (deterministic layer on top of agent)
    insights = cross_service_insights(_repo_results)

    # Save scan memory
    scan_id = memory.save(args.org, _repo_results, _cve_results)
    print(f"  💾  Scan memory saved → {args.memory_file}  (ID: {scan_id})")

    # Generate HTML dashboard
    html = generate_dashboard(
        _repo_results, _cve_results, insights, final_report,
        args.org, scan_time, scan_id)
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"  📊  HTML dashboard  → {Path(args.output).resolve()}")

    # JSON report
    report = {
        "scan_id": scan_id, "scan_time": scan_time, "org": args.org,
        "agent_report": final_report,
        "total_repos": len(_repo_results),
        "total_findings": sum(len(fl) for fl in _repo_results.values()),
        "new_findings": sum(sum(1 for f in fl if f.is_new) for fl in _repo_results.values()),
        "total_cves": sum(len(cl) for cl in _cve_results.values()),
        "cross_service_insights": insights,
        "repos": {n:[f.to_dict() for f in fl] for n,fl in _repo_results.items()},
        "cve_findings": {n:[c.to_dict() for c in cl] for n,cl in _cve_results.items()},
    }
    Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  📋  JSON report     → {Path(args.json_out).resolve()}")

    tot  = report["total_findings"]
    new  = report["new_findings"]
    cves = report["total_cves"]
    crit = sum(sum(1 for f in fl if f.severity==CRITICAL) for fl in _repo_results.values())
    print(f"\n{'='*58}")
    print(f"  Scan complete!")
    print(f"  Repos scanned   : {len(_repo_results)}")
    print(f"  Total findings  : {tot}  ({new} new)")
    print(f"  Critical        : {crit}")
    print(f"  CVEs found      : {cves}")
    print(f"{'='*58}\n")


if __name__ == "__main__":
    main()
