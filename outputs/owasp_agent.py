#!/usr/bin/env python3
"""
OWASP Multi-Repo Security Scanner Agent
========================================
Scans ALL repositories in a GitHub org (or specific repos) for:
  - OWASP Web Top 10 (2021)
  - OWASP API Top 10 (2023)
  - OWASP LLM / AI Top 10 (2025)

Uniquely performs CROSS-SERVICE correlation -- identifying systemic
vulnerabilities that span multiple microservices (shared secrets,
copy-pasted injection patterns, org-wide misconfigurations, etc.)

Supports: Python (.py) and Java/Kotlin (.java, .kt, .kts)

Usage:
  python owasp_agent.py --org my-company --token ghp_xxx
  python owasp_agent.py --org my-company --repos svc-a,svc-b --token ghp_xxx
  python owasp_agent.py --local /path/to/cloned/repos --org my-company
  GITHUB_TOKEN=ghp_xxx python owasp_agent.py --org my-company

Output:
  owasp_dashboard.html  -- interactive cross-service HTML dashboard
  owasp_report.json     -- machine-readable findings
"""

import os
import re
import sys
import json
import subprocess
import tempfile
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from collections import defaultdict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# SEVERITY
# ---------------------------------------------------------------------------
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_RANK = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# ---------------------------------------------------------------------------
# FINDING MODEL
# ---------------------------------------------------------------------------
class Finding:
    def __init__(self, rule_id, title, description, severity, category,
                 file_path, line_number, code_snippet, owasp_category):
        self.rule_id        = rule_id
        self.title          = title
        self.description    = description
        self.severity       = severity
        self.category       = category          # "web" | "api" | "ai"
        self.file_path      = file_path
        self.line_number    = line_number
        self.code_snippet   = (code_snippet or "").strip()
        self.owasp_category = owasp_category    # e.g. "A03:2021 - Injection"

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
        }


# ---------------------------------------------------------------------------
# RULES
# ---------------------------------------------------------------------------
# Each rule: rule_id, title, description, severity, category,
#            owasp_category, pattern (regex), lang (list of "py"/"java"/"kt"),
#            negative_lookahead (optional)

RULES = [

    # =========================================================================
    # OWASP WEB TOP 10  (2021)
    # =========================================================================

    # -- A01: Broken Access Control --
    {
        "rule_id": "W-A01-001",
        "title": "Broken Access Control - No Auth Decorator on Route",
        "pattern": r'@(?:app|router|blueprint)\.(?:route|get|post|put|delete|patch)\s*\([^)]+\)\s*\ndef\s+\w+\s*\(',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A01:2021 - Broken Access Control",
        "description": "Route handler defined without a following authentication decorator (login_required, jwt_required, etc.).",
        "lang": ["py"],
        "negative_lookahead": r'(?:@login_required|@permission_required|@jwt_required|@requires_auth|@authenticate|@authorized)',
    },
    {
        "rule_id": "W-A01-002",
        "title": "Broken Access Control - Object ID From Request Without Ownership Check",
        "pattern": r'(?:user_id|userId|owner_id|ownerId)\s*=\s*(?:request\.|req\.|params\.|data\.|args\.)',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A01:2021 - Broken Access Control",
        "description": "Object identifier taken directly from request without verifying caller owns it - potential IDOR.",
        "lang": ["py", "java", "kt"],
    },

    # -- A02: Cryptographic Failures --
    {
        "rule_id": "W-A02-001",
        "title": "Weak Crypto - MD5 Hash (Python)",
        "pattern": r'hashlib\.md5\s*\(',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "description": "MD5 is cryptographically broken. Use SHA-256 or stronger.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A02-J001",
        "title": "Weak Crypto - MD5 Hash (Java)",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "description": "MD5 is cryptographically broken. Use SHA-256 or stronger.",
        "lang": ["java", "kt"],
    },
    {
        "rule_id": "W-A02-002",
        "title": "Weak Crypto - SHA-1 Hash (Python)",
        "pattern": r'hashlib\.sha1\s*\(',
        "severity": MEDIUM,
        "category": "web",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "description": "SHA-1 is deprecated for security use. Use SHA-256 or stronger.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A02-J002",
        "title": "Weak Crypto - SHA-1 Hash (Java)",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']',
        "severity": MEDIUM,
        "category": "web",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "description": "SHA-1 is deprecated for security use. Use SHA-256 or stronger.",
        "lang": ["java", "kt"],
    },
    {
        "rule_id": "W-A02-003",
        "title": "Hardcoded Credential or Secret Key",
        "pattern": r'(?:SECRET_KEY|PASSWORD|PASSWD|API_KEY|AUTH_TOKEN|PRIVATE_KEY|DB_PASS|ACCESS_KEY|CLIENT_SECRET)\s*=\s*["\'][^"\']{6,}["\']',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "description": "Hardcoded credentials found in source. Rotate immediately and store in a secrets manager.",
        "lang": ["py", "java", "kt"],
    },
    {
        "rule_id": "W-A02-004",
        "title": "Plaintext HTTP URL (Non-localhost)",
        "pattern": r'"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
        "severity": MEDIUM,
        "category": "web",
        "owasp_category": "A02:2021 - Cryptographic Failures",
        "description": "Non-HTTPS URL found - traffic may be intercepted in transit.",
        "lang": ["py", "java", "kt"],
    },

    # -- A03: Injection --
    {
        "rule_id": "W-A03-001",
        "title": "SQL Injection - String Concatenation in Query (Python)",
        "pattern": r'(?:execute|cursor\.execute)\s*\(\s*(?:["\'][^"\']*["\']\s*\+|f["\'][^"\']*\{(?:user|input|param|request|data|query|search|name|id))',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "SQL query built with string concatenation or f-strings - high injection risk. Use parameterised queries.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A03-J001",
        "title": "SQL Injection - String Concatenation in Query (Java)",
        "pattern": r'(?:createQuery|createNativeQuery|prepareStatement|executeQuery|executeUpdate)\s*\([^)]*\+\s*(?:request|param|input|body|user|query)',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "SQL query built with string concatenation - high injection risk. Use PreparedStatement with parameters.",
        "lang": ["java", "kt"],
    },
    {
        "rule_id": "W-A03-002",
        "title": "Command Injection - subprocess with shell=True",
        "pattern": r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "subprocess with shell=True expands shell metacharacters. Dangerous if any input is user-controlled.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A03-003",
        "title": "Command Injection - os.system() Usage",
        "pattern": r'os\.system\s*\(',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "os.system() passes the command to a shell. Potential for command injection.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A03-J002",
        "title": "Command Injection - Runtime.exec() (Java)",
        "pattern": r'Runtime\.getRuntime\(\)\.exec\s*\(',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "Runtime.exec() with user-controlled input can lead to OS command injection.",
        "lang": ["java", "kt"],
    },
    {
        "rule_id": "W-A03-004",
        "title": "Template Injection - render_template_string",
        "pattern": r'render_template_string\s*\(',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "render_template_string with user content allows Server-Side Template Injection (SSTI).",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A03-005",
        "title": "LDAP Injection - Unfiltered Input in LDAP Filter",
        "pattern": r'(?:ldap_search|search_s|ldap\.filter)\s*\([^)]*(?:\+|%s|\.format\(|f["\'])',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "LDAP filter built with user input. Use ldap.filter.escape_filter_chars() to sanitise.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A03-006",
        "title": "Code Injection - eval() With Variable Input",
        "pattern": r'\beval\s*\(\s*(?![\"\'])',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A03:2021 - Injection",
        "description": "eval() called with a variable argument. If input is user-controlled this allows arbitrary code execution.",
        "lang": ["py"],
    },

    # -- A05: Security Misconfiguration --
    {
        "rule_id": "W-A05-001",
        "title": "Security Misconfiguration - DEBUG=True",
        "pattern": r'\bDEBUG\s*=\s*True\b',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "description": "DEBUG=True in production exposes stack traces, config, and internal details to attackers.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A05-002",
        "title": "Security Misconfiguration - CORS Wildcard",
        "pattern": r'(?:CORS_ORIGIN_WHITELIST|allow_origins|Access-Control-Allow-Origin|allowedOrigins)\s*[=:]\s*["\']?\*["\']?|origins\s*=\s*\[["\']\*["\']',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "description": "CORS wildcard (*) allows any origin to make cross-origin requests to this service.",
        "lang": ["py", "java", "kt"],
    },
    {
        "rule_id": "W-A05-003",
        "title": "Security Misconfiguration - ALLOWED_HOSTS Wildcard",
        "pattern": r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]?\*['\"]?\s*\]",
        "severity": MEDIUM,
        "category": "web",
        "owasp_category": "A05:2021 - Security Misconfiguration",
        "description": "ALLOWED_HOSTS=['*'] permits host header injection attacks.",
        "lang": ["py"],
    },

    # -- A07: Identification and Authentication Failures --
    {
        "rule_id": "W-A07-001",
        "title": "Auth Failure - JWT algorithm='none'",
        "pattern": r'algorithm\s*=\s*["\']none["\']',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "description": "JWT 'none' algorithm disables signature verification - tokens can be trivially forged.",
        "lang": ["py", "java", "kt"],
    },
    {
        "rule_id": "W-A07-002",
        "title": "Auth Failure - JWT Signature Verification Disabled",
        "pattern": r'(?:verify\s*=\s*False|["\']verify_signature["\']\s*:\s*False)',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "description": "JWT signature verification disabled. Tokens can be accepted without valid signatures.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A07-J001",
        "title": "Auth Failure - JWT Built Without Expiry (Java/Kotlin)",
        "pattern": r'Jwts\.builder\(\)',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "description": "JWT token created - verify an expiration (.expiration() / .setExpiration()) is set.",
        "lang": ["java", "kt"],
        "negative_lookahead": r'\.expiration\s*\(|\.setExpiration\s*\(',
    },
    {
        "rule_id": "W-A07-003",
        "title": "Auth Failure - Hardcoded Default Credentials",
        "pattern": r'(?:username|user)\s*=\s*["\'](?:admin|root|test|guest|user)["\']',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A07:2021 - Identification and Authentication Failures",
        "description": "Hardcoded default username found. Default credentials are a common attack vector.",
        "lang": ["py", "java", "kt"],
    },

    # -- A08: Software and Data Integrity Failures --
    {
        "rule_id": "W-A08-001",
        "title": "Insecure Deserialization - pickle.loads()",
        "pattern": r'pickle\.(?:load|loads)\s*\(',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "description": "pickle.loads() on untrusted data allows arbitrary code execution (RCE). Never deserialise untrusted pickle.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A08-002",
        "title": "Insecure Deserialization - yaml.load() Without Safe Loader",
        "pattern": r'\byaml\.load\s*\(',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "description": "yaml.load() without Loader=yaml.SafeLoader can execute arbitrary code. Use yaml.safe_load().",
        "lang": ["py"],
        "negative_lookahead": r'(?:Loader\s*=\s*yaml\.SafeLoader|yaml\.safe_load)',
    },
    {
        "rule_id": "W-A08-J001",
        "title": "Insecure Deserialization - Java ObjectInputStream",
        "pattern": r'new\s+ObjectInputStream\s*\(',
        "severity": CRITICAL,
        "category": "web",
        "owasp_category": "A08:2021 - Software and Data Integrity Failures",
        "description": "Java ObjectInputStream deserialisation on untrusted data can lead to RCE.",
        "lang": ["java", "kt"],
    },

    # -- A09: Security Logging Failures --
    {
        "rule_id": "W-A09-001",
        "title": "Sensitive Data in Logs",
        "pattern": r'(?:log(?:ger)?|logging|print)\b.{0,30}(?:password|secret|token|api_key|credit_card|ssn|passwd)',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A09:2021 - Security Logging and Monitoring Failures",
        "description": "Sensitive data (password/secret/token) appears to be written to logs or stdout.",
        "lang": ["py", "java", "kt"],
    },

    # -- A10: SSRF --
    {
        "rule_id": "W-A10-001",
        "title": "SSRF - HTTP Request With User-Controlled URL (Python)",
        "pattern": r'requests?\s*\.(?:get|post|put|delete|patch|head|request)\s*\(\s*(?:url\s*=\s*)?(?:request\.|req\.|args\.|data\.|params\.|body\.|input\.|user_)',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A10:2021 - Server-Side Request Forgery",
        "description": "HTTP request to a user-controlled URL without allow-list validation - potential SSRF.",
        "lang": ["py"],
    },
    {
        "rule_id": "W-A10-J001",
        "title": "SSRF - URL From User Input (Java)",
        "pattern": r'new\s+URL\s*\(\s*(?:request|param|input|body|query)',
        "severity": HIGH,
        "category": "web",
        "owasp_category": "A10:2021 - Server-Side Request Forgery",
        "description": "java.net.URL constructed from user input - validate against an allow-list to prevent SSRF.",
        "lang": ["java", "kt"],
    },

    # =========================================================================
    # OWASP API TOP 10  (2023)
    # =========================================================================

    # API1 - BOLA
    {
        "rule_id": "API-001-001",
        "title": "BOLA - Resource Fetched by Request ID Without Ownership Check",
        "pattern": r'(?:get_object_or_404|get_or_404|session\.get|db\.query)\s*\([^)]*(?:id\s*=\s*(?:request\.|req\.|params\.|args\.)|pk\s*=\s*(?:request\.|req\.|params\.))',
        "severity": CRITICAL,
        "category": "api",
        "owasp_category": "API1:2023 - Broken Object Level Authorization",
        "description": "Object fetched using an ID taken from the request without verifying the caller owns it (BOLA/IDOR).",
        "lang": ["py"],
    },

    # API3 - Mass Assignment
    {
        "rule_id": "API-003-001",
        "title": "Mass Assignment - Direct Request Body Binding (Python)",
        "pattern": r'(?:\.model_validate\(request|from_orm\(request|\.update\(\*\*request\.json\(\)|\.update\(\*\*data\b)',
        "severity": HIGH,
        "category": "api",
        "owasp_category": "API3:2023 - Broken Object Property Level Authorization",
        "description": "Request body bound directly to model without field whitelisting. Allows mass assignment of sensitive fields.",
        "lang": ["py"],
    },
    {
        "rule_id": "API-003-J001",
        "title": "Mass Assignment - @RequestBody Without @Valid (Java)",
        "pattern": r'public\s+\S+\s+\w+\s*\(\s*@RequestBody\s+(?!\S*@Valid)',
        "severity": HIGH,
        "category": "api",
        "owasp_category": "API3:2023 - Broken Object Property Level Authorization",
        "description": "@RequestBody without @Valid skips bean validation, allowing mass assignment.",
        "lang": ["java", "kt"],
    },

    # API4 - Unrestricted Resource Consumption
    {
        "rule_id": "API-004-001",
        "title": "No Pagination - Query Returns All Records",
        "pattern": r'(?:\.all\(\)|\.fetchall\(\)|\.find\s*\(\s*\{\s*\})',
        "severity": MEDIUM,
        "category": "api",
        "owasp_category": "API4:2023 - Unrestricted Resource Consumption",
        "description": "Query returns all records without pagination. Can exhaust memory and database resources.",
        "lang": ["py"],
        "negative_lookahead": r'(?:limit|paginate|page_size|per_page|offset)',
    },

    # API8 - Security Misconfiguration (reuse web CORS rule, already covers this)

    # API9 - Improper Inventory Management
    {
        "rule_id": "API-009-001",
        "title": "Stale API Version Endpoint Detected",
        "pattern": r'(?:/v[0-9]+/|/api/v[0-9]+/|prefix\s*=\s*["\'][^"\']*v[0-9])',
        "severity": LOW,
        "category": "api",
        "owasp_category": "API9:2023 - Improper Inventory Management",
        "description": "Versioned API endpoint detected. Ensure deprecated versions are properly decommissioned.",
        "lang": ["py", "java", "kt"],
    },

    # =========================================================================
    # OWASP LLM / AI TOP 10  (2025)
    # =========================================================================

    # LLM01 - Prompt Injection
    {
        "rule_id": "AI-LLM01-001",
        "title": "Prompt Injection - User Input Directly in f-string Prompt",
        "pattern": r'(?:prompt|system_prompt|user_message|content|messages?)\s*=\s*f["\'][^"\']*\{(?:user|input|query|request|body|text|message|data)',
        "severity": CRITICAL,
        "category": "ai",
        "owasp_category": "LLM01:2025 - Prompt Injection",
        "description": "User-controlled input directly interpolated into LLM prompt without sanitisation - classic prompt injection.",
        "lang": ["py"],
    },
    {
        "rule_id": "AI-LLM01-002",
        "title": "Prompt Injection - String Concatenation into LLM Call",
        "pattern": r'(?:\.invoke|\.complete|\.chat|\.create|\.generate)\s*\([^)]*(?:\+\s*(?:user|input|query|request)|(?:user|input|query)\s*\+)',
        "severity": HIGH,
        "category": "ai",
        "owasp_category": "LLM01:2025 - Prompt Injection",
        "description": "LLM invoked with string-concatenated user input. Prompt injection risk.",
        "lang": ["py"],
    },
    {
        "rule_id": "AI-LLM01-J001",
        "title": "Prompt Injection - User Input in LLM Prompt (Java/Kotlin)",
        "pattern": r'(?:prompt|message|content)\s*[+=]\s*.*(?:request|input|body|param)',
        "severity": HIGH,
        "category": "ai",
        "owasp_category": "LLM01:2025 - Prompt Injection",
        "description": "User-controlled input concatenated into LLM prompt without sanitisation.",
        "lang": ["java", "kt"],
    },

    # LLM02 - Insecure Output Handling
    {
        "rule_id": "AI-LLM02-001",
        "title": "Insecure Output - LLM Response Passed to eval()",
        "pattern": r'\beval\s*\([^)]*(?:response|completion|output|result|content|llm|gpt|claude|gemini)',
        "severity": CRITICAL,
        "category": "ai",
        "owasp_category": "LLM02:2025 - Insecure Output Handling",
        "description": "LLM output passed to eval() allows arbitrary code execution if the model is compromised.",
        "lang": ["py"],
    },
    {
        "rule_id": "AI-LLM02-002",
        "title": "Insecure Output - LLM Response Passed to exec()",
        "pattern": r'\bexec\s*\([^)]*(?:response|completion|output|result|content|llm|gpt|claude|gemini)',
        "severity": CRITICAL,
        "category": "ai",
        "owasp_category": "LLM02:2025 - Insecure Output Handling",
        "description": "LLM output passed to exec() allows arbitrary code execution.",
        "lang": ["py"],
    },
    {
        "rule_id": "AI-LLM02-003",
        "title": "Insecure Output - LLM Response Rendered as Raw HTML",
        "pattern": r'(?:render_template_string|mark_safe|Markup)\s*\([^)]*(?:response|completion|output|result|content)',
        "severity": HIGH,
        "category": "ai",
        "owasp_category": "LLM02:2025 - Insecure Output Handling",
        "description": "LLM output rendered as unescaped HTML - stored/reflected XSS risk.",
        "lang": ["py"],
    },

    # LLM05 - Supply Chain Vulnerabilities
    {
        "rule_id": "AI-LLM05-001",
        "title": "Unverified Model Loaded From External Source",
        "pattern": r'(?:from_pretrained|hub\.load|pipeline|AutoModel\.from_pretrained|AutoTokenizer\.from_pretrained)\s*\(\s*["\'][^"\']+["\']',
        "severity": MEDIUM,
        "category": "ai",
        "owasp_category": "LLM05:2025 - Supply Chain Vulnerabilities",
        "description": "Model loaded from external source without a pinned revision hash - supply chain risk.",
        "lang": ["py"],
        "negative_lookahead": r'(?:revision\s*=|sha\s*=|commit\s*=)',
    },

    # LLM06 - Sensitive Information Disclosure
    {
        "rule_id": "AI-LLM06-001",
        "title": "Sensitive Data Embedded in LLM System Prompt",
        "pattern": r'(?:system_prompt|prompt_template|system_message)\s*=\s*["\'][^"\']*(?:password|secret|api_key|private_key|ssn|credit_card)',
        "severity": HIGH,
        "category": "ai",
        "owasp_category": "LLM06:2025 - Sensitive Information Disclosure",
        "description": "Sensitive data (passwords, keys, PII) in LLM system prompt. May be leaked via prompt extraction attacks.",
        "lang": ["py"],
    },

    # LLM08 - Excessive Agency
    {
        "rule_id": "AI-LLM08-001",
        "title": "Excessive Agency - LLM Agent With File System or Shell Tools",
        "pattern": r'(?:tools|functions|tool_choice)\s*=.{0,200}(?:open\b|write\b|delete\b|remove\b|execute\b|run_code|bash|shell|subprocess)',
        "severity": HIGH,
        "category": "ai",
        "owasp_category": "LLM08:2025 - Excessive Agency",
        "description": "LLM agent granted file system or shell execution capabilities. Ensure strict scope and human-in-the-loop.",
        "lang": ["py"],
    },
    {
        "rule_id": "AI-LLM08-002",
        "title": "Excessive Agency - LLM Agent With Database Write Access",
        "pattern": r'(?:tools|functions)\s*=.{0,200}(?:delete_user|drop_table|execute_sql|update_record|insert_into)',
        "severity": HIGH,
        "category": "ai",
        "owasp_category": "LLM08:2025 - Excessive Agency",
        "description": "LLM agent has write/delete database access without human-in-the-loop confirmation.",
        "lang": ["py"],
    },

    # LLM09 - Overreliance
    {
        "rule_id": "AI-LLM09-001",
        "title": "Overreliance - LLM Output Used Without Validation",
        "pattern": r'(?:response|completion|output|result)\s*=\s*(?:client|llm|chain|agent|model)\.(?:invoke|complete|chat|generate|run)\s*\(',
        "severity": MEDIUM,
        "category": "ai",
        "owasp_category": "LLM09:2025 - Overreliance",
        "description": "LLM output assigned to variable - verify validation/sanitisation follows before use.",
        "lang": ["py"],
        "negative_lookahead": r'(?:if\s|assert\s|validate|check|verify|sanitize|parse|json\.loads)',
    },
]


# ---------------------------------------------------------------------------
# FILE EXTENSION -> LANG
# ---------------------------------------------------------------------------
EXTENSION_MAP = {
    ".py":   "py",
    ".java": "java",
    ".kt":   "kt",
    ".kts":  "kt",
}

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "target", ".gradle", ".mvn", "vendor",
    ".idea", ".vscode", ".pytest_cache", "eggs", ".eggs",
    "htmlcov", ".tox", "migrations",
}


# ---------------------------------------------------------------------------
# SCANNER ENGINE
# ---------------------------------------------------------------------------
class RepoScanner:
    def __init__(self, rules: List[Dict]):
        self._compiled = []
        for rule in rules:
            try:
                pat = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE | re.DOTALL)
                neg = re.compile(rule["negative_lookahead"], re.IGNORECASE) \
                      if rule.get("negative_lookahead") else None
                self._compiled.append((rule, pat, neg))
            except re.error as exc:
                print(f"  [WARN] Skipping rule {rule['rule_id']} - bad regex: {exc}", file=sys.stderr)

    def scan_file(self, file_path: Path, repo_root: Path) -> List[Finding]:
        findings = []
        lang = EXTENSION_MAP.get(file_path.suffix.lower())
        if not lang:
            return []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        lines    = content.split("\n")
        rel_path = str(file_path.relative_to(repo_root))

        for rule, pattern, neg_pattern in self._compiled:
            if lang not in rule.get("lang", []):
                continue
            seen = set()
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                if line_num in seen:
                    continue
                seen.add(line_num)
                code = lines[line_num - 1] if line_num <= len(lines) else ""

                if neg_pattern:
                    ctx = "\n".join(lines[max(0, line_num - 6):min(len(lines), line_num + 5)])
                    if neg_pattern.search(ctx):
                        continue

                findings.append(Finding(
                    rule_id        = rule["rule_id"],
                    title          = rule["title"],
                    description    = rule["description"],
                    severity       = rule["severity"],
                    category       = rule["category"],
                    file_path      = rel_path,
                    line_number    = line_num,
                    code_snippet   = code,
                    owasp_category = rule["owasp_category"],
                ))
        return findings

    def scan_repo(self, repo_path: Path) -> List[Finding]:
        all_findings = []
        for fp in repo_path.rglob("*"):
            if not fp.is_file():
                continue
            if any(part in SKIP_DIRS for part in fp.parts):
                continue
            if fp.suffix.lower() in EXTENSION_MAP:
                all_findings.extend(self.scan_file(fp, repo_path))
        return all_findings


# ---------------------------------------------------------------------------
# GITHUB CLIENT
# ---------------------------------------------------------------------------
class GitHubClient:
    def __init__(self, token: str, base_url: str = "https://api.github.com"):
        if not HAS_REQUESTS:
            raise ImportError("Run: pip install requests")
        self.token    = token
        self.base_url = base_url.rstrip("/")
        self.session  = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept":        "application/vnd.github.v3+json",
        })

    def _paginate(self, url: str, params: Dict) -> List[Dict]:
        items, page = [], 1
        while True:
            params["page"] = page
            resp = self.session.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            if not data:
                break
            items.extend(data)
            page += 1
        return items

    def get_repos(self, org: str) -> List[Dict]:
        try:
            return self._paginate(f"{self.base_url}/orgs/{org}/repos",
                                  {"per_page": 100, "type": "all"})
        except Exception:
            return self._paginate(f"{self.base_url}/users/{org}/repos",
                                  {"per_page": 100, "type": "all"})

    def get_specific_repos(self, org: str, names: List[str]) -> List[Dict]:
        out = []
        for name in names:
            r = self.session.get(f"{self.base_url}/repos/{org}/{name.strip()}")
            r.raise_for_status()
            out.append(r.json())
        return out


def clone_repo(clone_url: str, dest: Path, token: str, timeout: int = 120) -> bool:
    auth_url = clone_url.replace("https://", f"https://x-access-token:{token}@")
    r = subprocess.run(["git", "clone", "--depth=1", auth_url, str(dest)],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode == 0


# ---------------------------------------------------------------------------
# CROSS-SERVICE ANALYZER
# ---------------------------------------------------------------------------
class CrossServiceAnalyzer:
    def analyze(self, repo_results: Dict[str, List[Finding]]) -> List[Dict]:
        insights = []

        # 1. Same rule fires in >= 2 repos (systemic vulnerability)
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
                    "type":           "systemic_pattern",
                    "rule_id":        rule_id,
                    "title":          f"Systemic Pattern - {s.title}",
                    "description":    (
                        f"This vulnerability ({s.owasp_category}) appears across {len(unique)} services "
                        "- likely a shared pattern, shared library, or copy-paste issue. Fix once at the source."
                    ),
                    "severity":       s.severity,
                    "affected_repos": unique,
                    "count":          len(repos),
                })

        # 2. Identical hardcoded secret in multiple repos
        secret_map: Dict[str, List[str]] = defaultdict(list)
        for repo, findings in repo_results.items():
            for f in findings:
                if "W-A02-003" in f.rule_id and f.code_snippet:
                    secret_map[f.code_snippet.strip()].append(repo)
        for secret, repos in secret_map.items():
            unique = list(dict.fromkeys(repos))
            if len(unique) >= 2:
                insights.append({
                    "type":           "shared_secret",
                    "rule_id":        "CROSS-001",
                    "title":          "Same Hardcoded Secret Across Multiple Services",
                    "description":    (
                        f"The same hardcoded credential appears in {len(unique)} repositories. "
                        "A single leak compromises all services. Rotate and centralise in a secrets manager."
                    ),
                    "severity":       CRITICAL,
                    "affected_repos": unique,
                    "count":          len(repos),
                })

        # 3. Multiple AI services with unsafe LLM output handling
        ai_unsafe = [r for r, fl in repo_results.items()
                     if any(f.rule_id.startswith("AI-LLM02") for f in fl)]
        if len(ai_unsafe) >= 2:
            insights.append({
                "type":           "ai_output_risk",
                "rule_id":        "CROSS-002",
                "title":          "Multiple AI Services With Unsafe LLM Output Handling",
                "description":    (
                    f"{len(ai_unsafe)} services use LLM outputs in eval()/exec() or raw HTML. "
                    "Consider a shared output-sanitisation library."
                ),
                "severity":       CRITICAL,
                "affected_repos": ai_unsafe,
                "count":          len(ai_unsafe),
            })

        # 4. CORS wildcard spread across API services
        cors_repos = [r for r, fl in repo_results.items()
                      if any("W-A05-002" in f.rule_id for f in fl)]
        if len(cors_repos) >= 2:
            insights.append({
                "type":           "cors_wildcard_spread",
                "rule_id":        "CROSS-003",
                "title":          "CORS Wildcard Configured Across Multiple API Services",
                "description":    (
                    f"{len(cors_repos)} services have CORS wildcard (*). "
                    "In a microservice mesh this allows any origin to reach internal APIs."
                ),
                "severity":       HIGH,
                "affected_repos": cors_repos,
                "count":          len(cors_repos),
            })

        # 5. Repos with zero findings (scanner gap warning)
        zero = [r for r, fl in repo_results.items() if not fl]
        if zero:
            insights.append({
                "type":           "scanner_gap",
                "rule_id":        "CROSS-004",
                "title":          "Repositories With Zero Findings (Verify Manually)",
                "description":    (
                    "These repos produced no findings - may be clean, use unsupported languages, "
                    "or be infra/config repos. Recommend manual review."
                ),
                "severity":       INFO,
                "affected_repos": zero,
                "count":          0,
            })

        insights.sort(key=lambda i: (SEVERITY_RANK.get(i["severity"], 99), -len(i["affected_repos"])))
        return insights


# ---------------------------------------------------------------------------
# RISK SCORER
# ---------------------------------------------------------------------------
def risk_score(findings: List[Finding]) -> Tuple[int, str]:
    score = 100
    for f in findings:
        score -= {CRITICAL: 15, HIGH: 8, MEDIUM: 4, LOW: 1, INFO: 0}.get(f.severity, 0)
    score = max(0, score)
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"
    return score, grade


# ---------------------------------------------------------------------------
# HTML DASHBOARD
# ---------------------------------------------------------------------------
def _esc(s: str) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

CAT_ICON  = {"web": "Web", "api": "API", "ai": "AI/LLM"}
CAT_EMOJI = {"web": "🌐", "api": "🔌", "ai": "🤖"}

HEATMAP_CATS = [
    ("A01",   "Access Ctrl"),
    ("A02",   "Crypto"),
    ("A03",   "Injection"),
    ("A05",   "Misconfig"),
    ("A07",   "Auth"),
    ("A08",   "Integrity"),
    ("A09",   "Logging"),
    ("A10",   "SSRF"),
    ("API1",  "BOLA"),
    ("API3",  "MassAssign"),
    ("API4",  "Resources"),
    ("LLM01", "PromptInj"),
    ("LLM02", "LLMOutput"),
    ("LLM05", "AISupply"),
    ("LLM08", "Agency"),
]

SEV_COLORS = {
    CRITICAL: ("#fee2e2", "#b91c1c"),
    HIGH:     ("#ffedd5", "#c2410c"),
    MEDIUM:   ("#fef9c3", "#a16207"),
    LOW:      ("#dbeafe", "#1d4ed8"),
    INFO:     ("#f1f5f9", "#475569"),
}

def generate_dashboard(repo_results: Dict[str, List[Finding]],
                        insights: List[Dict],
                        org: str,
                        scan_time: str) -> str:

    total = sum(len(fl) for fl in repo_results.values())
    sev_t = {s: 0 for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
    cat_t = {"web": 0, "api": 0, "ai": 0}
    for fl in repo_results.values():
        for f in fl:
            sev_t[f.severity] = sev_t.get(f.severity, 0) + 1
            cat_t[f.category] = cat_t.get(f.category, 0) + 1

    # Per-repo summaries sorted riskiest first
    repo_data = []
    for name, fl in repo_results.items():
        sc, gr = risk_score(fl)
        sv = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0}
        ct = {"web":0, "api":0, "ai":0}
        for f in fl:
            if f.severity in sv: sv[f.severity] += 1
            if f.category in ct: ct[f.category] += 1
        repo_data.append({"name":name,"score":sc,"grade":gr,"total":len(fl),
                           "sev":sv,"cat":ct,"findings":[f.to_dict() for f in fl]})
    repo_data.sort(key=lambda x: x["score"])

    # ── Findings table rows ──
    rows = ""
    for rd in repo_data:
        for f in rd["findings"]:
            bg, fg = SEV_COLORS.get(f["severity"], ("#f1f5f9","#475569"))
            snip   = _esc(f["code_snippet"])[:100]
            cat_lbl = CAT_EMOJI.get(f["category"],"?") + " " + CAT_ICON.get(f["category"],"?")
            rows += (
                f'<tr class="frow" data-sev="{f["severity"]}" '
                f'data-cat="{f["category"]}" data-repo="{_esc(rd["name"])}">'
                f'<td class="td-repo">{_esc(rd["name"])}</td>'
                f'<td><span class="badge" style="background:{bg};color:{fg}">{f["severity"]}</span></td>'
                f'<td>{cat_lbl}</td>'
                f'<td class="td-title">{_esc(f["title"])}</td>'
                f'<td class="td-owasp">{_esc(f["owasp_category"])}</td>'
                f'<td class="td-loc">{_esc(f["file_path"])}:{f["line_number"]}</td>'
                f'<td><code class="snip">{snip}{"..." if len(_esc(f["code_snippet"]))>100 else ""}</code></td>'
                f'</tr>\n'
            )
    if not rows:
        rows = '<tr><td colspan="7" class="none">No findings across all repositories.</td></tr>'

    # ── Insight cards ──
    insight_html = ""
    for ins in insights:
        border = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308",
                  "LOW":"#3b82f6","INFO":"#94a3b8"}.get(ins["severity"],"#94a3b8")
        bg     = {"CRITICAL":"#fff5f5","HIGH":"#fff7ed","MEDIUM":"#fefce8",
                  "LOW":"#eff6ff","INFO":"#f8fafc"}.get(ins["severity"],"#f8fafc")
        tags   = "".join(f'<span class="rtag">{_esc(r)}</span>' for r in ins["affected_repos"])
        cnt    = f"{ins['count']} occurrence{'s' if ins['count']!=1 else ''}" if ins["count"] else "0 findings"
        insight_html += (
            f'<div class="icard" style="border-left-color:{border};background:{bg}">'
            f'<div class="ihead"><div>'
            f'<div class="ititle">{_esc(ins["title"])}</div>'
            f'<div class="idesc">{_esc(ins["description"])}</div>'
            f'<div class="rtags">{tags}</div>'
            f'</div><span class="icnt">{cnt}</span></div></div>\n'
        )
    if not insight_html:
        insight_html = '<p class="muted">No cross-service patterns detected.</p>'

    # ── Risk cards ──
    cards = ""
    for rd in repo_data:
        bar_c  = "#22c55e" if rd["score"]>=70 else ("#eab308" if rd["score"]>=40 else "#ef4444")
        gr_c   = {"A":"#16a34a","B":"#2563eb","C":"#ca8a04","D":"#ea580c","F":"#dc2626"}.get(rd["grade"],"#6b7280")
        cards += (
            f'<div class="rcard">'
            f'<div class="rchead"><span class="rcname" title="{_esc(rd["name"])}">{_esc(rd["name"])}</span>'
            f'<span class="rcgrade" style="color:{gr_c}">{rd["grade"]}</span></div>'
            f'<div class="rcbar"><div style="width:{rd["score"]}%;background:{bar_c};height:4px;border-radius:9px"></div></div>'
            f'<div class="rcsev">'
            f'<span>🔴 {rd["sev"][CRITICAL]}</span><span>🟠 {rd["sev"][HIGH]}</span>'
            f'<span>🟡 {rd["sev"][MEDIUM]}</span><span>🔵 {rd["sev"][LOW]}</span>'
            f'</div>'
            f'<div class="rccat">'
            f'<span>🌐 {rd["cat"]["web"]}</span><span>🔌 {rd["cat"]["api"]}</span><span>🤖 {rd["cat"]["ai"]}</span>'
            f'</div></div>\n'
        )

    # ── Heatmap ──
    hm_head = ('<th class="hmth">Repository</th>' +
               "".join(f'<th class="hmth"><small>{c[0]}</small><br><small style="font-weight:400;color:#94a3b8">{c[1]}</small></th>'
                       for c in HEATMAP_CATS))
    hm_rows = ""
    for rd in repo_data[:20]:
        hm_rows += f'<tr><td class="hmrepo">{_esc(rd["name"][:22])}</td>'
        for code, _ in HEATMAP_CATS:
            cnt = sum(1 for f in rd["findings"] if code.lower() in f["owasp_category"].lower())
            if   cnt == 0: bg, txt = "#dcfce7", ""
            elif cnt <= 2: bg, txt = "#fef9c3", str(cnt)
            elif cnt <= 5: bg, txt = "#fed7aa", str(cnt)
            else:          bg, txt = "#fca5a5", str(cnt)
            hm_rows += f'<td class="hmcell" style="background:{bg}">{txt}</td>'
        hm_rows += "</tr>\n"

    # Chart data
    top8 = repo_data[:8]
    chart_repos  = json.dumps([r["name"][:18] for r in top8])
    chart_totals = json.dumps([r["total"]     for r in top8])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>OWASP Multi-Repo Security Agent - {_esc(org)}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f1f5f9;color:#1e293b;font-size:14px}}
/* header */
.hdr{{background:linear-gradient(135deg,#0f172a,#1e40af);color:#fff;padding:18px 28px;display:flex;align-items:center;justify-content:space-between}}
.hdr h1{{font-size:19px;font-weight:700;letter-spacing:-.3px}}
.hdr p{{font-size:12px;color:#93c5fd;margin-top:3px}}
.hdr-r{{text-align:right}}.hdr-r .big{{font-size:32px;font-weight:800}}
.hdr-r small{{font-size:11px;color:#93c5fd}}
/* layout */
.wrap{{max-width:1440px;margin:0 auto;padding:22px 28px}}
.sec-title{{font-size:15px;font-weight:700;margin-bottom:12px}}
.sub{{font-size:11px;font-weight:400;color:#64748b;margin-left:6px}}
/* stat cards */
.stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}}
.stat{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px 12px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.stat .n{{font-size:30px;font-weight:800}}.stat .l{{font-size:11px;color:#64748b;margin-top:2px}}
/* charts */
.charts{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}}
.chart-card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:16px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.chart-label{{font-size:12px;font-weight:600;color:#64748b;margin-bottom:10px}}
/* badge */
.badge{{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700}}
/* cross-service */
.insights{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.icard{{border-left:4px solid #ccc;padding:12px 14px;margin-bottom:10px;border-radius:0 8px 8px 0}}
.icard:last-child{{margin-bottom:0}}
.ihead{{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}}
.ititle{{font-size:13px;font-weight:700;margin-bottom:3px}}
.idesc{{font-size:12px;color:#475569;line-height:1.55}}
.icnt{{font-size:11px;color:#94a3b8;white-space:nowrap;padding-top:2px}}
.rtags{{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}}
.rtag{{background:#f1f5f9;border:1px solid #e2e8f0;color:#475569;padding:2px 8px;border-radius:99px;font-size:11px}}
/* heatmap */
.hmwrap{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-bottom:20px;overflow-x:auto;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
table.hm{{border-collapse:collapse;font-size:11px}}
.hmth{{padding:5px 8px;font-size:10px;font-weight:700;color:#64748b;text-align:center;white-space:nowrap;border-bottom:2px solid #e2e8f0}}
.hmrepo{{padding:5px 10px;font-weight:600;white-space:nowrap;border-bottom:1px solid #f1f5f9}}
.hmcell{{padding:5px 8px;text-align:center;font-size:11px;font-weight:700;min-width:46px;border-bottom:1px solid #f8fafc}}
.hm-leg{{display:flex;gap:14px;margin-top:10px;font-size:11px;color:#64748b}}
.hm-leg span{{display:flex;align-items:center;gap:5px}}
.hm-leg .dot{{width:13px;height:13px;border-radius:3px;display:inline-block}}
/* repo cards */
.rgrid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:10px;margin-bottom:20px}}
.rcard{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:12px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.rchead{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
.rcname{{font-size:12px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:125px}}
.rcgrade{{font-size:24px;font-weight:900}}
.rcbar{{width:100%;background:#e2e8f0;border-radius:99px;height:4px;margin-bottom:8px}}
.rcsev{{display:grid;grid-template-columns:1fr 1fr;gap:2px;font-size:11px;font-weight:600;margin-bottom:6px}}
.rccat{{display:flex;justify-content:space-between;font-size:11px;color:#64748b;padding-top:6px;border-top:1px solid #f1f5f9}}
/* findings */
.fwrap{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
.filters select,.filters input{{font-size:12px;border:1px solid #e2e8f0;border-radius:7px;padding:5px 10px;background:#f8fafc;color:#1e293b;outline:none}}
table.ft{{width:100%;border-collapse:collapse}}
table.ft thead th{{background:#f8fafc;padding:9px 12px;text-align:left;font-size:11px;font-weight:700;color:#64748b;border-bottom:2px solid #e2e8f0}}
table.ft tbody tr{{border-bottom:1px solid #f1f5f9}}table.ft tbody tr:hover{{background:#f8fafc}}
table.ft td{{padding:8px 12px;vertical-align:top}}
.td-repo{{font-weight:700;font-size:12px;white-space:nowrap}}
.td-title{{font-weight:600}}
.td-owasp{{font-size:11px;color:#64748b}}
.td-loc{{font-size:11px;color:#94a3b8;white-space:nowrap}}
.snip{{font-size:11px;background:#fef2f2;padding:2px 6px;border-radius:4px;color:#b91c1c;display:block;max-width:270px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}}
.none{{text-align:center;padding:40px;color:#94a3b8}}
.muted{{color:#94a3b8;font-size:13px}}
footer{{text-align:center;font-size:11px;color:#94a3b8;padding:24px 0}}
@media(max-width:860px){{.stats{{grid-template-columns:repeat(3,1fr)}}.charts{{grid-template-columns:1fr}}}}
</style>
</head>
<body>

<header class="hdr">
  <div>
    <h1>🛡️ OWASP Multi-Repo Security Agent</h1>
    <p>Organisation: <strong>{_esc(org)}</strong>&nbsp;&nbsp;·&nbsp;&nbsp;Scanned: {scan_time}</p>
  </div>
  <div class="hdr-r">
    <div class="big">{len(repo_results)}</div>
    <small>Repositories Scanned</small>
  </div>
</header>

<div class="wrap">

<!-- STAT CARDS -->
<div class="stats">
  <div class="stat"><div class="n" style="color:#1e293b">{total}</div><div class="l">Total Findings</div></div>
  <div class="stat"><div class="n" style="color:#dc2626">{sev_t[CRITICAL]}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n" style="color:#ea580c">{sev_t[HIGH]}</div><div class="l">High</div></div>
  <div class="stat"><div class="n" style="color:#ca8a04">{sev_t[MEDIUM]}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n" style="color:#2563eb">{sev_t[LOW]}</div><div class="l">Low</div></div>
</div>

<!-- CHARTS -->
<div class="charts">
  <div class="chart-card"><div class="chart-label">Findings by OWASP Framework</div><canvas id="cCat" height="190"></canvas></div>
  <div class="chart-card"><div class="chart-label">Severity Breakdown</div><canvas id="cSev" height="190"></canvas></div>
  <div class="chart-card"><div class="chart-label">Riskiest Repositories (findings count)</div><canvas id="cRepo" height="190"></canvas></div>
</div>

<!-- CROSS-SERVICE INSIGHTS -->
<div class="insights">
  <div class="sec-title">⚡ Cross-Service Insights
    <span class="sub">Patterns spanning multiple microservices — unique to this multi-repo agent</span>
  </div>
  {insight_html}
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
<div class="sec-title">📊 Repository Risk Scores</div>
<div class="rgrid">{cards}</div>

<!-- FINDINGS TABLE -->
<div class="fwrap">
  <div class="sec-title">🔍 All Findings</div>
  <div class="filters">
    <select id="fSev" onchange="filt()">
      <option value="">All Severities</option>
      <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
    </select>
    <select id="fCat" onchange="filt()">
      <option value="">All Categories</option>
      <option value="web">🌐 Web</option>
      <option value="api">🔌 API</option>
      <option value="ai">🤖 AI/LLM</option>
    </select>
    <input id="fRepo" oninput="filt()" placeholder="Filter by repo..." style="width:180px"/>
    <input id="fFind" oninput="filt()" placeholder="Filter by finding..." style="width:200px"/>
  </div>
  <div style="overflow-x:auto">
    <table class="ft">
      <thead><tr>
        <th>Repository</th><th>Severity</th><th>Category</th>
        <th>Finding</th><th>OWASP</th><th>Location</th><th>Code Snippet</th>
      </tr></thead>
      <tbody id="tb">{rows}</tbody>
    </table>
  </div>
</div>

<footer>
  Generated by OWASP Multi-Repo Security Agent &nbsp;·&nbsp; {scan_time}<br>
  OWASP Web Top 10 (2021) &nbsp;·&nbsp; OWASP API Top 10 (2023) &nbsp;·&nbsp; OWASP LLM Top 10 (2025)
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
const rn={chart_repos}, rt={chart_totals};
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
  document.querySelectorAll('.frow').forEach(tr=>{{
    const ok=(!sev||tr.dataset.sev===sev)&&(!cat||tr.dataset.cat===cat)&&
             (!rep||tr.dataset.repo.toLowerCase().includes(rep))&&
             (!fnd||tr.cells[3].textContent.toLowerCase().includes(fnd));
    tr.style.display=ok?'':'none';
  }});
}}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="OWASP Multi-Repo Security Scanner Agent — Web, API & AI Top 10",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all repos in a GitHub organisation
  python owasp_agent.py --org acme-corp --token ghp_xxxxx

  # Scan specific microservices
  python owasp_agent.py --org acme-corp --repos auth-svc,order-svc,ai-svc --token ghp_xxxxx

  # GitHub Enterprise
  python owasp_agent.py --org acme-corp --token ghp_xxx --github-url https://github.acme.com/api/v3

  # Scan repos already cloned locally (no GitHub token needed)
  python owasp_agent.py --local /workspace/microservices --org acme-corp

  # Use environment variable
  export GITHUB_TOKEN=ghp_xxxxx
  python owasp_agent.py --org acme-corp
""")
    ap.add_argument("--org",        required=True,                     help="GitHub org or username")
    ap.add_argument("--token",      default=os.getenv("GITHUB_TOKEN"), help="GitHub PAT (or set GITHUB_TOKEN env var)")
    ap.add_argument("--repos",                                         help="Comma-separated repo names (default: all in org)")
    ap.add_argument("--exclude",                                       help="Comma-separated repo names to skip")
    ap.add_argument("--github-url", default="https://api.github.com", help="GitHub API base URL (for Enterprise)")
    ap.add_argument("--output",     default="owasp_dashboard.html",   help="Output HTML dashboard filename")
    ap.add_argument("--json-out",   default="owasp_report.json",      help="Output JSON report filename")
    ap.add_argument("--max-repos",  type=int, default=100,            help="Max repos to scan (default 100)")
    ap.add_argument("--local",                                         help="Path to directory of already-cloned repos")
    args = ap.parse_args()

    if not args.token and not args.local:
        ap.error("Provide --token (or set GITHUB_TOKEN) unless using --local mode")

    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{'='*56}")
    print(f"  OWASP Multi-Repo Security Agent")
    print(f"{'='*56}")
    print(f"  Org/Target   : {args.org}")
    print(f"  Scan started : {scan_time}")
    print(f"  Rules loaded : {len(RULES)} checks  (Web / API / AI/LLM)")
    print(f"{'='*56}\n")

    scanner: RepoScanner            = RepoScanner(RULES)
    repo_results: Dict[str, List[Finding]] = {}

    # ── LOCAL MODE ──
    if args.local:
        root = Path(args.local)
        if not root.is_dir():
            print(f"ERROR: --local '{args.local}' is not a directory", file=sys.stderr)
            sys.exit(1)
        dirs = sorted(d for d in root.iterdir() if d.is_dir() and not d.name.startswith("."))
        print(f"  Found {len(dirs)} dirs under {root}\n")
        for i, d in enumerate(dirs, 1):
            print(f"  [{i:>3}/{len(dirs)}] {d.name:<38}", end="", flush=True)
            fl = scanner.scan_repo(d)
            repo_results[d.name] = fl
            cr = sum(1 for f in fl if f.severity == CRITICAL)
            hi = sum(1 for f in fl if f.severity == HIGH)
            print(f"-> {len(fl):>4} findings  ({cr} critical / {hi} high)")

    # ── GITHUB MODE ──
    else:
        if not HAS_REQUESTS:
            print("ERROR: pip install requests  (required for GitHub mode)", file=sys.stderr)
            sys.exit(1)
        client   = GitHubClient(args.token, args.github_url)
        excl_set = set(x.strip() for x in args.exclude.split(",")) if args.exclude else set()
        print("  Fetching repo list from GitHub...", end="", flush=True)
        try:
            repos = client.get_specific_repos(args.org, args.repos.split(",")) \
                    if args.repos else client.get_repos(args.org)
        except Exception as exc:
            print(f"\n  ERROR: {exc}", file=sys.stderr); sys.exit(1)

        repos = [r for r in repos if r["name"] not in excl_set and not r.get("archived")]
        repos = repos[:args.max_repos]
        print(f" {len(repos)} repos\n")

        with tempfile.TemporaryDirectory(prefix="owasp_") as tmp:
            tp = Path(tmp)
            for i, repo in enumerate(repos, 1):
                nm = repo["name"]
                print(f"  [{i:>3}/{len(repos)}] {nm:<38}", end="", flush=True)
                dest = tp / nm
                if clone_repo(repo["clone_url"], dest, args.token):
                    fl = scanner.scan_repo(dest)
                    repo_results[nm] = fl
                    cr = sum(1 for f in fl if f.severity == CRITICAL)
                    hi = sum(1 for f in fl if f.severity == HIGH)
                    print(f"-> {len(fl):>4} findings  ({cr} critical / {hi} high)")
                else:
                    print("-> clone failed, skipped")
                    repo_results[nm] = []

    # ── CROSS-SERVICE ANALYSIS ──
    print(f"\n  Running cross-service analysis...", end="", flush=True)
    insights = CrossServiceAnalyzer().analyze(repo_results)
    print(f" {len(insights)} insights found\n")

    # ── HTML DASHBOARD ──
    html = generate_dashboard(repo_results, insights, args.org, scan_time)
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"  HTML dashboard  -> {Path(args.output).resolve()}")

    # ── JSON REPORT ──
    report = {
        "scan_time": scan_time, "org": args.org,
        "total_repos": len(repo_results),
        "total_findings": sum(len(fl) for fl in repo_results.values()),
        "severity_summary": {
            sev: sum(sum(1 for f in fl if f.severity == sev) for fl in repo_results.values())
            for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]
        },
        "cross_service_insights": insights,
        "repos": {n: [f.to_dict() for f in fl] for n, fl in repo_results.items()},
    }
    Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  JSON report     -> {Path(args.json_out).resolve()}")

    tot  = report["total_findings"]
    crit = report["severity_summary"][CRITICAL]
    cross= len([i for i in insights if i["type"] == "systemic_pattern"])
    print(f"\n{'='*56}")
    print(f"  Scan complete!")
    print(f"  Repos scanned       : {len(repo_results)}")
    print(f"  Total findings      : {tot}")
    print(f"  Critical            : {crit}")
    print(f"  Cross-svc patterns  : {cross}")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()
