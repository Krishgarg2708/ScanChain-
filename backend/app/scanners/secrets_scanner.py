"""
Secrets Scanner
Regex-based detection of hardcoded credentials, API keys, tokens, and
private key material in source files. Entropy check reduces false positives
on generic-looking assignments.
"""
import re
import math

PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9]{36,255}"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    ("Generic API Key", r"(?i)api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,64}['\"]"),
    ("JWT", r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ("Private Key Block", r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"),
    ("SSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("Generic Password", r"(?i)password\s*[:=]\s*['\"][^'\"\s]{6,64}['\"]"),
    ("Database Connection String", r"(?i)(postgres|mysql|mongodb)(\+\w+)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"),
    ("Stripe Key", r"sk_live_[0-9A-Za-z]{24,}"),
]

COMPILED = [(name, re.compile(pattern)) for name, pattern in PATTERNS]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def scan_secrets(files: dict):
    """files: dict of {filename: content_str}. Returns list of findings."""
    findings = []
    for fname, content in files.items():
        if not isinstance(content, str):
            continue
        lines = content.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for name, pattern in COMPILED:
                match = pattern.search(line)
                if match:
                    snippet = match.group(0)
                    # crude high-entropy confirmation for generic patterns
                    is_generic = name.startswith("Generic")
                    ent = shannon_entropy(snippet)
                    if is_generic and ent < 3.0:
                        continue
                    masked = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 12 else "***"
                    findings.append({
                        "scanner": "secrets",
                        "severity": "critical" if "Private Key" in name or "AWS" in name else "high",
                        "title": f"{name} detected",
                        "description": f"Potential hardcoded secret ({name}) found: {masked}",
                        "location": f"{fname}:{lineno}",
                        "cve_id": None,
                        "cvss": 8.5,
                        "remediation": "Remove the secret from source, rotate the credential immediately, "
                                       "and load it from a secrets manager or environment variable instead.",
                    })
    return findings
