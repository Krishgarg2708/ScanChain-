"""
Static Code Analysis Scanner
Wraps Semgrep (multi-language) and Bandit (Python-specific) as subprocesses,
parses their JSON output into the platform's unified finding schema.
"""
import json
import shutil
import subprocess
import tempfile
import os

SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
BANDIT_SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _write_temp_project(files: dict) -> str:
    tmpdir = tempfile.mkdtemp(prefix="scanchain_static_")
    for fname, content in files.items():
        # Only allow relative paths inside the temp dir; strip leading slashes/zip weirdness
        safe_name = fname.lstrip("/").replace("..", "_")
        full_path = os.path.join(tmpdir, safe_name)
        os.makedirs(os.path.dirname(full_path) or tmpdir, exist_ok=True)
        try:
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError:
            continue
    return tmpdir


def run_semgrep(tmpdir: str, timeout: int = 60):
    """Runs Semgrep with the 'auto' ruleset config (offline default rules bundled with the CLI)."""
    findings = []
    if not shutil.which("semgrep"):
        return findings, "semgrep not installed"
    try:
        result = subprocess.run(
            ["semgrep", "--config", "p/security-audit", "--config", "p/secrets",
             "--json", "--quiet", "--timeout", str(timeout), tmpdir],
            capture_output=True, text=True, timeout=timeout + 30,
        )
        data = json.loads(result.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return findings, "semgrep run failed or timed out"

    for r in data.get("results", []):
        sev = SEMGREP_SEVERITY_MAP.get(r.get("extra", {}).get("severity", "WARNING"), "medium")
        rel_path = os.path.relpath(r["path"], tmpdir)
        findings.append({
            "scanner": "static_analysis",
            "severity": sev,
            "title": r.get("check_id", "Semgrep finding").split(".")[-1],
            "description": r.get("extra", {}).get("message", "")[:400],
            "location": f"{rel_path}:{r['start']['line']}",
            "cve_id": None,
            "cvss": None,
            "remediation": "Review the flagged pattern; see Semgrep rule docs for the specific check.",
        })
    return findings, None


def run_bandit(tmpdir: str, timeout: int = 60):
    """Runs Bandit against any .py files in the extracted project."""
    findings = []
    if not shutil.which("bandit"):
        return findings, "bandit not installed"
    try:
        result = subprocess.run(
            ["bandit", "-r", tmpdir, "-f", "json"],
            capture_output=True, text=True, timeout=timeout,
        )
        data = json.loads(result.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return findings, "bandit run failed or timed out"

    for r in data.get("results", []):
        sev = BANDIT_SEVERITY_MAP.get(r.get("issue_severity", "MEDIUM"), "medium")
        rel_path = os.path.relpath(r["filename"], tmpdir)
        findings.append({
            "scanner": "static_analysis",
            "severity": sev,
            "title": f"{r.get('test_id')}: {r.get('test_name')}",
            "description": r.get("issue_text", "")[:400],
            "location": f"{rel_path}:{r['line_number']}",
            "cve_id": None,
            "cvss": {"high": 7.5, "medium": 5.0, "low": 2.5}.get(sev, 5.0),
            "remediation": r.get("more_info", "Review Bandit's documentation for this check ID."),
        })
    return findings, None


def scan_static_analysis(files: dict):
    """
    Runs Semgrep + Bandit over the provided source files.
    files: dict of {filename: content_str}
    Returns (findings list, errors list)
    """
    py_or_code_files = {
        f: c for f, c in files.items()
        if f.lower().endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php"))
    }
    if not py_or_code_files:
        return [], []

    tmpdir = _write_temp_project(py_or_code_files)
    errors = []
    all_findings = []

    semgrep_findings, semgrep_err = run_semgrep(tmpdir)
    all_findings.extend(semgrep_findings)
    if semgrep_err:
        errors.append(semgrep_err)

    bandit_findings, bandit_err = run_bandit(tmpdir)
    all_findings.extend(bandit_findings)
    if bandit_err:
        errors.append(bandit_err)

    shutil.rmtree(tmpdir, ignore_errors=True)
    return all_findings, errors
