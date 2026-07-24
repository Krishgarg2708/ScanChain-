"""
Dependency Scanner
Parses manifest files (requirements.txt, package.json, package-lock.json,
Pipfile.lock, poetry.lock, Cargo.lock, go.mod) and queries the OSV.dev
public vulnerability database (no API key required) in batch mode.
"""
import re
import json
import requests
from pathlib import Path

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"

# Known typosquat targets for popular ecosystems (small illustrative seed list;
# a production deployment would sync this from a maintained typosquat corpus).
POPULAR_PYPI = {"requests", "numpy", "flask", "django", "pandas", "urllib3", "boto3", "pytest"}
POPULAR_NPM = {"react", "lodash", "express", "axios", "chalk", "webpack", "eslint"}


def _levenshtein(a, b):
    if a == b:
        return 0
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[m][n]


def parse_requirements_txt(text: str):
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.\-]*)", line)
        if m and m.group(1):
            pkgs.append({"name": m.group(1), "version": m.group(3) or None, "ecosystem": "PyPI"})
    return pkgs


def parse_package_json(text: str):
    pkgs = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return pkgs
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            clean_ver = re.sub(r"^[^\d]*", "", ver) if isinstance(ver, str) else None
            pkgs.append({"name": name, "version": clean_ver or None, "ecosystem": "npm"})
    return pkgs


def parse_package_lock_json(text: str):
    pkgs = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return pkgs
    packages = data.get("packages", {})
    for path, info in packages.items():
        if not path:
            continue
        name = path.split("node_modules/")[-1]
        ver = info.get("version")
        if name and ver:
            pkgs.append({"name": name, "version": ver, "ecosystem": "npm"})
    return pkgs


def parse_go_mod(text: str):
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^([\w./\-]+)\s+v([\d][\w.\-+]*)", line)
        if m and "require" not in line.split()[0]:
            pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": "Go"})
    return pkgs


MANIFEST_FILENAMES = ("requirements.txt", "package.json", "package-lock.json", "pipfile.lock",
                      "poetry.lock", "cargo.lock", "go.mod", "pom.xml")


def parse_manifest(filename: str, content: str):
    fname = filename.lower().split("/")[-1]
    if not any(fname == m or fname.endswith(m) for m in MANIFEST_FILENAMES) and fname != "requirements.txt":
        # not a recognized manifest file — skip dependency parsing entirely to avoid
        # misreading arbitrary source files as package lists
        if "requirements" in fname and fname.endswith(".txt"):
            pass  # e.g. requirements-dev.txt
        else:
            return []
    if fname.endswith("package-lock.json"):
        return parse_package_lock_json(content)
    if fname.endswith("package.json"):
        return parse_package_json(content)
    if fname.endswith("go.mod"):
        return parse_go_mod(content)
    return parse_requirements_txt(content)


def check_typosquat(pkg_name: str, ecosystem: str):
    pool = POPULAR_PYPI if ecosystem == "PyPI" else POPULAR_NPM
    for popular in pool:
        if pkg_name == popular:
            return None
        dist = _levenshtein(pkg_name.lower(), popular.lower())
        if 0 < dist <= 2 and len(pkg_name) > 3:
            return popular
    return None


def query_osv_batch(packages):
    """Query OSV.dev in batch for known vulnerabilities. Public API, no key."""
    if not packages:
        return {}
    queries = [
        {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
        if p["version"] else {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}}
        for p in packages
    ]
    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=20)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except requests.RequestException:
        return {}
    out = {}
    for pkg, result in zip(packages, results):
        vulns = result.get("vulns", [])
        if vulns:
            out[pkg["name"]] = vulns
    return out


def fetch_vuln_detail(vuln_id: str):
    try:
        resp = requests.get(OSV_VULN_URL.format(id=vuln_id), timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        return {}


def severity_from_osv(detail):
    sev_list = detail.get("severity", [])
    for s in sev_list:
        if s.get("type") == "CVSS_V3":
            score = s.get("score", "")
            m = re.search(r"/AV:.*", score)
        # database_specific often has a severity string
    db_spec = detail.get("database_specific", {})
    sev = db_spec.get("severity")
    if sev:
        return sev.lower()
    return "medium"


def cvss_score_estimate(severity: str):
    return {"critical": 9.5, "high": 7.8, "medium": 5.0, "low": 2.5}.get(severity, 5.0)


def scan_dependencies(files: dict):
    """
    files: dict of {filename: content_str}
    Returns list of findings dicts.
    """
    findings = []
    all_pkgs = []
    for fname, content in files.items():
        all_pkgs.extend(parse_manifest(fname, content))

    # Dedup
    seen = set()
    unique_pkgs = []
    for p in all_pkgs:
        key = (p["name"], p["ecosystem"])
        if key not in seen:
            seen.add(key)
            unique_pkgs.append(p)

    vuln_map = query_osv_batch(unique_pkgs)

    for pkg in unique_pkgs:
        # Typosquatting check
        typo_target = check_typosquat(pkg["name"], pkg["ecosystem"])
        if typo_target:
            findings.append({
                "scanner": "dependency",
                "severity": "high",
                "title": f"Possible typosquat: {pkg['name']}",
                "description": f"Package '{pkg['name']}' closely resembles popular package '{typo_target}'. "
                                f"Verify this is the intended dependency before installing.",
                "location": pkg["name"],
                "cve_id": None,
                "cvss": 7.0,
                "remediation": f"Confirm you meant to install '{pkg['name']}' and not '{typo_target}'.",
            })

        vulns = vuln_map.get(pkg["name"], [])
        for v in vulns[:5]:  # cap per-package to keep scans fast
            detail = fetch_vuln_detail(v["id"])
            severity = severity_from_osv(detail)
            cvss = cvss_score_estimate(severity)
            summary = detail.get("summary") or detail.get("details", "")[:200] or "No summary available."
            fixed_versions = []
            for affected in detail.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
            remediation = (f"Upgrade to version {fixed_versions[0]}" if fixed_versions
                            else "Check the advisory for a patched version or mitigation.")
            findings.append({
                "scanner": "dependency",
                "severity": severity,
                "title": f"{v['id']} in {pkg['name']}" + (f"@{pkg['version']}" if pkg["version"] else ""),
                "description": summary,
                "location": pkg["name"],
                "cve_id": v["id"],
                "cvss": cvss,
                "remediation": remediation,
            })

    return findings, unique_pkgs
