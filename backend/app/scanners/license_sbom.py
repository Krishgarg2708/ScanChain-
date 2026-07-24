"""
License Scanner + SBOM Generator + Risk Engine
"""
import uuid
import datetime

COPYLEFT = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"}

# Minimal offline license inference for common PyPI/npm packages (illustrative seed).
KNOWN_LICENSES = {
    "requests": "Apache-2.0", "flask": "BSD-3-Clause", "django": "BSD-3-Clause",
    "numpy": "BSD-3-Clause", "react": "MIT", "lodash": "MIT", "express": "MIT",
    "gpl-sample-pkg": "GPL-3.0",
}


def scan_licenses(packages: list):
    findings = []
    license_summary = {}
    for pkg in packages:
        lic = KNOWN_LICENSES.get(pkg["name"].lower(), "Unknown")
        license_summary[pkg["name"]] = lic
        if lic in COPYLEFT:
            findings.append({
                "scanner": "license",
                "severity": "medium",
                "title": f"Copyleft license: {pkg['name']} ({lic})",
                "description": f"'{pkg['name']}' is licensed under {lic}, a strong/weak copyleft license "
                                f"that may impose obligations if you distribute derivative works.",
                "location": pkg["name"],
                "cve_id": None,
                "cvss": None,
                "remediation": "Review license compatibility with your project's distribution model, "
                                "or replace with a permissively-licensed alternative.",
            })
        elif lic == "Unknown":
            findings.append({
                "scanner": "license",
                "severity": "low",
                "title": f"Unknown license: {pkg['name']}",
                "description": f"Could not determine the license for '{pkg['name']}' from the local "
                                f"license database.",
                "location": pkg["name"],
                "cve_id": None,
                "cvss": None,
                "remediation": "Check the package's registry page or LICENSE file manually.",
            })
    return findings, license_summary


def generate_sbom(project_name: str, packages: list, license_summary: dict, fmt="cyclonedx"):
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    if fmt == "cyclonedx":
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {"timestamp": timestamp, "component": {"type": "application", "name": project_name}},
            "components": [
                {
                    "type": "library",
                    "name": p["name"],
                    "version": p.get("version") or "unknown",
                    "purl": f"pkg:{p['ecosystem'].lower()}/{p['name']}@{p.get('version') or 'unknown'}",
                    "licenses": [{"license": {"id": license_summary.get(p["name"], "Unknown")}}],
                }
                for p in packages
            ],
        }
    else:  # spdx
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": project_name,
            "creationInfo": {"created": timestamp, "creators": ["Tool: ScanChain-1.0"]},
            "packages": [
                {
                    "SPDXID": f"SPDXRef-Package-{i}",
                    "name": p["name"],
                    "versionInfo": p.get("version") or "NOASSERTION",
                    "licenseConcluded": license_summary.get(p["name"], "NOASSERTION"),
                }
                for i, p in enumerate(packages)
            ],
        }


SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}


def compute_risk_score(findings: list):
    """Returns 0-100 risk score (100 = worst) plus category breakdown."""
    category_scores = {}
    for f in findings:
        cat = f["scanner"]
        category_scores.setdefault(cat, 0)
        category_scores[cat] += SEVERITY_WEIGHT.get(f["severity"], 0)

    raw_total = sum(category_scores.values())
    # Diminishing-returns curve so score saturates instead of blowing past 100
    normalized = 100 - (100 / (1 + raw_total / 40))
    overall = round(min(100, max(0, normalized)), 1)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "overall_score": overall,
        "category_scores": category_scores,
        "severity_counts": counts,
        "total_findings": len(findings),
    }
