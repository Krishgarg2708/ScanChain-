"""
MITRE ATT&CK Mapping
Maps finding categories/titles to ATT&CK techniques using keyword heuristics.
This is a lightweight local mapping (no API key/network needed) covering the
technique families most relevant to supply-chain compromise.
"""

# (keyword_pattern, technique_id, technique_name, tactic)
TECHNIQUE_RULES = [
    ("typosquat", "T1195.001", "Compromise Software Dependencies and Development Tools", "Initial Access"),
    ("supply chain", "T1195", "Supply Chain Compromise", "Initial Access"),
    ("hardcoded secret", "T1552.001", "Credentials In Files", "Credential Access"),
    ("private key", "T1552.004", "Private Keys", "Credential Access"),
    ("aws", "T1552.001", "Credentials In Files", "Credential Access"),
    ("password", "T1552.001", "Credentials In Files", "Credential Access"),
    ("historical secret", "T1552.001", "Credentials In Files (Git History)", "Credential Access"),
    ("reverse shell", "T1059", "Command and Scripting Interpreter", "Execution"),
    ("encoded powershell", "T1059.001", "PowerShell", "Execution"),
    ("webshell", "T1505.003", "Web Shell", "Persistence"),
    ("process injection", "T1055", "Process Injection", "Defense Evasion"),
    ("remote thread", "T1055", "Process Injection", "Defense Evasion"),
    ("packer", "T1027.002", "Software Packing", "Defense Evasion"),
    ("high entropy", "T1027", "Obfuscated Files or Information", "Defense Evasion"),
    ("anti-debug", "T1622", "Debugger Evasion", "Defense Evasion"),
    ("cryptocurrency", "T1496", "Resource Hijacking", "Impact"),
    ("miner", "T1496", "Resource Hijacking", "Impact"),
    ("shadow copy", "T1490", "Inhibit System Recovery", "Impact"),
    ("ransomware", "T1486", "Data Encrypted for Impact", "Impact"),
    ("command injection", "T1059", "Command and Scripting Interpreter", "Execution"),
    ("sql injection", "T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("shell equals true", "T1059", "Command and Scripting Interpreter", "Execution"),
    ("root", "T1611", "Escape to Host", "Privilege Escalation"),
    ("curl", "T1105", "Ingress Tool Transfer", "Command and Control"),
    ("piping remote script", "T1105", "Ingress Tool Transfer", "Command and Control"),
    ("cve", "T1190", "Exploit Public-Facing Application", "Initial Access"),
    ("unpinned base image", "T1195.001", "Compromise Software Supply Chain", "Initial Access"),
]


def map_finding_to_attack(finding: dict):
    """Returns a list of {technique_id, technique_name, tactic} matches for a single finding."""
    haystack = f"{finding.get('title','')} {finding.get('description','')} {finding.get('scanner','')}".lower()
    matches = []
    seen_ids = set()
    for keyword, tid, tname, tactic in TECHNIQUE_RULES:
        if keyword in haystack and tid not in seen_ids:
            matches.append({"technique_id": tid, "technique_name": tname, "tactic": tactic})
            seen_ids.add(tid)
    if finding.get("cve_id") and "T1190" not in seen_ids:
        matches.append({"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
                         "tactic": "Initial Access"})
    return matches


def build_attack_summary(findings: list):
    """Aggregates ATT&CK technique coverage across a full finding set for a scan."""
    technique_counts = {}
    tactics_seen = set()
    for f in findings:
        for m in map_finding_to_attack(f):
            key = m["technique_id"]
            if key not in technique_counts:
                technique_counts[key] = {**m, "count": 0}
            technique_counts[key]["count"] += 1
            tactics_seen.add(m["tactic"])
    return {
        "techniques": sorted(technique_counts.values(), key=lambda x: -x["count"]),
        "tactics_covered": sorted(tactics_seen),
    }
