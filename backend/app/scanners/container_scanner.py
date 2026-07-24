"""
Container Scanner
Static analysis of Dockerfiles for common misconfigurations. Does not require
a Docker daemon or registry access — pure text/instruction analysis, so it
works fully offline in any environment.
"""
import re

OUTDATED_BASE_TAGS = ("latest", "")  # 'latest' or no tag pinned at all


def parse_dockerfile(content: str):
    instructions = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if parts:
            instructions.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return instructions


def scan_dockerfile(filename: str, content: str):
    findings = []
    instructions = parse_dockerfile(content)

    from_lines = [i for i in instructions if i[0] == "FROM"]
    user_lines = [i for i in instructions if i[0] == "USER"]
    expose_lines = [i for i in instructions if i[0] == "EXPOSE"]
    run_lines = [i for i in instructions if i[0] == "RUN"]
    add_lines = [i for i in instructions if i[0] == "ADD"]
    env_lines = [i for i in instructions if i[0] == "ENV"]

    # --- Base image pinning ---
    for _, arg in from_lines:
        image = arg.split()[0] if arg else ""
        if ":" not in image or image.split(":")[-1] in OUTDATED_BASE_TAGS:
            findings.append({
                "scanner": "container",
                "severity": "medium",
                "title": f"Unpinned base image: {image or '(none)'}",
                "description": f"Base image '{image}' does not pin a specific version tag. "
                                f"Using 'latest' or an untagged image makes builds non-reproducible "
                                f"and can silently pull in new vulnerabilities.",
                "location": filename,
                "cve_id": None,
                "cvss": 4.0,
                "remediation": "Pin to a specific, ideally digest-referenced tag, e.g. "
                                "'python:3.12.3-slim@sha256:...'.",
            })

    # --- Running as root ---
    if not user_lines:
        findings.append({
            "scanner": "container",
            "severity": "high",
            "title": "Container runs as root",
            "description": "No USER instruction found — the container will run as root by default, "
                            "widening the blast radius of any compromise inside the container.",
            "location": filename,
            "cve_id": None,
            "cvss": 6.5,
            "remediation": "Add 'USER <non-root-uid>' after installing dependencies, "
                            "and create a dedicated unprivileged user in the image.",
        })
    else:
        for _, arg in user_lines:
            if arg.strip() in ("root", "0"):
                findings.append({
                    "scanner": "container",
                    "severity": "high",
                    "title": "Explicit USER root",
                    "description": "Dockerfile explicitly sets USER to root.",
                    "location": filename,
                    "cve_id": None,
                    "cvss": 6.5,
                    "remediation": "Run the container as a non-root user.",
                })

    # --- Secrets in ENV / ARG / RUN ---
    secret_pattern = re.compile(r"(?i)(password|secret|api[_-]?key|token|access[_-]?key)\s*=\s*\S+")
    for kind, arg in env_lines + [i for i in instructions if i[0] == "ARG"]:
        if secret_pattern.search(arg):
            findings.append({
                "scanner": "container",
                "severity": "critical",
                "title": "Hardcoded secret in Dockerfile",
                "description": f"A {kind} instruction appears to embed a credential directly in the image layer, "
                                f"which persists in image history even if removed later.",
                "location": filename,
                "cve_id": None,
                "cvss": 8.0,
                "remediation": "Use build secrets (--mount=type=secret) or inject credentials at runtime "
                                "via environment variables / a secrets manager instead.",
            })

    # --- Exposed sensitive ports ---
    sensitive_ports = {"22": "SSH", "3389": "RDP", "3306": "MySQL", "5432": "PostgreSQL",
                        "6379": "Redis", "27017": "MongoDB", "9200": "Elasticsearch"}
    for _, arg in expose_lines:
        for port in re.findall(r"\d+", arg):
            if port in sensitive_ports:
                findings.append({
                    "scanner": "container",
                    "severity": "medium",
                    "title": f"Sensitive service port exposed: {port} ({sensitive_ports[port]})",
                    "description": f"EXPOSE {port} publishes a {sensitive_ports[port]} port. Confirm this is "
                                    f"intentional and network-restricted in your orchestration layer.",
                    "location": filename,
                    "cve_id": None,
                    "cvss": 5.0,
                    "remediation": "Restrict exposure via network policies / security groups, "
                                    "or avoid exposing management ports from application containers.",
                })

    # --- curl|bash / wget|sh pattern ---
    pipe_shell_pattern = re.compile(r"(curl|wget)[^|;]*\|\s*(sh|bash)")
    for _, arg in run_lines:
        if pipe_shell_pattern.search(arg):
            findings.append({
                "scanner": "container",
                "severity": "high",
                "title": "Piping remote script directly to shell",
                "description": "RUN instruction downloads and executes a remote script without "
                                "integrity verification (curl|bash / wget|sh pattern).",
                "location": filename,
                "cve_id": None,
                "cvss": 7.0,
                "remediation": "Download the script, verify its checksum/signature, then execute — "
                                "don't pipe directly to a shell.",
            })

    # --- ADD instead of COPY for remote URLs ---
    for _, arg in add_lines:
        if arg.strip().startswith(("http://", "https://")):
            findings.append({
                "scanner": "container",
                "severity": "low",
                "title": "ADD used to fetch remote URL",
                "description": "ADD with a remote URL bypasses build-time caching and layer transparency "
                                "that COPY provides; prefer explicit RUN curl/wget with checksum verification.",
                "location": filename,
                "cve_id": None,
                "cvss": 3.0,
                "remediation": "Replace with RUN curl -fsSL <url> -o file && verify checksum.",
            })

    return findings


def scan_container(files: dict):
    """files: dict of {filename: content}. Detects any Dockerfile-like entries."""
    findings = []
    for fname, content in files.items():
        base = fname.lower().split("/")[-1]
        if base == "dockerfile" or base.startswith("dockerfile."):
            findings.extend(scan_dockerfile(fname, content))
    return findings
