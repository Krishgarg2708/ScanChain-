"""
Binary Scanner
Computes MD5/SHA1/SHA256, Shannon entropy (packing/obfuscation indicator),
and — for PE files — imports/exports/sections via pefile if available.
"""
import hashlib
import math
import re

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

SUSPICIOUS_STRINGS = [
    (rb"powershell(\.exe)?\s+-enc(odedcommand)?", "Encoded PowerShell invocation"),
    (rb"cmd\.exe\s+/c", "Shell command execution"),
    (rb"WScript\.Shell", "WScript shell object (common in droppers)"),
    (rb"CreateRemoteThread", "Remote thread injection API"),
    (rb"VirtualAllocEx", "Remote memory allocation API"),
    (rb"WriteProcessMemory", "Process memory write API (injection primitive)"),
    (rb"IsDebuggerPresent", "Anti-debugging check"),
    (rb"(?i)bitcoin|monero|stratum\+tcp", "Cryptocurrency / mining pool reference"),
    (rb"(?i)vssadmin\s+delete\s+shadows", "Shadow copy deletion (ransomware indicator)"),
    (rb"(?i)-----BEGIN.*PRIVATE KEY-----", "Embedded private key material"),
]


def file_hashes(data: bytes):
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if HAS_SSDEEP:
        try:
            hashes["ssdeep"] = ssdeep.hash(data)
        except Exception:
            hashes["ssdeep"] = None
    else:
        hashes["ssdeep"] = None
    return hashes


def fuzzy_similarity(hash_a: str, hash_b: str) -> int:
    """0-100 similarity score between two ssdeep hashes. Requires ssdeep to be installed."""
    if not HAS_SSDEEP or not hash_a or not hash_b:
        return 0
    try:
        return ssdeep.compare(hash_a, hash_b)
    except Exception:
        return 0


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def scan_pe_metadata(data: bytes):
    if not HAS_PEFILE:
        return {"available": False, "note": "pefile not installed; PE-specific analysis skipped."}
    try:
        pe = pefile.PE(data=data)
    except Exception:
        return {"available": False, "note": "Not a valid PE file or parse error."}
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append(entry.dll.decode(errors="ignore"))
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode(errors="ignore"))
    return {
        "available": True,
        "imported_dlls": imports,
        "exported_functions": exports[:50],
        "is_dll": pe.is_dll(),
        "is_exe": pe.is_exe(),
        "machine": hex(pe.FILE_HEADER.Machine),
        "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections],
    }


def scan_binary(filename: str, data: bytes):
    findings = []
    hashes = file_hashes(data)
    entropy = shannon_entropy(data)

    if entropy > 7.5:
        findings.append({
            "scanner": "binary",
            "severity": "high",
            "title": f"High entropy file: {filename}",
            "description": f"File entropy is {entropy}/8.0, consistent with packing, encryption, "
                            f"or compression — a common evasion technique.",
            "location": filename,
            "cve_id": None,
            "cvss": 6.5,
            "remediation": "Manually inspect with a disassembler/unpacker; verify against known-good hash.",
        })

    for pattern, desc in SUSPICIOUS_STRINGS:
        if re.search(pattern, data):
            findings.append({
                "scanner": "binary",
                "severity": "high" if "injection" in desc.lower() or "shadow" in desc.lower() else "medium",
                "title": desc,
                "description": f"Suspicious pattern matched in {filename}: {desc}",
                "location": filename,
                "cve_id": None,
                "cvss": 7.0,
                "remediation": "Review the binary/script manually; treat as untrusted until verified.",
            })

    pe_info = scan_pe_metadata(data) if filename.lower().endswith((".exe", ".dll", ".sys")) else {"available": False}

    return {
        "hashes": hashes,
        "entropy": entropy,
        "pe_metadata": pe_info,
        "findings": findings,
    }
