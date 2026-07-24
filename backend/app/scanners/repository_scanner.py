"""
Repository Scanner
Clones a public Git repository locally (read-only, no credentials required)
and walks commit history for secrets that were introduced and possibly later
removed — a common way credentials leak even after a "fix" commit.
"""
import tempfile
import shutil
from git import Repo, GitCommandError
from .secrets_scanner import COMPILED, shannon_entropy

MAX_COMMITS_SCANNED = 50  # cap for scan time in a hosted/interactive context


def clone_repo(url: str):
    tmpdir = tempfile.mkdtemp(prefix="scanchain_repo_")
    try:
        repo = Repo.clone_from(url, tmpdir, depth=200)  # shallow clone, still gives useful history
    except GitCommandError as e:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise ValueError(f"Failed to clone repository: {e}")
    return repo, tmpdir


def scan_commit_diff(diff_text: str, commit_hexsha: str, commit_message: str):
    findings = []
    for lineno, line in enumerate(diff_text.splitlines(), start=1):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        content = line[1:]
        for name, pattern in COMPILED:
            match = pattern.search(content)
            if match:
                snippet = match.group(0)
                is_generic = name.startswith("Generic")
                if is_generic and shannon_entropy(snippet) < 3.0:
                    continue
                masked = snippet[:6] + "..." + snippet[-4:] if len(snippet) > 12 else "***"
                findings.append({
                    "scanner": "repository",
                    "severity": "critical" if "Private Key" in name or "AWS" in name else "high",
                    "title": f"Historical secret in commit {commit_hexsha[:8]}: {name}",
                    "description": f"Commit \"{commit_message.strip()[:80]}\" introduced a potential {name}: "
                                    f"{masked}. Even if later removed, this remains in git history.",
                    "location": f"commit {commit_hexsha[:8]}",
                    "cve_id": None,
                    "cvss": 9.0,
                    "remediation": "Rotate this credential immediately — it is permanently visible in git "
                                   "history until the history is rewritten (git filter-repo / BFG) and force-pushed.",
                })
    return findings


def scan_repository(url: str):
    """Clones the repo and scans recent commit history for leaked secrets. Returns (findings, meta)."""
    repo, tmpdir = clone_repo(url)
    findings = []
    commits_scanned = 0
    try:
        commits = list(repo.iter_commits(max_count=MAX_COMMITS_SCANNED))
        for commit in commits:
            commits_scanned += 1
            try:
                if commit.parents:
                    diff_text = repo.git.diff(commit.parents[0].hexsha, commit.hexsha)
                else:
                    diff_text = repo.git.show(commit.hexsha)
            except GitCommandError:
                continue
            findings.extend(scan_commit_diff(diff_text, commit.hexsha, commit.message))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return findings, {"commits_scanned": commits_scanned, "url": url}
