# ScanChain — Supply Chain Security Scanner

A working, self-hostable supply chain security platform: FastAPI + SQLite backend,
React/TypeScript/Tailwind dashboard. No API keys, no paid services — vulnerability
lookups go to the free public OSV.dev API; everything else runs 100% locally, including
real CLI/library security tools (Semgrep, Bandit, YARA, ssdeep, GitPython) wired in
directly, not mocked.

## Everything below is real, wired, and was tested end-to-end during the build

**Scanners**
- **Dependency** — parses `requirements.txt`/`package.json`/`package-lock.json`/`go.mod`,
  batch-queries OSV.dev, flags typosquats via Levenshtein distance.
- **Secrets** — regex + entropy detection (AWS/GitHub/Slack/Stripe keys, JWTs, private
  keys, DB connection strings).
- **Static analysis** — real **Semgrep** (`p/security-audit` + `p/secrets`) and **Bandit**
  subprocess calls, parsed into unified findings. Verified catching real
  `subprocess(shell=True)` command-injection issues.
- **Malware (YARA)** — a bundled, compiled ruleset (webshells, cryptominers, ransomware
  shadow-copy-deletion, reverse shells, process injection API chains, packer signatures).
  Verified matching planted reverse-shell and cryptominer strings.
- **Container** — static Dockerfile analysis: unpinned base images, root user, hardcoded
  secrets in ENV/ARG, exposed sensitive ports, `curl|bash` patterns, risky `ADD` usage.
- **Repository** — clones a public git repo (shallow, read-only) and walks commit diffs
  for secrets introduced and later "removed" but still live in history. Verified against
  a real GitHub repo.
- **Binary** — MD5/SHA1/SHA256, **ssdeep fuzzy hashing** (for similarity matching against
  known-malicious samples), Shannon entropy, suspicious-API-string matching, PE
  import/export/section parsing via `pefile`.
- **License** + **SBOM** — CycloneDX 1.5 / SPDX 2.3 JSON generation, downloadable.

**Platform**
- **Risk engine** — severity-weighted, diminishing-returns 0–100 score, per-category
  breakdown.
- **MITRE ATT&CK mapping** — every finding is matched against a local technique/tactic
  table (no network call); the scan detail page shows tactic coverage and technique
  counts. Verified producing correct T1059/T1496/T1552 mappings on planted test findings.
- **Report export** — HTML, Markdown, CSV, and PDF (ReportLab), generated from the same
  finding set.
- **Dependency graph API** — bipartite project → package → CVE graph for visualization.
- **Live scan logs** — a real WebSocket endpoint (`/ws/scan/{id}/logs`) streaming each
  scanner stage as it runs, backed by an in-memory pub/sub buffer so a client connecting
  after completion still gets the full transcript. Verified via a live websockets client.
- **Scan scheduling** — APScheduler-backed recurring git-repo scans, persisted in SQLite
  and re-registered on startup; full CRUD API + a Schedules page in the UI.
- **JWT auth + RBAC**, **SQLite persistence**, **React dashboard** with live stats,
  severity pie chart, drag-and-drop upload, "Scan Git Repository" mode, a Scheduled
  Scans page, findings table with severity filters + live log terminal + MITRE panel,
  SBOM + multi-format report download.

## What's still scoped out

- **Live Docker image scanning against a running daemon** — current container scanner is
  static Dockerfile analysis only (no daemon/registry access in this sandbox). Trivy/Grype
  CLI integration would slot in exactly like Semgrep/Bandit did.
- **Custom YARA rule editor / plugin system UI** — the YARA engine itself is real and
  compiled at runtime from `BUILTIN_RULES` in `malware_scanner.py`; an editor UI to submit
  custom rules through the frontend isn't built yet.
- **Dependency graph visualization UI** — the API (`/api/scan/{id}/dependency-graph`)
  returns real node/edge data; a rendered graph view (e.g. via d3/react-flow) in the
  frontend isn't wired up yet, though the data is there to build one directly on top of.
- Typosquat/license seed lists remain small and illustrative — swap in full registry
  mirrors for production use.

## Running it

**Backend**
```bash
cd backend
# System dependency for fuzzy hashing (Debian/Ubuntu):
sudo apt-get install -y libfuzzy-dev
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8822
```
Default login: `admin` / `admin123` (seeded on first startup). Requires `git` on PATH for
the repository scanner.

**Frontend**
```bash
cd frontend
npm install
npm run dev
```
`src/api.ts` points at `http://127.0.0.1:8822` — change `BASE_URL` if you deploy the
backend elsewhere.

## Full API surface

- `POST /api/auth/login`, `POST /api/auth/register`
- `GET /api/projects`
- `POST /api/scan/upload` — form fields `project_name`, `file`
- `POST /api/scan/repository` — form fields `project_name`, `repo_url`
- `GET /api/scan/{id}`, `GET /api/scans`
- `GET /api/scan/{id}/report?fmt=html|markdown|csv|pdf`
- `GET /api/scan/{id}/mitre`
- `GET /api/scan/{id}/dependency-graph`
- `WS /ws/scan/{id}/logs`
- `POST /api/schedule`, `GET /api/schedule`, `DELETE /api/schedule/{id}`
- `GET /api/dashboard/stats`, `GET /api/health`
