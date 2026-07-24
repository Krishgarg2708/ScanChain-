import io
import json
import zipfile
import datetime
import asyncio
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from apscheduler.schedulers.background import BackgroundScheduler

from . import database, auth, scan_logs
from .scanners import (dependency_scanner, secrets_scanner, binary_scanner, license_sbom,
                        static_analysis_scanner, container_scanner, malware_scanner,
                        repository_scanner, report_generator, mitre_mapping)

app = FastAPI(title="ScanChain — Supply Chain Security Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

database.init_db()

TEXT_EXTENSIONS = (".txt", ".json", ".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml",
                    ".toml", ".lock", ".mod", ".env", ".xml", ".java", ".go", ".rb", ".php")
MANIFEST_HINTS = ("requirements.txt", "package.json", "package-lock.json", "pipfile.lock",
                  "poetry.lock", "cargo.lock", "go.mod", "pom.xml")


scheduler = BackgroundScheduler()


def run_scheduled_repo_scan(scheduled_id: int):
    db = database.SessionLocal()
    try:
        sched = db.query(database.ScheduledScan).filter_by(id=scheduled_id).first()
        if not sched or not sched.enabled:
            return
        try:
            findings, meta = repository_scanner.scan_repository(sched.repo_url)
        except ValueError:
            return
        project = database.Project(name=sched.project_name, source_type="git-scheduled")
        db.add(project)
        db.commit()
        db.refresh(project)
        scan = database.Scan(project_id=project.id, status="running")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        risk = license_sbom.compute_risk_score(findings)
        for f in findings:
            db.add(database.Finding(scan_id=scan.id, **f))
        scan.status = "completed"
        scan.risk_score = risk["overall_score"]
        scan.completed_at = datetime.datetime.utcnow()
        scan.summary_json = json.dumps({"risk": risk, "repository_meta": meta, "package_count": 0, "binary_count": 0})
        sched.last_run_at = datetime.datetime.utcnow()
        db.commit()
    finally:
        db.close()


@app.on_event("startup")
def start_scheduler():
    scheduler.start()
    db = database.SessionLocal()
    try:
        for sched in db.query(database.ScheduledScan).filter_by(enabled=1).all():
            scheduler.add_job(run_scheduled_repo_scan, "interval", minutes=sched.interval_minutes,
                               args=[sched.id], id=f"sched-{sched.id}", replace_existing=True)
    finally:
        db.close()


@app.on_event("shutdown")
def stop_scheduler():
    scheduler.shutdown(wait=False)


@app.on_event("startup")
def seed_admin():
    db = database.SessionLocal()
    try:
        if not db.query(database.User).filter_by(username="admin").first():
            admin = database.User(
                username="admin",
                hashed_password=auth.hash_password("admin123"),
                role="admin",
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------- AUTH ----
@app.post("/api/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = db.query(database.User).filter_by(username=form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth.create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role}


@app.post("/api/auth/register")
def register(username: str = Form(...), password: str = Form(...), role: str = Form("developer"),
             db: Session = Depends(database.get_db)):
    if db.query(database.User).filter_by(username=username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if role not in auth.ROLE_HIERARCHY:
        role = "developer"
    user = database.User(username=username, hashed_password=auth.hash_password(password), role=role)
    db.add(user)
    db.commit()
    return {"status": "created", "username": username, "role": role}


# ------------------------------------------------------------- PROJECTS ----
@app.get("/api/projects")
def list_projects(db: Session = Depends(database.get_db), user=Depends(auth.get_current_user)):
    projects = db.query(database.Project).all()
    return [{"id": p.id, "name": p.name, "source_type": p.source_type,
             "created_at": p.created_at.isoformat(), "scan_count": len(p.scans)} for p in projects]


# ------------------------------------------------------------------ SCAN ----
@app.post("/api/scan/upload")
async def scan_upload(
    project_name: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(database.get_db),
    user=Depends(auth.require_role("developer")),
):
    """Accepts a .zip of a project (or a single manifest/binary file) and runs the full scanner pipeline."""
    raw = await file.read()
    text_files = {}
    binary_results = []
    all_files_bytes = {}  # for YARA malware scanning across every file, not just .exe/.dll

    if file.filename.lower().endswith(".zip"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive")
        for name in zf.namelist():
            if name.endswith("/"):
                continue
            data = zf.read(name)
            if len(data) < 5_000_000:  # cap per-file YARA scan size
                all_files_bytes[name] = data
            is_dockerfile = name.lower().split("/")[-1].startswith("dockerfile")
            if name.lower().endswith(TEXT_EXTENSIONS) or any(h in name.lower() for h in MANIFEST_HINTS) or is_dockerfile:
                try:
                    text_files[name] = data.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            elif name.lower().endswith((".exe", ".dll", ".so", ".bin", ".sys")):
                binary_results.append(binary_scanner.scan_binary(name, data))
    else:
        all_files_bytes[file.filename] = raw
        try:
            text_files[file.filename] = raw.decode("utf-8", errors="ignore")
        except Exception:
            binary_results.append(binary_scanner.scan_binary(file.filename, raw))

    project = database.Project(name=project_name, source_type="upload")
    db.add(project)
    db.commit()
    db.refresh(project)

    scan = database.Scan(project_id=project.id, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_logs.log(scan.id, f"Scan started for project '{project_name}'")
    scan_logs.log(scan.id, f"Extracted {len(text_files)} text/manifest files, "
                            f"{len(binary_results)} binaries, {len(all_files_bytes)} total files")

    all_findings = []

    scan_logs.log(scan.id, "Running dependency scanner (OSV.dev)...")
    dep_findings, packages = dependency_scanner.scan_dependencies(text_files)
    all_findings.extend(dep_findings)
    scan_logs.log(scan.id, f"Dependency scan complete — {len(packages)} packages, {len(dep_findings)} findings")

    scan_logs.log(scan.id, "Running secrets scanner...")
    secret_findings = secrets_scanner.scan_secrets(text_files)
    all_findings.extend(secret_findings)
    scan_logs.log(scan.id, f"Secrets scan complete — {len(secret_findings)} findings")

    scan_logs.log(scan.id, "Running license scanner...")
    lic_findings, license_summary = license_sbom.scan_licenses(packages)
    all_findings.extend(lic_findings)
    scan_logs.log(scan.id, f"License scan complete — {len(lic_findings)} findings")

    scan_logs.log(scan.id, "Running binary scanner (hashes, entropy, PE metadata)...")
    for br in binary_results:
        all_findings.extend(br["findings"])
    scan_logs.log(scan.id, f"Binary scan complete — {len(binary_results)} binaries analyzed")

    scan_logs.log(scan.id, "Running static analysis (Semgrep + Bandit)...")
    static_findings, static_errors = static_analysis_scanner.scan_static_analysis(text_files)
    all_findings.extend(static_findings)
    scan_logs.log(scan.id, f"Static analysis complete — {len(static_findings)} findings")

    scan_logs.log(scan.id, "Running container/Dockerfile scanner...")
    container_findings = container_scanner.scan_container(text_files)
    all_findings.extend(container_findings)
    scan_logs.log(scan.id, f"Container scan complete — {len(container_findings)} findings")

    scan_logs.log(scan.id, "Running malware scanner (YARA)...")
    malware_findings = malware_scanner.scan_files_for_malware(all_files_bytes)
    all_findings.extend(malware_findings)
    scan_logs.log(scan.id, f"Malware scan complete — {len(malware_findings)} findings")

    risk = license_sbom.compute_risk_score(all_findings)
    sbom = license_sbom.generate_sbom(project_name, packages, license_summary)
    scan_logs.log(scan.id, f"Risk engine computed overall score: {risk['overall_score']}/100")

    for f in all_findings:
        db.add(database.Finding(scan_id=scan.id, **f))

    attack_summary = mitre_mapping.build_attack_summary(all_findings)

    scan.status = "completed"
    scan.risk_score = risk["overall_score"]
    scan.completed_at = datetime.datetime.utcnow()
    scan.summary_json = json.dumps({
        "risk": risk,
        "package_count": len(packages),
        "binary_count": len(binary_results),
        "sbom": sbom,
        "binary_details": [{"hashes": b["hashes"], "entropy": b["entropy"]} for b in binary_results],
        "static_analysis_errors": static_errors,
        "attack_summary": attack_summary,
        "packages": packages,
    })
    db.commit()
    scan_logs.log(scan.id, f"Scan completed — {len(all_findings)} total findings")
    scan_logs.mark_done(scan.id)

    return {
        "scan_id": scan.id,
        "project_id": project.id,
        "risk": risk,
        "findings": all_findings,
        "package_count": len(packages),
        "sbom_preview": sbom,
    }


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(database.get_db), user=Depends(auth.get_current_user)):
    scan = db.query(database.Scan).filter_by(id=scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.query(database.Finding).filter_by(scan_id=scan_id).all()
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "created_at": scan.created_at.isoformat(),
        "summary": json.loads(scan.summary_json),
        "findings": [
            {"id": f.id, "scanner": f.scanner, "severity": f.severity, "title": f.title,
             "description": f.description, "location": f.location, "cve_id": f.cve_id,
             "cvss": f.cvss, "remediation": f.remediation}
            for f in findings
        ],
    }


@app.get("/api/scans")
def list_scans(db: Session = Depends(database.get_db), user=Depends(auth.get_current_user)):
    scans = db.query(database.Scan).order_by(database.Scan.created_at.desc()).all()
    return [{"id": s.id, "project_id": s.project_id, "status": s.status,
             "risk_score": s.risk_score, "created_at": s.created_at.isoformat()} for s in scans]


@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(database.get_db), user=Depends(auth.get_current_user)):
    scans = db.query(database.Scan).all()
    findings = db.query(database.Finding).all()
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    avg_risk = round(sum(s.risk_score for s in scans) / len(scans), 1) if scans else 0
    return {
        "total_scans": len(scans),
        "total_findings": len(findings),
        "severity_counts": sev_counts,
        "average_risk_score": avg_risk,
        "recent_scans": [{"id": s.id, "risk_score": s.risk_score, "status": s.status,
                           "created_at": s.created_at.isoformat()} for s in
                          sorted(scans, key=lambda x: x.created_at, reverse=True)[:10]],
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ------------------------------------------------------- REPOSITORY SCAN ----
@app.post("/api/scan/repository")
def scan_repository_endpoint(
    repo_url: str = Form(...),
    project_name: str = Form(...),
    db: Session = Depends(database.get_db),
    user=Depends(auth.require_role("developer")),
):
    """Clones a public git repository and scans its recent commit history for leaked secrets."""
    try:
        findings, meta = repository_scanner.scan_repository(repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    project = database.Project(name=project_name, source_type="git")
    db.add(project)
    db.commit()
    db.refresh(project)

    scan = database.Scan(project_id=project.id, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    risk = license_sbom.compute_risk_score(findings)
    for f in findings:
        db.add(database.Finding(scan_id=scan.id, **f))

    scan.status = "completed"
    scan.risk_score = risk["overall_score"]
    scan.completed_at = datetime.datetime.utcnow()
    scan.summary_json = json.dumps({"risk": risk, "repository_meta": meta, "package_count": 0, "binary_count": 0})
    db.commit()

    return {"scan_id": scan.id, "project_id": project.id, "risk": risk, "findings": findings, "meta": meta}


# ----------------------------------------------------------- REPORT EXPORT ----
@app.get("/api/scan/{scan_id}/report")
def export_report(scan_id: int, fmt: str = "html", db: Session = Depends(database.get_db),
                   user=Depends(auth.get_current_user)):
    scan_row = db.query(database.Scan).filter_by(id=scan_id).first()
    if not scan_row:
        raise HTTPException(status_code=404, detail="Scan not found")
    project = db.query(database.Project).filter_by(id=scan_row.project_id).first()
    findings = db.query(database.Finding).filter_by(scan_id=scan_id).all()
    scan_dict = {
        "id": scan_row.id,
        "risk_score": scan_row.risk_score,
        "summary": json.loads(scan_row.summary_json),
        "findings": [
            {"scanner": f.scanner, "severity": f.severity, "title": f.title, "description": f.description,
             "location": f.location, "cve_id": f.cve_id, "cvss": f.cvss, "remediation": f.remediation}
            for f in findings
        ],
    }
    project_name = project.name if project else f"scan-{scan_id}"

    if fmt == "markdown":
        content = report_generator.generate_markdown(project_name, scan_dict)
        return Response(content=content, media_type="text/markdown",
                         headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.md"'})
    if fmt == "csv":
        content = report_generator.generate_csv(scan_dict)
        return Response(content=content, media_type="text/csv",
                         headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.csv"'})
    if fmt == "pdf":
        content = report_generator.generate_pdf(project_name, scan_dict)
        return Response(content=content, media_type="application/pdf",
                         headers={"Content-Disposition": f'attachment; filename="report-{scan_id}.pdf"'})
    # default html
    content = report_generator.generate_html(project_name, scan_dict)
    return Response(content=content, media_type="text/html")


# ------------------------------------------------------ LIVE SCAN LOGS ----
@app.websocket("/ws/scan/{scan_id}/logs")
async def scan_log_stream(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    # Replay anything already buffered (covers the case where the scan finished
    # before the client connected, or connected mid-scan).
    for entry in scan_logs.get_buffer(scan_id):
        await websocket.send_json(entry)
        if entry["message"] == "__DONE__":
            await websocket.close()
            return

    queue = scan_logs.subscribe(scan_id)
    try:
        while True:
            entry = await asyncio.wait_for(queue.get(), timeout=120)
            await websocket.send_json(entry)
            if entry["message"] == "__DONE__":
                break
    except (asyncio.TimeoutError, WebSocketDisconnect):
        pass
    finally:
        scan_logs.unsubscribe(scan_id, queue)
        try:
            await websocket.close()
        except RuntimeError:
            pass


# -------------------------------------------------------- MITRE ATT&CK ----
@app.get("/api/scan/{scan_id}/mitre")
def get_mitre_mapping(scan_id: int, db: Session = Depends(database.get_db), user=Depends(auth.get_current_user)):
    findings = db.query(database.Finding).filter_by(scan_id=scan_id).all()
    finding_dicts = [{"title": f.title, "description": f.description, "scanner": f.scanner,
                       "cve_id": f.cve_id} for f in findings]
    return mitre_mapping.build_attack_summary(finding_dicts)


# ---------------------------------------------------- DEPENDENCY GRAPH ----
@app.get("/api/scan/{scan_id}/dependency-graph")
def dependency_graph(scan_id: int, db: Session = Depends(database.get_db), user=Depends(auth.get_current_user)):
    """Bipartite graph: project -> packages -> CVEs affecting them, for visualization."""
    scan_row = db.query(database.Scan).filter_by(id=scan_id).first()
    if not scan_row:
        raise HTTPException(status_code=404, detail="Scan not found")
    project = db.query(database.Project).filter_by(id=scan_row.project_id).first()
    summary = json.loads(scan_row.summary_json)
    packages = summary.get("packages", [])
    findings = db.query(database.Finding).filter_by(scan_id=scan_id).all()

    nodes = [{"id": "root", "label": project.name if project else "project", "type": "project"}]
    edges = []
    pkg_vuln_count = {}
    for f in findings:
        if f.cve_id and f.location:
            pkg_vuln_count.setdefault(f.location, []).append(f.cve_id)

    for pkg in packages:
        pkg_id = f"pkg:{pkg['name']}"
        vulns = pkg_vuln_count.get(pkg["name"], [])
        nodes.append({
            "id": pkg_id, "label": pkg["name"], "type": "package",
            "version": pkg.get("version"), "ecosystem": pkg.get("ecosystem"),
            "vulnerable": len(vulns) > 0,
        })
        edges.append({"source": "root", "target": pkg_id})
        for cve in vulns:
            cve_id = f"cve:{cve}:{pkg['name']}"
            nodes.append({"id": cve_id, "label": cve, "type": "vulnerability"})
            edges.append({"source": pkg_id, "target": cve_id})

    return {"nodes": nodes, "edges": edges}


# ------------------------------------------------------- SCAN SCHEDULING ----
@app.post("/api/schedule")
def create_schedule(
    project_name: str = Form(...),
    repo_url: str = Form(...),
    interval_minutes: int = Form(1440),
    db: Session = Depends(database.get_db),
    user=Depends(auth.require_role("analyst")),
):
    sched = database.ScheduledScan(project_name=project_name, repo_url=repo_url,
                                    interval_minutes=max(interval_minutes, 5), enabled=1)
    db.add(sched)
    db.commit()
    db.refresh(sched)
    scheduler.add_job(run_scheduled_repo_scan, "interval", minutes=sched.interval_minutes,
                       args=[sched.id], id=f"sched-{sched.id}", replace_existing=True)
    return {"id": sched.id, "status": "scheduled", "interval_minutes": sched.interval_minutes}


@app.get("/api/schedule")
def list_schedules(db: Session = Depends(database.get_db), user=Depends(auth.get_current_user)):
    scheds = db.query(database.ScheduledScan).all()
    return [{
        "id": s.id, "project_name": s.project_name, "repo_url": s.repo_url,
        "interval_minutes": s.interval_minutes, "enabled": bool(s.enabled),
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "created_at": s.created_at.isoformat(),
    } for s in scheds]


@app.delete("/api/schedule/{schedule_id}")
def delete_schedule(schedule_id: int, db: Session = Depends(database.get_db),
                     user=Depends(auth.require_role("analyst"))):
    sched = db.query(database.ScheduledScan).filter_by(id=schedule_id).first()
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    try:
        scheduler.remove_job(f"sched-{schedule_id}")
    except Exception:
        pass
    db.delete(sched)
    db.commit()
    return {"status": "deleted"}
