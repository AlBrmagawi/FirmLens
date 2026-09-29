"""Authenticated, versioned API. This process has no container-runtime access."""

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from firmwarelens.ai import ask
from firmwarelens.comparison import compare
from firmwarelens.config import settings
from firmwarelens.database import (
    Artifact,
    Audit,
    BrowserSession,
    Conversation,
    Event,
    Heartbeat,
    Project,
    ProjectArtifact,
    Scan,
    Triage,
    db_session,
    session,
)
from firmwarelens.redaction import clean, redact
from firmwarelens.reports import report
from firmwarelens.schemas import (
    AIQuestion,
    AnalysisResult,
    ProjectCreate,
    ScanCreate,
    TriageUpdate,
    now,
)

TERMINAL = {"complete", "partial", "unsupported", "failed", "cancelled"}


def token_path() -> Path:
    return settings().data_dir / "admin-token"


def access_token() -> str:
    return token_path().read_text().strip()


@asynccontextmanager
async def lifespan(app: FastAPI):
    root = settings().data_dir
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ("artifacts", "uploads"):
        (root / name).mkdir(exist_ok=True, mode=0o700)
    try:
        fd = os.open(token_path(), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_urlsafe(32))
    except FileExistsError:
        pass
    with session() as db:
        for item in db.scalars(select(Conversation).where(Conversation.state == "running")):
            item.state = "interrupted"
        db.execute(delete(BrowserSession).where(BrowserSession.expires < time.time()))
        db.commit()
    # Incomplete upload temporaries are never artifacts; reap only aged files on restart.
    for path in (root / "uploads").glob("*.part"):
        if path.is_file() and time.time() - path.stat().st_mtime > 3600:
            path.unlink()
    yield


app = FastAPI(
    title="FirmwareLens",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=list(
        {
            "localhost",
            "127.0.0.1",
            "api",
            "testserver",
            urlparse(settings().origin).hostname or "localhost",
        }
    ),
)


@app.get("/api/docs", include_in_schema=False, response_class=HTMLResponse)
def api_documentation():
    """Locally bundled Swagger: works offline without weakening application CSP."""
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>FirmwareLens API</title><link rel="stylesheet" href="/vendor/swagger/swagger-ui.css">
    </head><body><div id="swagger-ui"></div>
    <script src="/vendor/swagger/swagger-ui-bundle.js"></script>
    <script src="/swagger-init.js"></script></body></html>"""


@app.middleware("http")
async def boundaries(request: Request, call_next):
    request_id = str(uuid.uuid4())
    origin = request.headers.get("origin")
    if request.method not in ("GET", "HEAD", "OPTIONS") and origin and origin != settings().origin:
        return JSONResponse(
            {
                "error": {
                    "code": "origin",
                    "message": "Request origin is not permitted",
                    "request_id": request_id,
                }
            },
            status_code=403,
        )
    started = time.monotonic()
    response = await call_next(request)
    response.headers.update(
        {
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        }
    )
    print(
        json.dumps(
            {
                "event": "request",
                "request_id": request_id,
                "method": request.method,
                "status": response.status_code,
                "duration_ms": round((time.monotonic() - started) * 1000),
            }
        ),
        flush=True,
    )
    return response


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse(
        {"error": {"code": str(exc.status_code), "message": redact(str(exc.detail))}},
        status_code=exc.status_code,
    )


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    return JSONResponse(
        {
            "error": {
                "code": "validation",
                "message": "Request validation failed",
                "fields": [{"location": list(e["loc"]), "message": e["msg"]} for e in exc.errors()],
            }
        },
        status_code=422,
    )


@app.exception_handler(Exception)
async def internal_error(request: Request, exc: Exception):
    print(json.dumps({"event": "api_error", "type": type(exc).__name__}), flush=True)
    return JSONResponse(
        {
            "error": {
                "code": "internal",
                "message": "Internal operation failed; inspect local diagnostics",
            }
        },
        status_code=500,
    )


def csrf(token: str) -> str:
    return hashlib.sha256((token + ":firmwarelens-csrf").encode()).hexdigest()


def authenticated(request: Request, db: Session = Depends(db_session)) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Bearer ") and hmac.compare_digest(
        authorization[7:], access_token()
    ):
        return "local-owner"
    token = request.cookies.get("fl_session", "")
    active = db.get(BrowserSession, hashlib.sha256(token.encode()).hexdigest()) if token else None
    if active is None or active.expires < time.time():
        raise HTTPException(401, "Sign in with the locally generated access token")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("origin") != settings().origin or not hmac.compare_digest(
            request.headers.get("x-csrf-token", ""), csrf(token)
        ):
            raise HTTPException(403, "CSRF verification failed")
    return "local-owner"


class Login(BaseModel):
    token: str = Field(min_length=1, max_length=200)


attempts: dict[str, deque] = defaultdict(deque)


@app.post("/api/v1/auth/login")
def login(payload: Login, request: Request, response: Response, db: Session = Depends(db_session)):
    key = request.client.host if request.client else "local"
    recent = attempts[key]
    while recent and recent[0] < time.time() - 60:
        recent.popleft()
    if len(recent) >= 10:
        raise HTTPException(429, "Too many sign-in attempts; wait one minute")
    recent.append(time.time())
    if not hmac.compare_digest(payload.token, access_token()):
        raise HTTPException(401, "Invalid local access token")
    token = secrets.token_urlsafe(32)
    db.add(
        BrowserSession(
            token_hash=hashlib.sha256(token.encode()).hexdigest(), expires=time.time() + 43200
        )
    )
    db.commit()
    response.set_cookie(
        "fl_session",
        token,
        httponly=True,
        secure=settings().secure_cookie,
        samesite="strict",
        max_age=43200,
    )
    return {"authenticated": True, "csrf": csrf(token)}


router = APIRouter(prefix="/api/v1", dependencies=[Depends(authenticated)])


@router.get("/auth/session")
def whoami(request: Request):
    return {"authenticated": True, "csrf": csrf(request.cookies.get("fl_session", ""))}


@router.post("/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(db_session)):
    db.execute(
        delete(BrowserSession).where(
            BrowserSession.token_hash
            == hashlib.sha256(request.cookies.get("fl_session", "").encode()).hexdigest()
        )
    )
    db.commit()
    response.delete_cookie("fl_session")
    return {"authenticated": False}


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/ready")
def ready(db: Session = Depends(db_session)):
    db.execute(text("SELECT 1"))
    worker = db.get(Heartbeat, "supervisor")
    if worker is None or time.time() - worker.at > 90 or not worker.details.get("ready"):
        raise HTTPException(
            503,
            "Database available; analysis supervisor or required sandbox capabilities unavailable",
        )
    return {"status": "ready"}


def project_for(db: Session, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found")
    return project


def scan_for(db: Session, project_id: str, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.project_id != project_id:
        raise HTTPException(404, "Scan not found in selected project")
    return scan


def result_for(scan: Scan) -> AnalysisResult:
    if scan.result is None:
        raise HTTPException(
            409, "Analysis result is not available; inspect job state and diagnostics"
        )
    return AnalysisResult.model_validate(scan.result)


def scan_view(scan: Scan) -> dict:
    result = scan.result or {}
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "artifact_id": scan.artifact_id,
        "label": scan.label,
        "status": scan.status,
        "created_at": scan.created_at,
        "finished_at": scan.finished_at,
        "attempts": scan.attempts,
        "cancel_requested": scan.cancel_requested,
        "error": scan.error,
        "options": scan.options,
        "summary": {
            "files": len(result.get("files", [])),
            "components": len(result.get("components", [])),
            "findings": len(result.get("findings", [])),
            "severity": {
                s: sum(f["severity"] == s for f in result.get("findings", []))
                for s in ("critical", "high", "medium", "low", "info")
            },
        },
        "stages": result.get("stages", []),
        "manifest": result.get("manifest", {}),
        "limitations": result.get("limitations", []),
        "format": result.get("format"),
        "payloads": result.get("payloads", []),
    }


def page(items: list, offset: int, limit: int) -> dict:
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "offset": offset,
        "limit": limit,
    }


@router.get("/projects")
def projects(db: Session = Depends(db_session)):
    return [
        {"id": p.id, "name": p.name, "description": p.description, "created_at": p.created_at}
        for p in db.scalars(select(Project).order_by(Project.created_at.desc()).limit(1000))
    ]


@router.post("/projects", status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(db_session)):
    project = Project(name=redact(payload.name), description=redact(payload.description))
    db.add(project)
    db.commit()
    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "created_at": project.created_at,
    }


@router.post("/projects/{project_id}/artifacts", status_code=201)
async def upload(
    project_id: str,
    request: Request,
    x_filename: str = Header(default="firmware"),
    db: Session = Depends(db_session),
):
    project_for(db, project_id)
    config = settings()
    temp = config.data_dir / "uploads" / f"{uuid.uuid4()}.part"
    digest = hashlib.sha256()
    size = 0
    try:
        with temp.open("xb") as stream:
            os.chmod(temp, 0o600)
            async for chunk in request.stream():
                size += len(chunk)
                if size > config.upload_limit:
                    raise HTTPException(
                        413, f"Firmware exceeds {config.upload_limit} byte upload limit"
                    )
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if size == 0:
            raise HTTPException(422, "Firmware is empty")
        sha = digest.hexdigest()
        supplied = request.headers.get("x-content-sha256")
        if supplied and not hmac.compare_digest(supplied, sha):
            raise HTTPException(422, "Upload SHA-256 did not match")
        directory = config.data_dir / "artifacts" / sha
        directory.mkdir(mode=0o755, exist_ok=True)
        destination = directory / "firmware"
        try:
            os.link(temp, destination)
            destination.chmod(0o444)
        except FileExistsError:
            with destination.open("rb") as existing:
                if hashlib.file_digest(existing, "sha256").hexdigest() != sha:
                    raise HTTPException(500, "Stored artifact failed integrity check") from None
        duplicate = db.get(Artifact, sha) is not None
        if not duplicate:
            db.add(Artifact(id=sha, size=size))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                duplicate = True
        if db.get(ProjectArtifact, (project_id, sha)) is None:
            db.add(
                ProjectArtifact(
                    project_id=project_id,
                    artifact_id=sha,
                    filename=redact(Path(x_filename).name[:255]),
                )
            )
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
        return {"id": sha, "sha256": sha, "size": size, "duplicate": duplicate}
    finally:
        temp.unlink(missing_ok=True)


@router.get("/projects/{project_id}/artifacts")
def artifacts(project_id: str, db: Session = Depends(db_session)):
    project_for(db, project_id)
    return [
        {"id": a.id, "size": a.size, "filename": pa.filename, "created_at": a.created_at}
        for a, pa in db.execute(
            select(Artifact, ProjectArtifact)
            .join(ProjectArtifact)
            .where(ProjectArtifact.project_id == project_id)
        )
    ]


@router.get("/projects/{project_id}/artifacts/{artifact_id}/download")
def download_artifact(project_id: str, artifact_id: str, db: Session = Depends(db_session)):
    if db.get(ProjectArtifact, (project_id, artifact_id)) is None:
        raise HTTPException(404, "Artifact not found in project")
    return FileResponse(
        settings().data_dir / "artifacts" / artifact_id / "firmware",
        media_type="application/octet-stream",
        filename=f"{artifact_id}.firmware",
    )


@router.post("/projects/{project_id}/scans", status_code=201)
def create_scan(
    project_id: str,
    payload: ScanCreate,
    idempotency_key: str | None = Header(default=None, max_length=100),
    db: Session = Depends(db_session),
):
    if db.get(ProjectArtifact, (project_id, payload.artifact_id)) is None:
        raise HTTPException(404, "Artifact not found in project")
    if idempotency_key:
        existing = db.scalar(
            select(Scan).where(
                Scan.project_id == project_id, Scan.idempotency_key == idempotency_key
            )
        )
        if existing:
            if (
                existing.artifact_id != payload.artifact_id
                or existing.options != payload.options.model_dump()
                or existing.label != redact(payload.label)
            ):
                raise HTTPException(
                    409, "Idempotency key already used with different scan parameters"
                )
            return scan_view(existing)
    scan = Scan(
        project_id=project_id,
        artifact_id=payload.artifact_id,
        label=redact(payload.label),
        options=payload.options.model_dump(),
        idempotency_key=idempotency_key,
    )
    db.add(scan)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return create_scan(project_id, payload, idempotency_key, db)
    db.add(
        Event(
            scan_id=scan.id,
            stage="queued",
            message="Immutable artifact queued for isolated analysis",
        )
    )
    db.commit()
    return scan_view(scan)


@router.get("/projects/{project_id}/scans")
def scans(
    project_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(db_session),
):
    project_for(db, project_id)
    total = db.scalar(select(func.count()).select_from(Scan).where(Scan.project_id == project_id))
    return {
        "items": [
            scan_view(s)
            for s in db.scalars(
                select(Scan)
                .where(Scan.project_id == project_id)
                .order_by(Scan.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
        ],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


@router.get("/projects/{project_id}/scans/{scan_id}")
def scan_detail(project_id: str, scan_id: str, db: Session = Depends(db_session)):
    return scan_view(scan_for(db, project_id, scan_id))


@router.get("/projects/{project_id}/scans/{scan_id}/events")
def events(
    project_id: str, scan_id: str, after: int = Query(0, ge=0), db: Session = Depends(db_session)
):
    scan_for(db, project_id, scan_id)
    return [
        {"id": e.id, "stage": e.stage, "message": e.message, "at": e.at}
        for e in db.scalars(
            select(Event)
            .where(Event.scan_id == scan_id, Event.id > after)
            .order_by(Event.id)
            .limit(500)
        )
    ]


@router.post("/projects/{project_id}/scans/{scan_id}/cancel")
def cancel(project_id: str, scan_id: str, db: Session = Depends(db_session)):
    scan = scan_for(db, project_id, scan_id)
    if scan.status not in TERMINAL:
        scan.cancel_requested = True
        if scan.status == "queued":
            scan.status = "cancelled"
            scan.finished_at = now()
        db.commit()
    return scan_view(scan)


def triage_view(item: Triage | None) -> dict:
    if item is None:
        return {"status": "open", "note": "", "suppressed": False}
    active = item.suppress and (item.expires_at is None or item.expires_at > now())
    return {
        "status": item.status,
        "note": item.note,
        "suppressed": active,
        "suppress": item.suppress,
        "reason": item.reason,
        "expires_at": item.expires_at,
        "updated_at": item.updated_at,
    }


@router.get("/projects/{project_id}/scans/{scan_id}/findings")
def findings(
    project_id: str,
    scan_id: str,
    q: str = Query("", max_length=200),
    severity: str = "",
    status: str = "",
    sort: str = "priority",
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(db_session),
):
    result = result_for(scan_for(db, project_id, scan_id))
    triage = {
        t.fingerprint: t for t in db.scalars(select(Triage).where(Triage.project_id == project_id))
    }
    scores = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    items = []
    for finding in result.findings:
        item = {**finding.model_dump(), "triage": triage_view(triage.get(finding.fingerprint))}
        item["priority"] = (
            scores[finding.severity] * 10 + {"high": 3, "medium": 2, "low": 1}[finding.confidence]
        )
        if (
            q.lower() not in (finding.title + " " + finding.path + " " + finding.rule_id).lower()
            or severity
            and finding.severity != severity
            or status
            and item["triage"]["status"] != status
        ):
            continue
        items.append(item)
    items.sort(
        key=lambda f: (
            (-f["priority"], f["id"])
            if sort == "priority"
            else (
                str(f.get(sort if sort in ("title", "path", "confidence") else "title", "")),
                f["id"],
            )
        )
    )
    return page(items, offset, limit)


@router.get("/projects/{project_id}/scans/{scan_id}/findings/{finding_id}")
def finding_detail(
    project_id: str, scan_id: str, finding_id: str, db: Session = Depends(db_session)
):
    result = result_for(scan_for(db, project_id, scan_id))
    finding = next((f for f in result.findings if f.id == finding_id), None)
    if finding is None:
        raise HTTPException(404, "Finding not found in selected scan")
    history = [
        {"at": a.at, "change": a.change}
        for a in db.scalars(
            select(Audit)
            .where(Audit.project_id == project_id, Audit.fingerprint == finding.fingerprint)
            .order_by(Audit.id)
        )
    ]
    return {
        **finding.model_dump(),
        "evidence": [e.model_dump() for e in result.evidence if e.id in finding.evidence_ids],
        "triage": triage_view(db.get(Triage, (project_id, finding.fingerprint))),
        "history": history,
    }


@router.patch("/projects/{project_id}/scans/{scan_id}/findings/{finding_id}")
def triage_finding(
    project_id: str,
    scan_id: str,
    finding_id: str,
    payload: TriageUpdate,
    db: Session = Depends(db_session),
):
    finding = finding_detail(project_id, scan_id, finding_id, db)
    if payload.suppress and not payload.reason.strip():
        raise HTTPException(422, "A scoped suppression requires a reason")
    expires = (
        payload.expires_at.astimezone(UTC).isoformat()
        if payload.expires_at and payload.expires_at.tzinfo
        else None
    )
    if payload.expires_at and not payload.expires_at.tzinfo:
        raise HTTPException(422, "Suppression expiry requires an explicit timezone")
    item = db.get(Triage, (project_id, finding["fingerprint"])) or Triage(
        project_id=project_id, fingerprint=finding["fingerprint"]
    )
    changes = clean(payload.model_dump(mode="json"))
    item.status, item.note, item.suppress, item.reason, item.expires_at, item.updated_at = (
        payload.status,
        redact(payload.note),
        payload.suppress,
        redact(payload.reason),
        expires,
        now(),
    )
    db.add(item)
    db.add(Audit(project_id=project_id, fingerprint=finding["fingerprint"], change=changes))
    db.commit()
    return triage_view(item)


@router.get("/projects/{project_id}/scans/{scan_id}/components")
def components(
    project_id: str,
    scan_id: str,
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(db_session),
):
    result = result_for(scan_for(db, project_id, scan_id))
    return page(
        [
            c.model_dump()
            for c in result.components
            if q.lower() in (c.name + " " + c.version + " " + c.ecosystem).lower()
        ],
        offset,
        limit,
    )


@router.get("/projects/{project_id}/scans/{scan_id}/evidence/{evidence_id}")
def evidence(project_id: str, scan_id: str, evidence_id: str, db: Session = Depends(db_session)):
    result = result_for(scan_for(db, project_id, scan_id))
    entry = next((e for e in result.evidence if e.id == evidence_id), None)
    if entry is None:
        raise HTTPException(404, "Evidence not found in selected scan")
    return entry


@router.get("/projects/{project_id}/scans/{scan_id}/files")
def files(
    project_id: str,
    scan_id: str,
    q: str = Query("", max_length=200),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(db_session),
):
    result = result_for(scan_for(db, project_id, scan_id))
    return page(
        [
            f.model_dump(exclude={"preview", "elf"})
            for f in result.files
            if q.lower() in f.path.lower()
        ],
        offset,
        limit,
    )


@router.get("/projects/{project_id}/scans/{scan_id}/file")
def preview(
    project_id: str,
    scan_id: str,
    path: str = Query(max_length=1024),
    db: Session = Depends(db_session),
):
    result = result_for(scan_for(db, project_id, scan_id))
    file = next((f for f in result.files if f.path == path), None)
    if file is None:
        raise HTTPException(404, "File not in scan inventory")
    return file


@router.get("/projects/{project_id}/compare")
def comparison(project_id: str, before: str, after: str, db: Session = Depends(db_session)):
    old = scan_for(db, project_id, before)
    new = scan_for(db, project_id, after)
    return {"before": before, "after": after, **compare(result_for(old), result_for(new))}


@router.get("/projects/{project_id}/compare/export")
def comparison_export(
    project_id: str,
    before: str,
    after: str,
    format: str = "html",
    db: Session = Depends(db_session),
):
    if format not in ("html", "markdown", "json"):
        raise HTTPException(422, "Comparison supports HTML, Markdown or JSON")
    body, media = report(
        {
            "project": project_for(db, project_id).name,
            "comparison": comparison(project_id, before, after, db),
        },
        format,
    )
    return Response(
        body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="firmwarelens-comparison.{"md" if format == "markdown" else format}"'
        },
    )


@router.get("/projects/{project_id}/scans/{scan_id}/report")
def export(project_id: str, scan_id: str, format: str = "html", db: Session = Depends(db_session)):
    scan = scan_for(db, project_id, scan_id)
    result = result_for(scan)
    try:
        body, media = report(
            {
                "id": scan.id,
                "project": project_for(db, project_id).name,
                "status": scan.status,
                "result": result.model_dump(),
                "triage": [
                    {"fingerprint": t.fingerprint, **triage_view(t)}
                    for t in db.scalars(select(Triage).where(Triage.project_id == project_id))
                ],
            },
            format,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    extension = {"markdown": "md", "sbom": "cdx.json", "sarif": "sarif.json"}.get(format, format)
    return Response(
        body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="firmwarelens-{scan.id}.{extension}"'
        },
    )


@router.get("/settings")
def diagnostics(db: Session = Depends(db_session)):
    config = settings()
    db.execute(text("SELECT 1"))
    worker = db.get(Heartbeat, "supervisor")
    return {
        "database": "available",
        "supervisor": {
            "last_seen": worker.at if worker else None,
            "alive": bool(worker and time.time() - worker.at < 90),
            "sandbox": worker.details if worker else {},
        },
        "limits": {
            "upload_bytes": config.upload_limit,
            "job_timeout_seconds": config.job_timeout,
            "max_attempts": config.max_attempts,
        },
        "ai": {
            "provider": config.ai_provider,
            "model": config.ai_model,
            "cloud_enabled": config.cloud_ai_enabled,
            "key_configured": bool(config.openai_api_key),
            "daily_requests": config.ai_daily_requests,
            "context_chars": config.ai_context_chars,
            "disclosure": "When explicitly enabled, cloud AI receives your redacted question, bounded redacted finding/evidence/component records, coverage, and selected comparison data. Raw firmware is never sent. No automatic model downloads.",
        },
    }


@router.get("/projects/{project_id}/scans/{scan_id}/conversations")
def conversations(project_id: str, scan_id: str, db: Session = Depends(db_session)):
    scan_for(db, project_id, scan_id)
    return [
        {
            "id": c.id,
            "question": c.question,
            "answer": c.answer,
            "state": c.state,
            "provider": c.provider,
            "model": c.model,
            "at": c.at,
        }
        for c in db.scalars(
            select(Conversation)
            .where(Conversation.project_id == project_id, Conversation.scan_id == scan_id)
            .order_by(Conversation.at.desc())
            .limit(100)
        )
    ]


@router.post("/projects/{project_id}/scans/{scan_id}/assistant")
async def assistant(
    project_id: str,
    scan_id: str,
    payload: AIQuestion,
    request: Request,
    db: Session = Depends(db_session),
):
    result = result_for(scan_for(db, project_id, scan_id))
    config = settings()
    if config.ai_provider == "disabled":
        raise HTTPException(
            409,
            "AI disabled. Configure FL_AI_PROVIDER and FL_AI_MODEL in .env; cloud AI requires explicit enablement.",
        )
    comparison_data = (
        comparison(project_id, payload.compare_scan_id, scan_id, db)
        if payload.compare_scan_id
        else None
    )
    # Serialize usage reservations across projects for the single local owner.
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(78219411)"))
    count = (
        db.scalar(
            select(func.count())
            .select_from(Conversation)
            .where(Conversation.at >= datetime.now(UTC).date().isoformat())
        )
        or 0
    )
    if count >= config.ai_daily_requests:
        raise HTTPException(
            429, "Daily AI request limit reached; adjust server configuration if needed"
        )
    record = Conversation(
        project_id=project_id,
        scan_id=scan_id,
        question=redact(payload.question),
        provider=config.ai_provider,
        model=config.ai_model,
    )
    db.add(record)
    db.commit()
    task = asyncio.create_task(ask(config, payload, result, comparison_data))
    try:
        while not task.done():
            if await request.is_disconnected():
                task.cancel()
                record.state = "cancelled"
                db.commit()
                raise HTTPException(499, "AI request cancelled")
            await asyncio.sleep(0.2)
        answer = await task
        record.answer, record.state = answer, "complete"
        db.commit()
        return {"id": record.id, **answer}
    except HTTPException:
        raise
    except Exception as exc:
        record.state = "failed"
        db.commit()
        message = (
            str(exc)[:300]
            if isinstance(exc, ValueError)
            else f"AI provider request failed ({type(exc).__name__}); check local provider settings, availability and timeout"
        )
        raise HTTPException(502, message) from exc
    finally:
        if not task.done():
            task.cancel()


@router.delete("/projects/{project_id}/scans/{scan_id}")
def delete_scan(project_id: str, scan_id: str, db: Session = Depends(db_session)):
    scan = scan_for(db, project_id, scan_id)
    if scan.status not in TERMINAL:
        raise HTTPException(409, "Cancel active analysis before deletion")
    db.execute(delete(Event).where(Event.scan_id == scan_id))
    db.execute(delete(Conversation).where(Conversation.scan_id == scan_id))
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}


@router.delete("/projects/{project_id}")
def delete_project(project_id: str, db: Session = Depends(db_session)):
    project = project_for(db, project_id)
    scans = list(db.scalars(select(Scan).where(Scan.project_id == project_id)))
    if any(s.status not in TERMINAL for s in scans):
        raise HTTPException(409, "Cancel active analyses before deleting project")
    ids = [s.id for s in scans]
    db.execute(delete(Event).where(Event.scan_id.in_(ids)))
    for model in (Conversation, Audit, Triage, Scan, ProjectArtifact):
        db.execute(delete(model).where(model.project_id == project_id))
    db.delete(project)
    db.commit()
    return {
        "deleted": project_id,
        "note": "Unreferenced immutable artifacts can be removed with firmwarelens retention gc",
    }


app.include_router(router)
frontend = Path("/app/frontend/dist")
if frontend.is_dir():
    app.mount("/", StaticFiles(directory=frontend, html=True), name="frontend")
