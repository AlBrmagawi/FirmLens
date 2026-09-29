import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from firmwarelens.config import settings
from firmwarelens.database import Base, Scan, engine, session
from firmwarelens.schemas import AnalysisResult, Stage
from firmwarelens.worker import claim


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("FL_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("FL_DATA_DIR", str(tmp_path / "data"))
    settings.cache_clear()
    engine.cache_clear()
    Base.metadata.create_all(engine())
    from firmwarelens.api import app, attempts

    attempts.clear()

    with TestClient(app) as client:
        yield client
    engine().dispose()
    engine.cache_clear()
    settings.cache_clear()


def login(client):
    response = client.post(
        "/api/v1/auth/login", json={"token": (settings().data_dir / "admin-token").read_text()}
    )
    assert response.status_code == 200
    client.headers.update(
        {"Origin": "http://localhost:8080", "X-CSRF-Token": response.json()["csrf"]}
    )


def project(client, name="Research"):
    response = client.post("/api/v1/projects", json={"name": name})
    assert response.status_code == 201
    return response.json()["id"]


def submit(client, pid, key="request-1"):
    artifact = client.post(
        f"/api/v1/projects/{pid}/artifacts",
        content=b"synthetic unsupported image",
        headers={"X-Filename": "image.img"},
    )
    assert artifact.status_code == 201
    aid = artifact.json()["id"]
    scan = client.post(
        f"/api/v1/projects/{pid}/scans",
        json={"artifact_id": aid, "label": "test"},
        headers={"Idempotency-Key": key},
    )
    assert scan.status_code == 201
    return scan.json(), artifact.json()


def test_auth_origin_and_csrf(client):
    assert client.get("/api/v1/projects").status_code == 401
    login(client)
    assert "HttpOnly" in client.cookies.jar._cookies["testserver.local"]["/"]["fl_session"]._rest
    assert (
        client.post(
            "/api/v1/projects", json={"name": "bad"}, headers={"Origin": "https://hostile.example"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/projects", json={"name": "bad"}, headers={"X-CSRF-Token": "wrong"}
        ).status_code
        == 403
    )
    assert client.get("/api/v1/projects").status_code == 200


def test_duplicate_scans_history_scope_and_cancellation(client):
    login(client)
    pid = project(client)
    other = project(client, "Other project")
    first, artifact = submit(client, pid)
    retried, duplicate = submit(client, pid)
    assert first["id"] == retried["id"]
    assert duplicate["duplicate"]
    second, _ = submit(client, pid, "request-2")
    assert second["id"] != first["id"]
    assert client.get(f"/api/v1/projects/{other}/scans/{first['id']}").status_code == 404
    assert (
        client.get(f"/api/v1/projects/{other}/artifacts/{artifact['id']}/download").status_code
        == 404
    )
    assert client.get(f"/api/v1/projects/{pid}/scans").json()["total"] == 2
    assert (
        client.post(f"/api/v1/projects/{pid}/scans/{first['id']}/cancel").json()["status"]
        == "cancelled"
    )
    assert client.delete(f"/api/v1/projects/{pid}").status_code == 409
    client.post(f"/api/v1/projects/{pid}/scans/{second['id']}/cancel")
    assert client.delete(f"/api/v1/projects/{pid}").status_code == 200


def test_integrity_size_and_idempotency_conflict(client, monkeypatch):
    login(client)
    pid = project(client)
    assert (
        client.post(
            f"/api/v1/projects/{pid}/artifacts",
            content=b"hello",
            headers={"X-Content-SHA256": "wrong"},
        ).status_code
        == 422
    )
    assert not list((settings().data_dir / "uploads").iterdir())
    scan, artifact = submit(client, pid)
    assert artifact["id"] == hashlib.sha256(b"synthetic unsupported image").hexdigest()
    assert (
        client.post(
            f"/api/v1/projects/{pid}/scans",
            json={"artifact_id": artifact["id"], "label": "different"},
            headers={"Idempotency-Key": "request-1"},
        ).status_code
        == 409
    )
    settings().upload_limit = 3
    assert client.post(f"/api/v1/projects/{pid}/artifacts", content=b"large").status_code == 413
    assert not list((settings().data_dir / "uploads").iterdir())


def test_restart_recovery_and_retry_limit(client):
    login(client)
    pid = project(client)
    created, _ = submit(client, pid)
    with session() as db:
        scan = claim(db, settings())
        assert scan.id == created["id"] and scan.attempts == 1
        token = scan.lease_token
        scan.lease_until = time.time() - 1
        db.commit()
    with session() as db:
        recovered = claim(db, settings())
        assert recovered.id == scan.id and recovered.attempts == 2
        assert recovered.lease_token != token
        recovered.lease_until = time.time() - 1
        db.commit()
    with session() as db:
        assert claim(db, settings()) is None
        assert db.get(Scan, scan.id).status == "failed"


def test_missing_results_and_disabled_ai(client):
    login(client)
    pid = project(client)
    scan, artifact = submit(client, pid)
    root = f"/api/v1/projects/{pid}/scans/{scan['id']}"
    assert client.get(root + "/report").status_code == 409
    with session() as db:
        row = db.get(Scan, scan["id"])
        row.status = "partial"
        row.result = AnalysisResult(
            artifact_sha256=artifact["id"],
            format="tar",
            outcome="partial",
            stages=[Stage(id="vulnerabilities", state="failure", message="Missing database")],
        ).model_dump()
        db.commit()
    assert client.post(root + "/assistant", json={"question": "What is known?"}).status_code == 409
    assert client.get(root + "/report?format=html").status_code == 200
    assert client.get(root + "/report?format=sbom").status_code == 422
    assert client.get(root + "/file?path=../../admin-token").status_code == 404
    assert client.get(root + "/findings?limit=10000").status_code == 422


@pytest.mark.parametrize("analyst_cancelled", [False, True])
@pytest.mark.parametrize("previous_attempts", [0, 1])
def test_shutdown_respects_retry_budget_and_records_terminal_time(
    client, monkeypatch, analyst_cancelled, previous_attempts
):
    from firmwarelens import worker

    login(client)
    pid = project(client)
    created, _ = submit(client, pid)
    with session() as db:
        row = db.get(Scan, created["id"])
        row.attempts = previous_attempts
        db.commit()

    class Runtime:
        def close(self):
            pass

    def interrupted(*args):
        if analyst_cancelled:
            with session() as db:
                db.get(Scan, created["id"]).cancel_requested = True
                db.commit()
        worker.stopping = True
        raise worker.Cancelled()

    monkeypatch.setattr(worker, "stopping", False)
    monkeypatch.setattr(worker.signal, "signal", lambda *args: None)
    monkeypatch.setattr(worker.docker, "from_env", lambda **kwargs: Runtime())
    monkeypatch.setattr(worker, "capabilities", lambda *args: {"ready": True})
    monkeypatch.setattr(worker, "cleanup_orphans", lambda *args: None)
    monkeypatch.setattr(worker, "run_sandbox", interrupted)
    worker.main()
    with session() as db:
        row = db.get(Scan, created["id"])
        expected = "cancelled" if analyst_cancelled else "failed" if previous_attempts else "queued"
        assert row.status == expected
        assert (row.finished_at is not None) == (expected != "queued")
        assert row.lease_until == 0
        assert row.result is None
        if expected == "queued":
            assert claim(db, settings()).attempts == 2
        else:
            assert claim(db, settings()) is None


def completed_scan(client, pid, key="completed"):
    from firmwarelens.schemas import Component, Evidence, FileRecord, Finding

    scan, artifact = submit(client, pid, key)
    result = AnalysisResult(
        artifact_sha256=artifact["id"],
        outcome="complete",
        format="tar",
        stages=[Stage(id="configuration", state="success", message="Inspected")],
        files=[FileRecord(path="etc/config", size=10, mode=0o644, preview="password=[REDACTED]")],
        components=[Component(id="component-1", name="busybox", version="1.30", ecosystem="apk")],
        evidence=[
            Evidence(
                id="evidence-1",
                path="etc/config",
                artifact_sha256=artifact["id"],
                analyzer="configuration",
                excerpt="password=[REDACTED]",
            )
        ],
        findings=[
            Finding(
                id="finding-1",
                fingerprint="fingerprint-1",
                rule_id="CRED-001",
                title="Embedded credential",
                category="credentials",
                severity="high",
                confidence="medium",
                path="etc/config",
                evidence_ids=["evidence-1"],
                explanation="Static credential",
                remediation="Remove credential",
                analyzer="configuration",
            )
        ],
    ).model_dump(mode="json")
    with session() as db:
        row = db.get(Scan, scan["id"])
        row.status, row.result = "complete", result
        db.commit()
    return f"/api/v1/projects/{pid}/scans/{scan['id']}", scan["id"], result


def test_triage_scope_expiry_audit_and_immutable_results(client):
    login(client)
    pid = project(client)
    base, scan_id, original = completed_scan(client, pid)
    second, _, _ = completed_scan(client, pid, "second")
    other, _, _ = completed_scan(client, project(client, "Other"))
    detail = base + "/findings/finding-1"
    assert (
        client.patch(detail, json={"status": "accepted-risk", "suppress": True}).status_code == 422
    )
    assert (
        client.patch(
            detail, json={"status": "open", "expires_at": "2030-01-01T00:00:00"}
        ).status_code
        == 422
    )
    update = {
        "status": "acknowledged",
        "note": "password=SHOULD_NOT_SURVIVE",
        "suppress": True,
        "reason": "Lab scope",
        "expires_at": "2099-01-01T03:00:00+03:00",
    }
    assert client.patch(detail, json=update).json()["suppressed"]
    for path in (detail, second + "/findings/finding-1"):
        response = client.get(path)
        assert response.json()["triage"]["status"] == "acknowledged"
        assert response.json()["triage"]["expires_at"] == "2099-01-01T00:00:00+00:00"
        assert len(response.json()["history"]) == 1
        assert "SHOULD_NOT_SURVIVE" not in response.text
    assert client.get(other + "/findings/finding-1").json()["triage"]["status"] == "open"
    assert (
        client.get(base + "/findings?q=CRED&severity=high&status=acknowledged&limit=1").json()[
            "total"
        ]
        == 1
    )
    assert client.get(base + "/findings?status=open").json()["total"] == 0
    assert client.get(base + "/findings?offset=1").json()["items"] == []
    update["expires_at"] = "2000-01-01T00:00:00Z"
    assert not client.patch(detail, json=update).json()["suppressed"]
    with session() as db:
        assert db.get(Scan, scan_id).result == original


def test_inventory_exports_comparison_and_deletion(client):
    login(client)
    pid = project(client)
    base, scan_id, original = completed_scan(client, pid)
    other_pid = project(client, "Other")
    _, other_id, _ = completed_scan(client, other_pid)
    assert client.get(base + "/components?q=BUSYBOX").json()["total"] == 1
    assert client.get(base + "/components?q=absent").json()["total"] == 0
    listing = client.get(base + "/files?q=config").json()["items"]
    assert listing[0]["path"] == "etc/config" and "preview" not in listing[0]
    assert client.get(base + "/file?path=etc/config").json()["preview"] == "password=[REDACTED]"
    assert (
        client.get(base + "/evidence/evidence-1").json()["artifact_sha256"]
        == original["artifact_sha256"]
    )
    for suffix in ("/evidence/missing", "/findings/missing", "/file?path=/etc/passwd"):
        assert client.get(base + suffix).status_code == 404
    for format in ("json", "html", "markdown", "sarif"):
        response = client.get(base + "/report", params={"format": format})
        assert response.status_code == 200
        assert response.headers["content-disposition"].startswith("attachment;")
    compare = f"/api/v1/projects/{pid}/compare"
    assert client.get(compare, params={"before": scan_id, "after": other_id}).status_code == 404
    for format in ("json", "html", "markdown"):
        assert (
            client.get(
                compare + "/export", params={"before": scan_id, "after": scan_id, "format": format}
            ).status_code
            == 200
        )
    assert (
        client.get(
            compare + "/export", params={"before": scan_id, "after": scan_id, "format": "invalid"}
        ).status_code
        == 422
    )
    assert client.delete(base).status_code == 200
    assert client.get(base).status_code == 404


def test_assistant_scope_failure_budget_and_history(client, monkeypatch):
    from firmwarelens import api

    login(client)
    pid = project(client)
    base, scan_id, original = completed_scan(client, pid)
    _, other_id, _ = completed_scan(client, project(client, "Other"))
    settings().ai_provider = "ollama"
    settings().ai_model = "test-provider"
    settings().ai_daily_requests = 2
    calls = []

    async def provider(config, question, result, comparison):
        calls.append(question.question)
        assert result.model_dump(mode="json") == original
        if len(calls) == 2:
            raise TimeoutError("SENSITIVE_PROVIDER_DETAIL")
        return {"claims": [], "cannot_answer": True, "provider": "ollama"}

    monkeypatch.setattr(api, "ask", provider)
    assert (
        client.post(
            base + "/assistant", json={"question": "Compare", "compare_scan_id": other_id}
        ).status_code
        == 404
    )
    assert not calls
    assert (
        client.post(base + "/assistant", json={"question": "password=DO_NOT_STORE"}).status_code
        == 200
    )
    failed = client.post(base + "/assistant", json={"question": "Retry"})
    assert failed.status_code == 502 and "SENSITIVE_PROVIDER_DETAIL" not in failed.text
    assert client.post(base + "/assistant", json={"question": "Over budget"}).status_code == 429
    history = client.get(base + "/conversations")
    assert history.status_code == 200
    assert {row["state"] for row in history.json()} == {"complete", "failed"}
    assert "DO_NOT_STORE" not in history.text
    with session() as db:
        assert db.get(Scan, scan_id).result == original


def test_session_revocation_expiry_rate_limit_and_readiness(client):
    from sqlalchemy import select

    from firmwarelens.database import BrowserSession, Heartbeat

    assert client.get("/ready").status_code == 503
    with session() as db:
        db.add(Heartbeat(id="supervisor", at=time.time(), details={"ready": True}))
        db.commit()
    assert client.get("/ready").status_code == 200
    login(client)
    assert client.get("/api/v1/settings").json()["ai"]["provider"] == "disabled"
    cookie = client.cookies.get("fl_session")
    assert client.post("/api/v1/auth/logout").status_code == 200
    client.cookies.set("fl_session", cookie)
    assert client.get("/api/v1/projects").status_code == 401
    client.cookies.clear()
    login(client)
    with session() as db:
        db.scalar(select(BrowserSession)).expires = time.time() - 1
        db.get(Heartbeat, "supervisor").at = time.time() - 91
        db.commit()
    assert client.get("/api/v1/projects").status_code == 401
    assert client.get("/ready").status_code == 503
    for _ in range(8):
        assert client.post("/api/v1/auth/login", json={"token": "invalid"}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"token": "invalid"}).status_code == 429
