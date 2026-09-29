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
    from firmwarelens.api import app

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
