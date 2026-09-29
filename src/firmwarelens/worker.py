"""Durable leased queue; safe recovery and bounded retries without a broker."""

import json
import signal
import time

import docker
from sqlalchemy import select

from firmwarelens.config import settings
from firmwarelens.database import Event, Heartbeat, Scan, session, uid
from firmwarelens.sandbox import Cancelled, capabilities, run_sandbox
from firmwarelens.schemas import ScanOptions, now

stopping = False


def cleanup_orphans(client) -> None:
    """Reap only our managed containers whose job no longer has an active lease."""
    for container in client.containers.list(
        all=True, filters={"label": "firmwarelens.role=analysis"}
    ):
        scan_id = container.labels.get("firmwarelens.scan", "")
        if not scan_id or container.name != f"firmwarelens-{scan_id}":
            continue
        with session() as db:
            scan = db.scalar(select(Scan).where(Scan.id == scan_id).with_for_update())
            if scan and scan.status == "running" and scan.lease_until > time.time():
                continue
            container.remove(force=True)


def stop(signum: int, frame: object) -> None:
    global stopping
    stopping = True


def claim(db, config):
    for scan in db.scalars(
        select(Scan)
        .where(Scan.status == "running", Scan.lease_until < time.time())
        .with_for_update(skip_locked=True)
    ):
        scan.status = (
            "cancelled"
            if scan.cancel_requested
            else "queued"
            if scan.attempts < config.max_attempts
            else "failed"
        )
        scan.error = (
            "Recovered interrupted worker lease"
            if scan.status == "queued"
            else "Worker interrupted; retry budget exhausted"
            if scan.status == "failed"
            else "Cancelled during restart"
        )
        db.add(Event(scan_id=scan.id, stage="recovery", message=scan.error))
        if scan.status != "queued":
            scan.finished_at = now()
            scan.lease_until = 0
    db.flush()
    scan = db.scalar(
        select(Scan)
        .where(Scan.status == "queued")
        .order_by(Scan.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if scan is not None:
        scan.status = "running"
        scan.attempts += 1
        scan.lease_token = uid()
        scan.lease_until = time.time() + config.lease_seconds
        scan.error = None
        db.add(Event(scan_id=scan.id, stage="starting", message=f"Sandbox attempt {scan.attempts}"))
    db.commit()
    return scan


def main() -> None:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    config = settings()
    last_check = 0.0
    health: dict = {}
    while not stopping:
        try:
            if time.time() - last_check > 30:
                try:
                    client = docker.from_env(timeout=10)
                    health = capabilities(client, config)
                    cleanup_orphans(client)
                    client.close()
                except Exception:
                    health = {"ready": False, "error": "Docker runtime unavailable"}
                last_check = time.time()
            with session() as db:
                db.merge(Heartbeat(id="supervisor", at=time.time(), details=health))
                db.commit()
                scan = claim(db, config)
            if scan is None:
                time.sleep(1)
                continue
            scan_id, token = scan.id, scan.lease_token

            def heartbeat(scan_id=scan_id, token=token, health=health) -> bool:
                with session() as db:
                    current = db.get(Scan, scan_id)
                    if current is None or current.lease_token != token:
                        return True
                    current.lease_until = time.time() + config.lease_seconds
                    db.merge(Heartbeat(id="supervisor", at=time.time(), details=health))
                    db.commit()
                    return current.cancel_requested or stopping

            def event(stage: str, message: str, scan_id=scan_id) -> None:
                with session() as db:
                    db.add(Event(scan_id=scan_id, stage=stage, message=message))
                    db.commit()

            result = None
            error = None
            try:
                result = run_sandbox(
                    config,
                    scan.id,
                    scan.artifact_id,
                    ScanOptions.model_validate(scan.options),
                    heartbeat,
                    event,
                )
                status: str = result.outcome
            except Cancelled:
                status = "queued" if stopping else "cancelled"
                error = (
                    "Worker shutdown; queued for recovery" if stopping else "Cancelled by analyst"
                )
            except Exception as exc:
                status = "failed"
                error = (
                    str(exc)[:500]
                    if isinstance(exc, RuntimeError)
                    else f"Supervisor failure ({type(exc).__name__})"
                )
            with session() as db:
                current = db.get(Scan, scan_id)
                if current and current.lease_token == token:
                    current.status = "cancelled" if current.cancel_requested else status
                    current.result = (
                        result.model_dump(mode="json")
                        if result and not current.cancel_requested
                        else None
                    )
                    current.error = error
                    current.finished_at = now() if status != "queued" else None
                    current.lease_until = 0
                    db.add(
                        Event(
                            scan_id=scan_id,
                            stage=current.status,
                            message=error or f"Analysis {current.status}",
                        )
                    )
                    db.commit()
            print(
                json.dumps({"job_id": scan_id, "state": status, "event": "job_finished"}),
                flush=True,
            )
        except Exception as exc:
            print(json.dumps({"event": "supervisor_error", "type": type(exc).__name__}), flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
