"""CLI client for the same authenticated API and isolated pipeline as the UI."""

import json
import os
import time
import uuid
from pathlib import Path

import httpx
import typer

app = typer.Typer(help="FirmwareLens — evidence-first firmware research", no_args_is_help=True)
projects = typer.Typer(help="Manage research projects")
scans = typer.Typer(help="Inspect or cancel persisted scans")
intelligence = typer.Typer(help="Explicit local Grype database maintenance outside analysis")
retention = typer.Typer(help="Remove expired records and unreferenced artifacts")
app.add_typer(projects, name="project")
app.add_typer(scans, name="scans")
app.add_typer(intelligence, name="intelligence")
app.add_typer(retention, name="retention")


def token() -> str:
    value = os.environ.get("FL_TOKEN", "")
    path = Path(os.environ.get("FL_TOKEN_FILE", "/data/admin-token"))
    if not value and path.is_file():
        value = path.read_text().strip()
    if not value:
        typer.echo("Set FL_TOKEN or FL_TOKEN_FILE to the local access credential", err=True)
        raise typer.Exit(5)
    return value


def request(method: str, path: str, **kwargs) -> httpx.Response:
    try:
        with httpx.Client(
            base_url=os.environ.get("FL_API_URL", "http://localhost:8080"),
            headers={"Authorization": f"Bearer {token()}"},
            timeout=180,
            trust_env=False,
        ) as client:
            response = client.request(method, "/api/v1" + path, **kwargs)
            response.raise_for_status()
            return response
    except httpx.HTTPStatusError as exc:
        typer.echo(exc.response.text, err=True)
        raise typer.Exit(2) from exc
    except httpx.HTTPError as exc:
        typer.echo(
            f"API unavailable ({type(exc).__name__}); run docker compose up and firmwarelens doctor",
            err=True,
        )
        raise typer.Exit(5) from exc


def emit(data, json_output: bool = True) -> None:
    typer.echo(json.dumps(data, indent=2, ensure_ascii=False, default=str))


@app.command()
def doctor(json_output: bool = typer.Option(False, "--json")):
    """Check database, supervisor, sandbox capabilities, and configured tools."""
    info = request("GET", "/settings").json()
    emit(info, json_output)
    if not info["supervisor"]["alive"] or not info["supervisor"]["sandbox"].get("ready"):
        raise typer.Exit(5)


@app.command("access-token")
def show_access_token():
    """Display the first-run credential locally. Never paste it into an issue."""
    typer.echo(token())


@projects.command("create")
def project_create(
    name: str, description: str = "", json_output: bool = typer.Option(False, "--json")
):
    emit(
        request("POST", "/projects", json={"name": name, "description": description}).json(),
        json_output,
    )


@projects.command("list")
def project_list():
    emit(request("GET", "/projects").json())


@projects.command("delete")
def project_delete(project: str):
    """Delete project history. Active scans must be cancelled first."""
    emit(request("DELETE", f"/projects/{project}").json())


@app.command()
def scan(
    image: Path = typer.Argument(exists=True, dir_okay=False),
    project: str = typer.Option(..., "--project", "-p"),
    label: str = "",
    wait: bool = True,
    fail_on: str = typer.Option(
        "none", help="Exit 3 at/above critical, high, medium, low, or info"
    ),
    allow_partial: bool = False,
    idempotency_key: str = typer.Option("", help="Reuse for safe submission retries"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Stream firmware to immutable storage and run isolated analysis. Exit 2=failed, 3=threshold, 4=partial, 5=unavailable."""
    if fail_on not in ("none", "critical", "high", "medium", "low", "info"):
        raise typer.BadParameter("Invalid severity threshold")
    with image.open("rb") as stream:
        artifact = request(
            "POST",
            f"/projects/{project}/artifacts",
            content=stream,
            headers={"X-Filename": image.name},
        ).json()
    result = request(
        "POST",
        f"/projects/{project}/scans",
        json={"artifact_id": artifact["id"], "label": label or image.name[:100]},
        headers={"Idempotency-Key": idempotency_key or str(uuid.uuid4())},
    ).json()
    if wait:
        while result["status"] in ("queued", "running"):
            time.sleep(1)
            result = request("GET", f"/projects/{project}/scans/{result['id']}").json()
    emit(result, json_output)
    if result["status"] in ("failed", "unsupported", "cancelled"):
        raise typer.Exit(2)
    if fail_on != "none" and result["status"] in ("complete", "partial"):
        order = ["critical", "high", "medium", "low", "info"]
        if any(result["summary"]["severity"][s] for s in order[: order.index(fail_on) + 1]):
            raise typer.Exit(3)
    if result["status"] == "partial" and not allow_partial:
        raise typer.Exit(4)


@scans.command("list")
def scans_list(project: str, json_output: bool = typer.Option(False, "--json")):
    emit(request("GET", f"/projects/{project}/scans").json(), json_output)


@scans.command("cancel")
def scans_cancel(project: str, scan_id: str):
    emit(request("POST", f"/projects/{project}/scans/{scan_id}/cancel").json())


@app.command()
def findings(
    project: str,
    scan_id: str,
    severity: str = "",
    search: str = "",
    offset: int = 0,
    limit: int = 50,
    json_output: bool = typer.Option(False, "--json"),
):
    emit(
        request(
            "GET",
            f"/projects/{project}/scans/{scan_id}/findings",
            params={"severity": severity, "q": search, "offset": offset, "limit": limit},
        ).json(),
        json_output,
    )


@app.command("compare")
def compare_scans(
    project: str, before: str, after: str, output: Path | None = None, format: str = "json"
):
    path = f"/projects/{project}/compare" + ("/export" if output else "")
    response = request("GET", path, params={"before": before, "after": after, "format": format})
    if output:
        output.write_bytes(response.content)
        emit({"saved": str(output)})
    else:
        emit(response.json())


@app.command("report")
def export_report(project: str, scan_id: str, output: Path, format: str = "html"):
    response = request(
        "GET", f"/projects/{project}/scans/{scan_id}/report", params={"format": format}
    )
    output.write_bytes(response.content)
    emit({"saved": str(output), "bytes": len(response.content)})


def maintain_database(action: str, archive: Path | None = None):
    import subprocess

    argv = ["grype", "db", action]
    if archive:
        argv.append(str(archive.resolve()))
    env = {
        **os.environ,
        "GRYPE_DB_CACHE_DIR": "/intelligence",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    }
    try:
        result = subprocess.run(argv, env=env, timeout=600, check=False)  # noqa: S603
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        typer.echo(
            "Run intelligence commands in the dedicated maintenance container; tool unavailable or timed out",
            err=True,
        )
        raise typer.Exit(5) from exc
    if result.returncode:
        raise typer.Exit(2)


@intelligence.command("update")
def intelligence_update():
    """Explicitly download/update advisory database (requires network)."""
    maintain_database("update")


@intelligence.command("import")
def intelligence_import(archive: Path = typer.Argument(exists=True, dir_okay=False)):
    """Import a previously prepared official Grype database archive."""
    maintain_database("import", archive)


@intelligence.command("status")
def intelligence_status():
    maintain_database("status")


@retention.command("gc")
def garbage_collect(days: int = typer.Option(30, min=1), apply: bool = False):
    """Locally collect unreferenced artifacts older than DAYS; dry-run by default."""
    import shutil

    from sqlalchemy import delete, select

    from firmwarelens.config import settings
    from firmwarelens.database import Artifact, BrowserSession, ProjectArtifact, Scan, session

    removed = []
    cutoff = time.time() - days * 86400
    from datetime import datetime

    with session() as db:
        for artifact in db.scalars(select(Artifact).with_for_update()):
            if datetime.fromisoformat(artifact.created_at).timestamp() >= cutoff:
                continue
            if db.scalar(
                select(ProjectArtifact).where(ProjectArtifact.artifact_id == artifact.id)
            ) or db.scalar(select(Scan).where(Scan.artifact_id == artifact.id)):
                continue
            directory = settings().data_dir / "artifacts" / artifact.id
            if directory.resolve().parent != (settings().data_dir / "artifacts").resolve():
                raise RuntimeError("Retention path escaped artifact root")
            removed.append(artifact.id)
            if apply:
                shutil.rmtree(directory, ignore_errors=True)
                db.delete(artifact)
        if apply:
            db.execute(delete(BrowserSession).where(BrowserSession.expires < time.time()))
            db.commit()
    emit({"dry_run": not apply, "artifact_ids": removed})


if __name__ == "__main__":
    app()
