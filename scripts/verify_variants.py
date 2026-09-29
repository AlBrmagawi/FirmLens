"""Real sandbox integration through the application queue, including signature-based variants."""

import json
import os
import time
import uuid
from pathlib import Path

import httpx

client = httpx.Client(
    base_url=os.environ.get("FL_API_URL", "http://localhost:8080") + "/api/v1",
    headers={"Authorization": "Bearer " + Path("/data/admin-token").read_text().strip()},
    timeout=180,
)


def call(method, path, **kwargs):
    r = client.request(method, path, **kwargs)
    r.raise_for_status()
    return r.json()


pid = call("POST", "/projects", json={"name": "Integration · format support matrix"})["id"]
measurements = []
for name in [
    "lab.tar",
    "lab.tar.gz",
    "lab-gzip.squashfs",
    "lab-xz.squashfs",
    "lab-zstd.squashfs",
    "lab-embedded.bin",
    "lab.zip",
]:
    image = Path("/demo") / name
    artifact = call(
        "POST",
        f"/projects/{pid}/artifacts",
        content=image.read_bytes(),
        headers={"X-Filename": "misleading-extension.dat"},
    )
    scan = call(
        "POST",
        f"/projects/{pid}/scans",
        json={"artifact_id": artifact["id"], "label": name, "options": {"vulnerabilities": False}},
        headers={"Idempotency-Key": str(uuid.uuid4())},
    )
    start = time.monotonic()
    while scan["status"] in ("running", "queued") and time.monotonic() - start < 600:
        time.sleep(1)
        scan = call("GET", f"/projects/{pid}/scans/{scan['id']}")
    findings = call("GET", f"/projects/{pid}/scans/{scan['id']}/findings?limit=200")["items"]
    required = {
        "AUTH-001",
        "SSH-001",
        "SVC-001",
        "CRED-001",
        "CRED-002",
        "PERM-001",
        "PERM-002",
        "ELF-001",
        "ELF-002",
        "ELF-003",
    }
    assert required <= {f["rule_id"] for f in findings}, (name, scan, findings)
    assert all(s["state"] == "success" for s in scan["stages"] if s["id"] != "vulnerabilities"), (
        name,
        scan["stages"],
    )
    assert scan["summary"]["components"] >= 1, (name, "missing component")
    if name.endswith("embedded.bin"):
        assert scan["payloads"][0]["offset"] == 4096
    measurements.append(
        {
            "input": name,
            "scan_id": scan["id"],
            "format": scan["format"],
            "summary": scan["summary"],
            "duration_ms": scan["manifest"].get("duration_ms"),
        }
    )
    print(json.dumps(measurements[-1]), flush=True)
Path("/exports/format-validation.json").write_text(json.dumps(measurements, indent=2))
