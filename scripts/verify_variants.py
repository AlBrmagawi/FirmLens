"""Real sandbox integration through the application queue, including signature-based variants."""

import io
import json
import os
import time
import uuid
import zipfile
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


def scan_input(pid, content, label):
    artifact = call(
        "POST",
        f"/projects/{pid}/artifacts",
        content=content,
        headers={"X-Filename": "misleading-extension.dat"},
    )
    scan = call(
        "POST",
        f"/projects/{pid}/scans",
        json={"artifact_id": artifact["id"], "label": label, "options": {"vulnerabilities": False}},
        headers={"Idempotency-Key": str(uuid.uuid4())},
    )
    start = time.monotonic()
    while scan["status"] in ("running", "queued") and time.monotonic() - start < 600:
        time.sleep(1)
        scan = call("GET", f"/projects/{pid}/scans/{scan['id']}")
    return scan


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
    scan = scan_input(pid, image.read_bytes(), name)
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

# Real encoded ZIP members: supported codecs analyze successfully; others stop
# at the extraction boundary with an actionable unsupported result.
codecs = []
for name, method, supported in [
    ("Store", zipfile.ZIP_STORED, True),
    ("Deflate", zipfile.ZIP_DEFLATED, True),
    ("BZIP2", zipfile.ZIP_BZIP2, False),
    ("LZMA", zipfile.ZIP_LZMA, False),
    ("Zstandard", getattr(zipfile, "ZIP_ZSTANDARD", 93), False),
]:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=method) as archive:
        archive.writestr("rootfs.tar", Path("/demo/lab.tar").read_bytes())
    scan = scan_input(pid, stream.getvalue(), f"ZIP codec: {name}")
    if supported:
        assert scan["status"] == "partial", (name, scan["status"])
        assert scan["summary"]["findings"] == 12
        assert scan["stages"][0]["state"] == "success"
    else:
        assert scan["status"] == "unsupported", (name, scan["status"])
        assert "ZIP compression" in scan["stages"][0]["message"]
        assert scan["summary"]["findings"] == 0
    codecs.append({"codec": name, "status": scan["status"], "scan_id": scan["id"]})
    print(json.dumps(codecs[-1]), flush=True)
Path("/exports/zip-codec-validation.json").write_text(json.dumps(codecs, indent=2))
