"""Exercise the normal authenticated API; writes measured results, never fabricated scans."""

import json
import os
import time
import uuid
from pathlib import Path

import httpx

token = Path(os.environ.get("FL_TOKEN_FILE", "/data/admin-token")).read_text().strip()
api = httpx.Client(
    base_url=os.environ.get("FL_API_URL", "http://localhost:8080") + "/api/v1",
    headers={"Authorization": f"Bearer {token}"},
    timeout=180,
    trust_env=False,
)


def call(method, path, **kwargs):
    response = api.request(method, path, **kwargs)
    response.raise_for_status()
    return response.json()


project = call(
    "POST",
    "/projects",
    json={
        "name": "Gateway · synthetic firmware lab",
        "description": "Two source-built releases: inspect deliberately insecure settings, validate the revisions, and compare evidence.",
    },
)
pid = project["id"]
results = {}
for release in ("lab", "revised"):
    path = Path("/demo") / f"{release}-gzip.squashfs"
    artifact = call(
        "POST",
        f"/projects/{pid}/artifacts",
        content=path.read_bytes(),
        headers={"X-Filename": path.name},
    )
    scan = call(
        "POST",
        f"/projects/{pid}/scans",
        json={
            "artifact_id": artifact["id"],
            "label": "Gateway OS · 1.0 lab" if release == "lab" else "Gateway OS · 1.1 revised",
        },
        headers={"Idempotency-Key": str(uuid.uuid4())},
    )
    start = time.monotonic()
    while scan["status"] in ("queued", "running") and time.monotonic() - start < 660:
        time.sleep(1)
        scan = call("GET", f"/projects/{pid}/scans/{scan['id']}")
    results[release] = scan
    if scan["status"] not in ("complete", "partial"):
        print(json.dumps(scan, indent=2))
        raise RuntimeError(f"Demo scan failed: {scan['status']}")
    for format in ("json", "html", "markdown", "sbom", "sarif"):
        response = api.get(f"/projects/{pid}/scans/{scan['id']}/report", params={"format": format})
        response.raise_for_status()
        Path(
            f"/exports/{release}.{ {'markdown': 'md', 'sbom': 'cdx.json', 'sarif': 'sarif.json'}.get(format, format) }"
        ).write_bytes(response.content)
delta = call(
    "GET",
    f"/projects/{pid}/compare",
    params={"before": results["lab"]["id"], "after": results["revised"]["id"]},
)
Path("/exports/comparison.json").write_text(json.dumps(delta, indent=2))
summary = {"project": project, "scans": results, "comparison": delta}
Path("/exports/demo-results.json").write_text(json.dumps(summary, indent=2))
print(
    json.dumps(
        {
            "project_id": pid,
            "url": f"http://localhost:8080/#/{pid}",
            "scans": {
                key: {
                    "id": value["id"],
                    "status": value["status"],
                    "summary": value["summary"],
                    "measurement": {
                        k: value["manifest"].get(k)
                        for k in ("duration_ms", "peak_rss_kib", "child_peak_rss_kib")
                    },
                }
                for key, value in results.items()
            },
            "comparison_findings": delta["findings"],
        },
        indent=2,
    )
)
