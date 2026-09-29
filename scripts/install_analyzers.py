"""Build-time, checksummed installs from official Anchore release assets."""

import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

for tool, version in [("syft", "1.52.0"), ("grype", "0.119.0")]:
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    base = f"https://github.com/anchore/{tool}/releases/download/v{version}"
    name = f"{tool}_{version}_linux_{arch}.tar.gz"
    with urllib.request.urlopen(f"{base}/{tool}_{version}_checksums.txt", timeout=60) as response:  # noqa: S310
        checksums = response.read().decode()
    expected = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1] == name)
    with urllib.request.urlopen(f"{base}/{name}", timeout=120) as response:  # noqa: S310
        content = response.read()
    if hashlib.sha256(content).hexdigest() != expected:
        raise RuntimeError("Release checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(content)) as archive:
        stream = archive.extractfile(tool)
        if stream is None:
            raise RuntimeError("Tool missing from release")
        path = Path("/usr/local/bin") / tool
        path.write_bytes(stream.read())
        path.chmod(0o755)
