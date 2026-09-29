"""Build both lab releases reproducibly from source; no seeded analysis results."""

import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

EPOCH = 1700000000
OUT = Path(os.environ.get("DEMO_OUT", "/out"))
OUT.mkdir(parents=True, exist_ok=True)
manifest = {"source_date_epoch": EPOCH, "releases": {}}
for release in ("lab", "revised"):
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp) / "root"
        root.mkdir()
        files = {
            "etc/os-release": 'ID=alpine\nNAME="FirmwareLens synthetic lab"\nVERSION_ID=3.20.0\n',
            "etc/passwd": "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/var/empty:/sbin/nologin\n",
            "etc/shadow": "root::19000:0:99999:7:::\n"
            if release == "lab"
            else "root:!:19000:0:99999:7:::\n",
            "etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n"
            if release == "lab"
            else "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\n",
            "etc/init.d/remote": "#!/bin/sh\n/usr/sbin/telnetd -l /bin/sh\n"
            if release == "lab"
            else "#!/bin/sh\n# Telnet removed; SSH administration only\n/usr/sbin/sshd\n",
            "etc/device.conf": "admin_password=SYNTHETIC_LAB_ONLY_DO_NOT_USE\n"
            if release == "lab"
            else "credential_source=per_device_provisioning\n",
            "etc/motd": "FirmwareLens deliberately synthetic research fixture. No real device or credential.\n",
            "lib/apk/db/installed": f"P:busybox\nV:{'1.36.1-r15' if release == 'lab' else '1.36.1-r29'}\nA:x86_64\nL:GPL-2.0-only\nT:Synthetic package metadata for inventory testing\no:busybox\nS:123\nI:123\nF:bin\nR:busybox\n\n",
        }
        if release == "lab":
            files["etc/lab_private_key"] = (
                "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-NONFUNCTIONAL-FIXTURE\n-----END PRIVATE KEY-----\n"
            )
        for name, content in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o644)
        (root / "etc/shadow").chmod(0o666 if release == "lab" else 0o600)
        (root / "etc/init.d").chmod(0o777 if release == "lab" else 0o755)
        (root / "usr/bin").mkdir(parents=True)
        flags = (
            ["-fno-stack-protector", "-no-pie", "-Wl,-z,norelro", "-Wl,-z,execstack"]
            if release == "lab"
            else [
                "-fstack-protector-all",
                "-fPIE",
                "-pie",
                "-Wl,-z,relro,-z,now",
                "-Wl,-z,noexecstack",
                "-s",
            ]
        )
        subprocess.run(
            [
                "gcc",
                "-O1",
                "-Wl,--build-id=none",
                *flags,
                "/demo/probe.c",
                "-o",
                str(root / "usr/bin/lens-probe"),
            ],
            check=True,
        )
        for path in sorted(root.rglob("*")):
            os.utime(path, (EPOCH, EPOCH))
        os.utime(root, (EPOCH, EPOCH))
        tar_path = OUT / f"{release}.tar"
        with tarfile.open(tar_path, "w", format=tarfile.USTAR_FORMAT) as archive:
            for path in sorted(root.rglob("*")):
                info = archive.gettarinfo(str(path), arcname=path.relative_to(root).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = EPOCH
                with path.open("rb") if path.is_file() else io.BytesIO() as source:
                    archive.addfile(info, source if path.is_file() else None)
        with (OUT / f"{release}.tar.gz").open("wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=EPOCH) as stream:
                stream.write(tar_path.read_bytes())
        for compression in ("gzip", "xz", "zstd"):
            image = OUT / f"{release}-{compression}.squashfs"
            subprocess.run(
                [
                    "mksquashfs",
                    str(root),
                    str(image),
                    "-noappend",
                    "-no-progress",
                    "-processors",
                    "1",
                    "-all-root",
                    "-all-time",
                    str(EPOCH),
                    "-mkfs-time",
                    str(EPOCH),
                    "-comp",
                    compression,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        image = (OUT / f"{release}-gzip.squashfs").read_bytes()
        (OUT / f"{release}-embedded.bin").write_bytes(
            b"FIRMWARELENS-SYNTHETIC".ljust(4096, b"\x00") + image
        )
        with zipfile.ZipFile(OUT / f"{release}.zip", "w", zipfile.ZIP_DEFLATED) as bundle:
            entry = zipfile.ZipInfo("payload/rootfs.img", date_time=(2023, 11, 14, 22, 13, 20))
            entry.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(entry, image)
        manifest["releases"][release] = {
            "compiler_flags": flags,
            "file_count": sum(1 for p in root.rglob("*") if p.is_file()),
        }
manifest["sha256"] = {
    p.name: hashlib.sha256(p.read_bytes()).hexdigest()
    for p in sorted(OUT.iterdir())
    if p.is_file() and p.name.startswith(("lab.", "lab-", "revised.", "revised-"))
}
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2))
print(json.dumps(manifest, indent=2))
