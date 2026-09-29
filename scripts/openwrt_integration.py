"""Download a pinned, redistributable OpenWrt rootfs for the ordinary scan workflow."""

import gzip
import hashlib
import io
import urllib.request
from pathlib import Path

URL = "https://downloads.openwrt.org/releases/23.05.5/targets/x86/64/openwrt-23.05.5-x86-64-generic-squashfs-rootfs.img.gz"
SHA256 = "478601ab0f5176372e6e0079614240dd25049c74167572ca9bc1b91e9261fe17"
destination = Path("demo/generated/openwrt-23.05.5-rootfs.squashfs")
destination.parent.mkdir(parents=True, exist_ok=True)
with urllib.request.urlopen(URL, timeout=120) as response:  # noqa: S310
    payload = response.read(33554433)
if len(payload) > 33554432 or hashlib.sha256(payload).hexdigest() != SHA256:
    raise RuntimeError("Pinned OpenWrt checksum mismatch or unexpected download size")
with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
    image = stream.read(134217729)
if len(image) > 134217728 or image[:4] != b"hsqs":
    raise RuntimeError("Unexpected decompressed OpenWrt filesystem")
destination.write_bytes(image)
print(f"Verified {SHA256}; extracted {len(image)} bytes to {destination}")
print(f"Raw image SHA-256: {hashlib.sha256(image).hexdigest()}")
