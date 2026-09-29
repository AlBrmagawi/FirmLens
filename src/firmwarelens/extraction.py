"""Signature-led extraction. Called only in the disposable analysis sandbox."""

import gzip
import hashlib
import io
import os
import re
import stat
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import IO

from firmwarelens.schemas import FileRecord, Limits
from firmwarelens.tooling import ToolError, run_tool


class ExtractionError(ValueError):
    pass


class Unsupported(ExtractionError):
    pass


def safe_path(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    if (
        not name
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or ":" in name
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
        or len(name) > 1024
    ):
        raise ExtractionError("Unsafe or overlong archive path rejected")
    return str(path)


def signature(data: bytes) -> str:
    if data.startswith(b"hsqs"):
        return "squashfs"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if len(data) >= 512:
        try:
            tarfile.TarInfo.frombuf(data[:512], "utf-8", "surrogateescape")
            return "tar"
        except (tarfile.HeaderError, ValueError):
            pass
    return "unknown"


@dataclass
class Extraction:
    root: Path
    limits: Limits
    files: list[FileRecord] = field(default_factory=list)
    payloads: list[dict] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    used: int = 0
    expanded: int = 0
    paths: set[str] = field(default_factory=set)
    format: str = "unknown"

    def budget(self, size: int) -> None:
        if (
            size < 0
            or size > self.limits.max_file_bytes
            or len(self.files) >= self.limits.max_files
            or self.used + size > self.limits.max_bytes
        ):
            raise ExtractionError(
                "Extraction file-count or byte budget exceeded; increase bounded scan limits if appropriate"
            )
        self.used += size

    def add(
        self,
        name: str,
        size: int,
        mode: int,
        uid: int = 0,
        gid: int = 0,
        kind: str = "file",
        link: str | None = None,
        source: IO[bytes] | None = None,
    ) -> None:
        path = safe_path(name)
        if path == ".":
            return
        if path in self.paths:
            raise ExtractionError("Duplicate archive path rejected")
        self.paths.add(path)
        self.budget(size)
        record = FileRecord(
            path=path, size=size, mode=mode & 0o7777, uid=uid, gid=gid, kind=kind, link_target=link
        )
        target = self.root / path
        if kind == "file" and source is not None:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = hashlib.sha256()
            remaining = size
            with target.open("xb") as output:
                while remaining:
                    chunk = source.read(min(65536, remaining))
                    if not chunk:
                        raise ExtractionError("Truncated archive member")
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            target.chmod(0o600)
            record.sha256 = digest.hexdigest()
        elif kind == "directory":
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
        elif kind in ("symlink", "hardlink"):
            # Preserve link metadata, but never create links or dereference their targets.
            self.diagnostics.append(f"Link metadata retained without dereference: {path}")
        else:
            self.diagnostics.append(f"Special file omitted: {path}")
        self.files.append(record)

    def unpack(self, data: bytes, work: Path, prefix: str = "", depth: int = 0) -> None:
        if depth > self.limits.max_depth:
            raise ExtractionError("Nested payload depth exceeded")
        kind = signature(data)
        if depth == 0:
            self.format = kind
        if kind == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                unpacked = stream.read(self.limits.max_bytes + 1)
            self.expanded += len(unpacked)
            if self.expanded > self.limits.max_bytes:
                raise ExtractionError("Decompression byte budget exceeded")
            if signature(unpacked) != "tar":
                raise Unsupported("Gzip payload is not a supported tar root filesystem")
            self.unpack(unpacked, work, prefix, depth + 1)
        elif kind == "tar":
            self.payloads.append({"type": "tar", "path": prefix or "/", "offset": 0})
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
                for item in archive:
                    name = prefix + safe_path(item.name)
                    if item.isfile():
                        self.add(
                            name,
                            item.size,
                            item.mode,
                            item.uid,
                            item.gid,
                            source=archive.extractfile(item),
                        )
                    else:
                        file_kind = (
                            "directory"
                            if item.isdir()
                            else "symlink"
                            if item.issym()
                            else "hardlink"
                            if item.islnk()
                            else "special"
                        )
                        self.add(
                            name, 0, item.mode, item.uid, item.gid, file_kind, item.linkname or None
                        )
        elif kind == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if len(members) > self.limits.max_files:
                    raise ExtractionError("ZIP member count exceeded")
                found = 0
                names: set[str] = set()
                for member in members:
                    name = safe_path(member.filename)
                    if name in names:
                        raise ExtractionError("Duplicate ZIP member rejected")
                    names.add(name)
                    if member.flag_bits & 1:
                        raise Unsupported(
                            "Encrypted ZIP members are unsupported; supply decrypted authorized firmware"
                        )
                    if member.is_dir():
                        continue
                    if stat.S_ISLNK(member.external_attr >> 16):
                        self.diagnostics.append(f"ZIP symlink omitted: {name}")
                        continue
                    if member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                        raise Unsupported(
                            "ZIP compression method is unsupported; use Store or Deflate"
                        )
                    self.expanded += member.file_size
                    if self.expanded > self.limits.max_bytes:
                        raise ExtractionError("ZIP expansion budget exceeded")
                    with archive.open(member) as stream:
                        payload = stream.read(self.limits.max_bytes + 1)
                    if len(payload) != member.file_size:
                        raise ExtractionError("Invalid ZIP member size")
                    try:
                        self.unpack(payload, work, prefix + f"payload-{found}/", depth + 1)
                        found += 1
                    except Unsupported:
                        self.diagnostics.append(f"Unsupported ZIP member: {name}")
                if not found:
                    raise Unsupported("No supported filesystem payload found in ZIP bundle")
        else:
            offset = 0
            found = 0
            while (offset := data.find(b"hsqs", offset)) >= 0:
                if len(data) - offset < 96:
                    break
                major, minor = struct.unpack_from("<HH", data, offset + 28)
                size = struct.unpack_from("<Q", data, offset + 40)[0]
                if major != 4 or minor != 0 or size < 96 or size > len(data) - offset:
                    offset += 4
                    continue
                self.squash(
                    data[offset : offset + size],
                    work,
                    prefix + (f"filesystem-{found}/" if found else ""),
                )
                self.payloads.append({"type": "squashfs", "offset": offset, "size": size})
                found += 1
                offset += size
                if found > 16:
                    raise ExtractionError("Embedded filesystem count exceeded")
            if not found:
                raise Unsupported(
                    "No valid SquashFS v4 or supported archive signature; encrypted, damaged, and other filesystems are unsupported"
                )
            if depth == 0:
                self.format = "squashfs" if data.startswith(b"hsqs") else "embedded-squashfs"

    def squash(self, data: bytes, work: Path, prefix: str) -> None:
        image = work / f"payload-{len(self.payloads)}.sqfs"
        image.write_bytes(data)
        listing = run_tool(["unsquashfs", "-lln", str(image)], self.limits, work).decode(
            "utf-8", "replace"
        )
        metadata: dict[str, tuple[int, int, int]] = {}
        for line in listing.splitlines():
            match = re.match(
                r"^([dlcbps-][rwxstST-]{9})\s+(\d+)/(\d+)\s+\S+(?:\s+\S+)?\s+\d{4}-\d\d-\d\d\s+\d\d:\d\d\s+squashfs-root(?:/(.*))?$",
                line,
            )
            if match and match[4]:
                name = match[4].split(" -> ", 1)[0]
                safe_path(name)
                perms = match[1]
                mode = sum(
                    bit
                    for char, bit in zip(perms[1:], [256, 128, 64, 32, 16, 8, 4, 2, 1], strict=True)
                    if char not in "-ST"
                )
                mode |= (
                    (0o4000 if perms[3] in "sS" else 0)
                    | (0o2000 if perms[6] in "sS" else 0)
                    | (0o1000 if perms[9] in "tT" else 0)
                )
                metadata[name] = (mode, int(match[2]), int(match[3]))
        if len(metadata) > self.limits.max_files:
            raise ExtractionError("SquashFS file-count limit exceeded")
        dest = work / f"squash-{len(self.payloads)}"
        try:
            run_tool(
                [
                    "unsquashfs",
                    "-no-progress",
                    "-processors",
                    "1",
                    "-no-xattrs",
                    "-d",
                    str(dest),
                    str(image),
                ],
                self.limits,
                work,
            )
        except ToolError as exc:
            # Squashfs-tools documents exit 2 as nonfatal: extraction continued.
            # Keep safe entries, record missing metadata/special files, never call it complete.
            if exc.returncode != 2 or not dest.is_dir():
                raise
            self.diagnostics.append(
                "PARTIAL EXTRACTION: unsquashfs reported nonfatal errors; permissions, links or special-file entries may be omitted"
            )
        for current, dirs, files in os.walk(dest, followlinks=False):
            for name in sorted(dirs + files):
                path = Path(current) / name
                relative = path.relative_to(dest).as_posix()
                info = path.lstat()
                mode, uid, gid = metadata.get(
                    relative, (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)
                )
                if stat.S_ISREG(info.st_mode):
                    path.chmod(0o600)
                    with path.open("rb") as stream:
                        self.add(prefix + relative, info.st_size, mode, uid, gid, source=stream)
                elif stat.S_ISDIR(info.st_mode):
                    path.chmod(0o700)
                    self.add(prefix + relative, 0, mode, uid, gid, "directory")
                else:
                    link = os.readlink(path) if path.is_symlink() else None
                    self.add(
                        prefix + relative,
                        0,
                        mode,
                        uid,
                        gid,
                        "symlink" if link is not None else "special",
                        link,
                    )
        if not metadata:
            self.diagnostics.append(
                "SquashFS original uid/gid listing unavailable; extracted metadata may be incomplete"
            )


def extract(image: Path, root: Path, work: Path, limits: Limits) -> Extraction:
    root.mkdir(mode=0o700)
    result = Extraction(root=root, limits=limits)
    try:
        result.unpack(image.read_bytes(), work)
    except (
        ExtractionError,
        ToolError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
        EOFError,
    ) as exc:
        result.diagnostics.append(str(exc))
        # Preserve already extracted safe files and make incomplete extraction explicit.
        if result.files:
            result.diagnostics.insert(0, "PARTIAL EXTRACTION")
        else:
            raise
    return result
