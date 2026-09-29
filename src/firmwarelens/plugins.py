"""Typed, versioned analysis plugins. All implementations are sandbox-only."""

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Literal, Protocol, cast

from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.segments import InterpSegment

from firmwarelens.redaction import clean, redact
from firmwarelens.schemas import (
    AnalysisResult,
    Component,
    Evidence,
    FileRecord,
    Finding,
    Limits,
    Severity,
    identity,
)
from firmwarelens.tooling import ToolError, run_tool


@dataclass
class Context:
    root: Path
    work: Path
    result: AnalysisResult
    limits: Limits

    def evidence(
        self,
        file: FileRecord,
        analyzer: str,
        key: str,
        excerpt: str = "",
        line: int | None = None,
        observation: dict | None = None,
    ) -> str:
        eid = identity(analyzer, file.path, key, str(line))
        if not any(e.id == eid for e in self.result.evidence):
            self.result.evidence.append(
                Evidence(
                    id=eid,
                    path=file.path,
                    artifact_sha256=file.sha256 or self.result.artifact_sha256,
                    line=line,
                    key=key,
                    excerpt=redact(excerpt[:2000], file.path),
                    observation=clean(observation or {}),
                    analyzer=analyzer,
                )
            )
        return eid

    def finding(
        self,
        file: FileRecord,
        rule: str,
        title: str,
        severity: Severity,
        explanation: str,
        remediation: str,
        evidence_id: str,
        analyzer: str = "configuration",
        confidence: Literal["high", "medium", "low"] = "high",
        key: str = "",
    ) -> None:
        fingerprint = identity(rule, file.path, key)
        if any(f.fingerprint == fingerprint for f in self.result.findings):
            return
        self.result.findings.append(
            Finding(
                id=fingerprint,
                fingerprint=fingerprint,
                rule_id=rule,
                title=title,
                category="hardening" if analyzer == "elf" else "configuration",
                severity=severity,
                confidence=confidence,
                path=file.path,
                evidence_ids=[evidence_id],
                explanation=explanation,
                remediation=remediation,
                analyzer=analyzer,
            )
        )


class Plugin(Protocol):
    id: ClassVar[str]
    version: ClassVar[str]
    inputs: ClassVar[tuple[str, ...]]
    capabilities: ClassVar[tuple[str, ...]]

    def run(self, context: Context) -> str: ...


class InventoryPlugin:
    id: ClassVar[str] = "inventory"
    version: ClassVar[str] = "1.0.0"
    inputs: ClassVar[tuple[str, ...]] = ("filesystem",)
    capabilities: ClassVar[tuple[str, ...]] = ("file-inventory", "redacted-preview", "os-hints")

    def run(self, context: Context) -> str:
        for file in context.result.files:
            if file.kind != "file":
                continue
            path = context.root / file.path
            with path.open("rb") as stream:
                head = stream.read(65536)
            file.role = (
                "elf"
                if head.startswith(b"\x7fELF")
                else "startup"
                if any(v in file.path for v in ("etc/init.d/", "etc/rc", "systemd/system/"))
                else "configuration"
                if file.path.startswith("etc/") or "/etc/" in file.path
                else "other"
            )
            if b"\x00" not in head:
                file.preview = redact(head.decode("utf-8", "replace"), file.path)[:16384]
            if file.path.endswith("etc/os-release") and file.preview:
                context.result.manifest.setdefault("os_hints", []).append(
                    {"path": file.path, "text": file.preview[:2000]}
                )
        return f"Inventoried {len(context.result.files)} entries; text previews bounded to 16 KiB and redacted"


class ConfigurationPlugin:
    id: ClassVar[str] = "configuration"
    version: ClassVar[str] = "1.0.0"
    inputs: ClassVar[tuple[str, ...]] = ("filesystem", "original-metadata")
    capabilities: ClassVar[tuple[str, ...]] = (
        "credentials",
        "ssh",
        "startup-services",
        "permissions",
    )

    def run(self, context: Context) -> str:
        before = len(context.result.findings)
        for file in context.result.files:
            if file.kind == "directory":
                if file.mode & 0o002 and any(
                    p in file.path for p in ("etc/init.d", "etc/rc", "systemd/system")
                ):
                    eid = context.evidence(
                        file, self.id, "mode", observation={"original_mode": oct(file.mode)}
                    )
                    context.finding(
                        file,
                        "PERM-002",
                        "World-writable startup directory",
                        Severity.high,
                        "An unprivileged writer may alter startup configuration; actual boot behavior requires validation.",
                        "Remove world-write permission and audit ownership.",
                        eid,
                    )
                continue
            if file.kind != "file":
                continue
            if (
                file.mode & 0o002
                and ("/etc/" in "/" + file.path or file.role == "startup")
                or file.path.endswith("etc/shadow")
                and file.mode & 0o007
            ):
                eid = context.evidence(
                    file,
                    self.id,
                    "mode",
                    observation={"original_mode": oct(file.mode), "uid": file.uid, "gid": file.gid},
                )
                context.finding(
                    file,
                    "PERM-001",
                    "Unsafe permissions on security-sensitive file",
                    Severity.high,
                    "Original filesystem metadata grants world access incompatible with this sensitive file's role.",
                    "Restrict permissions and confirm required service ownership.",
                    eid,
                )
            if file.size > 1048576:
                continue
            raw = (context.root / file.path).read_bytes()
            if b"\x00" in raw:
                continue
            text = raw.decode("utf-8", "replace")
            if "-----BEGIN " in text and "PRIVATE KEY-----" in text:
                eid = context.evidence(
                    file,
                    self.id,
                    "private-key",
                    "[REDACTED PRIVATE KEY]",
                    observation={"private_key_marker_present": True},
                )
                context.finding(
                    file,
                    "CRED-002",
                    "Embedded private-key material",
                    Severity.high,
                    "Private-key markers are present. Synthetic keys and intended trust anchors require analyst review.",
                    "Remove shared private keys; provision unique keys per device and rotate exposed keys.",
                    eid,
                    confidence="medium",
                )
            first: set[tuple[str, str]] = set()
            section = "global"
            for line_number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", ";")):
                    continue
                if file.path.endswith(("etc/shadow", "etc/passwd")):
                    fields = line.split(":")
                    if len(fields) >= 3 and fields[1] == "":
                        eid = context.evidence(
                            file,
                            self.id,
                            f"account:{fields[0]}",
                            line=line_number,
                            observation={"account": fields[0], "password_field": "empty"},
                        )
                        context.finding(
                            file,
                            "AUTH-001",
                            "Account has an empty password field",
                            Severity.high,
                            "An empty account password field was parsed. Whether login is possible depends on the authentication stack.",
                            "Lock unused accounts and require provisioned credentials.",
                            eid,
                            key=fields[0],
                        )
                if file.path.endswith("sshd_config") or "sshd_config.d/" in file.path:
                    parts = re.split(r"\s+|=", stripped.split("#", 1)[0], maxsplit=1)
                    if len(parts) == 2:
                        directive, value = parts[0].lower(), parts[1].strip().lower()
                        if directive == "match":
                            section = f"match:{value}"
                        if (section, directive) in first:
                            continue
                        first.add((section, directive))
                        risky = {
                            "permitrootlogin": "yes",
                            "passwordauthentication": "yes",
                            "permitemptypasswords": "yes",
                        }
                        if risky.get(directive) == value:
                            eid = context.evidence(
                                file,
                                self.id,
                                f"{section}:{directive}",
                                line,
                                line_number,
                                {
                                    "directive": directive,
                                    "value": value,
                                    "scope": section,
                                    "effective_policy": "requires validation of Include/Match and daemon invocation",
                                },
                            )
                            context.finding(
                                file,
                                "SSH-001",
                                f"SSH configuration permits {directive}",
                                Severity.high
                                if directive != "passwordauthentication"
                                else Severity.medium,
                                "A risky SSH directive is configured. Include order, Match conditions, and runtime options may change effective policy.",
                                "Restrict SSH to approved keys and accounts; validate effective configuration on the authorized device.",
                                eid,
                                confidence="medium",
                                key=f"{section}:{directive}",
                            )
                if file.role == "startup" or file.path.endswith(("inetd.conf", "inittab")):
                    if re.search(
                        r"(?:^|[\s/=])(?:telnetd|in\.telnetd)(?:\s|$)", stripped.split("#", 1)[0]
                    ):
                        eid = context.evidence(
                            file,
                            self.id,
                            "telnet-startup",
                            line,
                            line_number,
                            {"configured_start": True, "reachability": "unknown"},
                        )
                        context.finding(
                            file,
                            "SVC-001",
                            "Telnet configured in startup or service definition",
                            Severity.high,
                            "An active configuration line invokes a Telnet daemon. This does not establish reachability.",
                            "Disable Telnet startup and use authenticated, encrypted administration.",
                            eid,
                        )
                secret = re.search(
                    r"(?i)\b((?:[\w.-]*[_.-])?(?:password|passwd|secret|api[_-]?key|psk))\b[\"']?\s*[:=]\s*[\"']?([^\s\"';#]+)",
                    stripped,
                )
                if (
                    secret
                    and secret[2].lower()
                    not in ("no", "yes", "false", "true", "null", "none", "[redacted]")
                    and not secret[2].startswith(("$", "${"))
                ):
                    eid = context.evidence(
                        file,
                        self.id,
                        secret[1].lower(),
                        "[REDACTED suspected credential assignment]",
                        line_number,
                        {"key": secret[1], "value_present": True},
                    )
                    context.finding(
                        file,
                        "CRED-001",
                        "Suspected embedded credential",
                        Severity.high,
                        "A credential-like assignment contains a literal value. This heuristic may identify non-secret examples.",
                        "Remove shared credentials, provision unique secrets, and rotate any real exposed values.",
                        eid,
                        confidence="medium",
                        key=secret[1].lower(),
                    )
        return f"Produced {len(context.result.findings) - before} configuration and credential findings"


def inspect_elf(path: Path) -> dict:
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.num_sections() > 8192 or elf.num_segments() > 4096:
            raise ValueError("ELF table count exceeds parser budget")
        segments = list(elf.iter_segments())
        interpreter = next(
            (s.get_interp_name() for s in segments if isinstance(s, InterpSegment)), None
        )
        stack = next((s for s in segments if s["p_type"] == "PT_GNU_STACK"), None)
        relro = any(s["p_type"] == "PT_GNU_RELRO" for s in segments)
        libraries: list[str] = []
        symbols: set[str] = set()
        bind_now = False
        pie_flag = False
        symtab = False
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                symtab |= section["sh_type"] == "SHT_SYMTAB"
                if section.num_symbols() > 100000:
                    raise ValueError("ELF symbol count exceeds parser budget")
                symbols.update(s.name for s in section.iter_symbols())
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        libraries.append(cast(Any, tag).needed)
                    if (
                        tag.entry.d_tag == "DT_BIND_NOW"
                        or tag.entry.d_tag == "DT_FLAGS"
                        and tag.entry.d_val & 8
                        or tag.entry.d_tag == "DT_FLAGS_1"
                        and tag.entry.d_val & 1
                    ):
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 0x8000000:
                        pie_flag = True
        file_type = elf.header["e_type"]
        return {
            "architecture": elf.get_machine_arch(),
            "machine": elf.header["e_machine"],
            "bits": elf.elfclass,
            "endianness": "little" if elf.little_endian else "big",
            "type": file_type,
            "interpreter": interpreter,
            "pie": "yes"
            if file_type == "ET_DYN" and (interpreter or pie_flag)
            else "no"
            if file_type == "ET_EXEC"
            else "not-applicable"
            if file_type == "ET_REL"
            else "unknown",
            "nx_stack": "unknown" if stack is None else "no" if stack["p_flags"] & 1 else "yes",
            "relro": "full"
            if relro and bind_now
            else "partial"
            if relro
            else "none"
            if file_type in ("ET_DYN", "ET_EXEC")
            else "not-applicable",
            "canary": "indicator-present"
            if symbols & {"__stack_chk_fail", "__stack_chk_guard", "__stack_chk_fail_local"}
            else "unknown",
            "stripped": not symtab,
            "libraries": sorted(libraries)[:100],
            "symbol_count": len(symbols),
            "symbols": sorted(symbols)[:200],
        }


class ELFPlugin:
    id: ClassVar[str] = "elf"
    version: ClassVar[str] = "1.0.0"
    inputs: ClassVar[tuple[str, ...]] = ("filesystem",)
    capabilities: ClassVar[tuple[str, ...]] = ("elf-metadata", "hardening")

    def run(self, context: Context) -> str:
        count = 0
        errors = 0
        for file in context.result.files:
            if file.role != "elf":
                continue
            try:
                file.elf = inspect_elf(context.root / file.path)
            except Exception:  # A malformed binary must not hide results for other files.
                file.elf = {"error": "Malformed or unsupported ELF metadata", "canary": "unknown"}
                errors += 1
                continue
            count += 1
            for key, bad, rule, title, severity in [
                ("pie", "no", "ELF-001", "Executable is not position independent", Severity.medium),
                ("nx_stack", "no", "ELF-002", "ELF requests an executable stack", Severity.high),
                ("relro", "none", "ELF-003", "ELF has no RELRO segment", Severity.medium),
                ("relro", "partial", "ELF-004", "ELF has partial RELRO", Severity.low),
            ]:
                if file.elf[key] == bad:
                    eid = context.evidence(
                        file,
                        self.id,
                        key,
                        observation={key: bad, "architecture": file.elf["architecture"]},
                    )
                    context.finding(
                        file,
                        rule,
                        title,
                        severity,
                        "ELF metadata indicates reduced defense in depth; this is not proof of an exploitable vulnerability.",
                        "Rebuild with appropriate PIE, non-executable stack, and full RELRO linker/compiler options, then verify on target.",
                        eid,
                        analyzer=self.id,
                    )
        if errors:
            raise ToolError(
                f"Parsed {count} ELF files; {errors} malformed binaries could not be inspected (other results retained)"
            )
        return f"Inspected {count} ELF files; absent canary symbols are reported as unknown"


def tool_env() -> dict[str, str]:
    return {
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_DB_CACHE_DIR": "/intelligence",
        "GRYPE_DB_VALIDATE_AGE": "false",
    }


class ComponentsPlugin:
    id: ClassVar[str] = "components"
    version: ClassVar[str] = "1.0.0"
    inputs: ClassVar[tuple[str, ...]] = ("filesystem",)
    capabilities: ClassVar[tuple[str, ...]] = ("syft-inventory", "cyclonedx")

    def run(self, context: Context) -> str:
        native_path = context.work / "syft.json"
        sbom_path = context.work / "cyclonedx.json"
        config = context.work / "syft-config.yaml"
        config.write_text("check-for-app-update: false\n", encoding="utf-8")
        run_tool(
            [
                "syft",
                "scan",
                f"dir:{context.root}",
                "--config",
                str(config),
                "-o",
                f"syft-json={native_path}",
                "-o",
                f"cyclonedx-json={sbom_path}",
            ],
            context.limits,
            context.work,
            tool_env(),
        )
        if native_path.stat().st_size + sbom_path.stat().st_size > context.limits.max_output:
            raise ToolError("Syft inventory exceeds output budget")
        native = json.loads(native_path.read_text())
        context.result.native_inventory = clean(native)
        context.result.sbom = clean(json.loads(sbom_path.read_text()))
        context.result.manifest["syft"] = native.get("descriptor", {}).get("version", "unknown")
        files = {file.path: file for file in context.result.files}
        for package in native.get("artifacts", [])[: context.limits.max_files]:
            locations = [
                loc.get("path", "").removeprefix(str(context.root)).lstrip("/")
                for loc in package.get("locations", [])
            ]
            component = Component(
                id=package["id"],
                name=package["name"],
                version=package.get("version", ""),
                ecosystem=package.get("type", "unknown"),
                purl=package.get("purl", ""),
                locations=locations,
                identity_method="heuristic-binary"
                if package.get("type") == "binary"
                else "package-metadata",
            )
            for location in locations:
                file = files.get(location)
                if file:
                    component.evidence_ids.append(
                        context.evidence(
                            file,
                            self.id,
                            component.id,
                            observation={
                                "name": component.name,
                                "version": component.version,
                                "method": component.identity_method,
                                "cataloger": package.get("foundBy", "unknown"),
                            },
                        )
                    )
            context.result.components.append(component)
        return f"Syft identified {len(context.result.components)} components; binary cataloger hints remain heuristic"


class VulnerabilitiesPlugin:
    id: ClassVar[str] = "vulnerabilities"
    version: ClassVar[str] = "1.0.0"
    inputs: ClassVar[tuple[str, ...]] = ("syft-inventory", "local-grype-database")
    capabilities: ClassVar[tuple[str, ...]] = ("vulnerability-matching",)

    def run(self, context: Context) -> str:
        config = context.work / "grype-config.yaml"
        config.write_text(
            "check-for-app-update: false\ndb:\n  auto-update: false\n  cache-dir: /intelligence\n  validate-age: false\n",
            encoding="utf-8",
        )
        base = ["grype", "--config", str(config)]
        try:
            status = json.loads(
                run_tool(
                    [*base, "db", "status", "-o", "json"], context.limits, context.work, tool_env()
                )
            )
        except ToolError as exc:
            context.result.manifest["intelligence"] = {
                "available": False,
                "message": "Prepare a local database with firmwarelens intelligence update or import",
            }
            raise ToolError(
                "Vulnerability intelligence unavailable; matching did not run, not zero vulnerabilities"
            ) from exc
        identity_files = sorted(Path("/intelligence").rglob("*.db"))
        database_hash = hashlib.sha256()
        for file in identity_files:
            with file.open("rb") as stream:
                while chunk := stream.read(1048576):
                    database_hash.update(chunk)
        db = {
            "available": True,
            "status": clean(status),
            "sha256": database_hash.hexdigest(),
            "freshness": "unknown",
        }
        built = status.get("built") or status.get("buildTime")
        if built:
            from datetime import datetime

            try:
                age = (
                    time.time() - datetime.fromisoformat(built.replace("Z", "+00:00")).timestamp()
                ) / 86400
                db["age_days"] = round(age, 2)
                db["freshness"] = "stale" if age > 5 else "fresh"
            except ValueError:
                pass
        context.result.manifest["intelligence"] = db
        result = json.loads(
            run_tool(
                [*base, f"sbom:{context.work / 'syft.json'}", "-o", "json"],
                context.limits,
                context.work,
                tool_env(),
            )
        )
        context.result.manifest["grype"] = result.get("descriptor", {}).get("version", "unknown")
        components = {c.id: c for c in context.result.components}
        for match in result.get("matches", []):
            advisory = match["vulnerability"]
            component = components.get(match["artifact"]["id"])
            if component is None:
                continue
            fingerprint = identity(
                "VULN-001",
                advisory["id"],
                component.purl.split("@")[0] or component.name,
                component.ecosystem,
            )
            if any(f.fingerprint == fingerprint for f in context.result.findings):
                continue
            methods = [m.get("type", "unknown") for m in match.get("matchDetails", [])]
            confidence: Literal["high", "medium", "low"] = (
                "low"
                if component.identity_method == "heuristic-binary"
                or any("cpe" in m for m in methods)
                else "high"
            )
            severity = advisory.get("severity", "info").lower()
            context.result.findings.append(
                Finding(
                    id=fingerprint,
                    fingerprint=fingerprint,
                    rule_id="VULN-001",
                    title=f"{advisory['id']} matches {component.name} {component.version}",
                    category="vulnerability",
                    severity=severity if severity in Severity._value2member_map_ else Severity.info,
                    confidence=confidence,
                    path=component.locations[0] if component.locations else "",
                    component_id=component.id,
                    evidence_ids=component.evidence_ids,
                    explanation="Grype matched component metadata against local advisory constraints. Distribution backports and device applicability require validation; a version match is not proof of exploitability.",
                    remediation="Review the vendor/distribution advisory and fixed versions; validate the actual build before upgrading or mitigating.",
                    analyzer=self.id,
                    references=[advisory["dataSource"]]
                    if str(advisory.get("dataSource", "")).startswith("https://")
                    else [],
                    details=clean(
                        {
                            "advisory": advisory,
                            "match_details": match.get("matchDetails", []),
                            "identity_method": component.identity_method,
                            "database": db["sha256"],
                        }
                    ),
                )
            )
        return f"Grype completed advisory matching; database freshness: {db['freshness']}"
