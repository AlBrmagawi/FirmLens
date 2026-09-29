"""Trusted Docker supervisor interface. No command, image, or host path from requests."""

import json
import re
import threading
import time
from collections.abc import Callable

import docker

from firmwarelens.config import Settings
from firmwarelens.extraction import safe_path
from firmwarelens.schemas import AnalysisResult, ScanOptions


class SandboxError(RuntimeError):
    pass


class Cancelled(SandboxError):
    pass


_probe_cache: dict[str, dict] = {}


def capabilities(client, config: Settings) -> dict:
    info = client.info()
    required = {
        "linux": info.get("OSType") == "linux",
        "memory_limit": info.get("MemoryLimit", False),
        "cpu_limit": info.get("CpuCfsQuota", False),
        "pids_limit": info.get("PidsLimit", False),
        "seccomp": any("seccomp" in s for s in info.get("SecurityOptions", [])),
        "cgroup_v2": info.get("CgroupVersion") == "2",
    }
    try:
        img = client.images.get(config.sandbox_image)
        required["sandbox_image"] = bool(img.id)
        image_id = img.id
    except docker.errors.ImageNotFound:
        required["sandbox_image"] = False
        image_id = "missing"
    probe = {}
    if all(required.values()):
        try:
            if image_id not in _probe_cache:
                output = client.containers.run(
                    image_id,
                    entrypoint=["python", "-m", "firmwarelens.doctor_probe"],
                    network_mode="none",
                    user="65532:65532",
                    read_only=True,
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    mem_limit="384m",
                    memswap_limit="384m",
                    nano_cpus=1_000_000_000,
                    pids_limit=32,
                    tmpfs={
                        "/work": "rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=700"
                    },
                    remove=True,
                )
                _probe_cache[image_id] = json.loads(output)
            probe = _probe_cache[image_id]
            required["isolation_probe"] = True
        except Exception:
            required["isolation_probe"] = False
            probe = {
                "error": "Sandbox self-test failed; rebuild matching sandbox and application images"
            }
    return {
        "checks": required,
        "ready": all(required.values()),
        "engine": info.get("ServerVersion"),
        "image": image_id,
        **probe,
    }


def validate_result(raw: bytes, expected: str, options: ScanOptions) -> AnalysisResult:
    if len(raw) > options.limits.max_output:
        raise SandboxError("Sandbox output exceeded promotion limit")
    result = AnalysisResult.model_validate_json(raw)
    if result.artifact_sha256 != expected or len(result.files) > options.limits.max_files:
        raise SandboxError("Output identity or inventory limit mismatch")
    seen: set[str] = set()
    for file in result.files:
        safe_path(file.path)
        if file.path in seen or file.size < 0:
            raise SandboxError("Invalid output file inventory")
        seen.add(file.path)
    evidence = {e.id for e in result.evidence}
    if len(evidence) != len(result.evidence) or len({f.id for f in result.findings}) != len(
        result.findings
    ):
        raise SandboxError("Duplicate result identities")
    if any(not set(f.evidence_ids) <= evidence for f in result.findings):
        raise SandboxError("Finding refers to missing evidence")
    return result


def run_sandbox(
    config: Settings,
    scan_id: str,
    artifact_id: str,
    options: ScanOptions,
    heartbeat: Callable[[], bool],
    event: Callable[[str, str], None],
) -> AnalysisResult:
    if not re.fullmatch(r"[0-9a-f-]{36}", scan_id) or not re.fullmatch(
        r"[0-9a-f]{64}", artifact_id
    ):
        raise SandboxError("Invalid internal job identity")
    client = docker.from_env(timeout=15)
    health = capabilities(client, config)
    if not health["ready"]:
        raise SandboxError(
            "Required sandbox isolation unavailable: " + json.dumps(health["checks"])
        )
    for stale in client.containers.list(
        all=True, filters={"label": ["firmwarelens.role=analysis", f"firmwarelens.scan={scan_id}"]}
    ):
        stale.remove(force=True)
    mounts = [
        docker.types.Mount(
            target="/input", source=config.data_volume, type="volume", read_only=True
        ),
        docker.types.Mount(
            target="/intelligence",
            source=config.intelligence_volume,
            type="volume",
            read_only=True,
            no_copy=True,
        ),
    ]
    mounts[0]["VolumeOptions"] = {"Subpath": f"artifacts/{artifact_id}"}
    container = client.containers.create(
        health["image"],
        name=f"firmwarelens-{scan_id}",
        network_mode="none",
        user="65532:65532",
        read_only=True,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        mem_limit="1536m",
        memswap_limit="1536m",
        nano_cpus=1_000_000_000,
        pids_limit=64,
        mounts=mounts,
        init=True,
        tmpfs={
            "/work": "rw,noexec,nosuid,nodev,size=805306368,uid=65532,gid=65532,mode=700",
            "/tmp": "rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=700",  # noqa: S108
        },
        environment={
            "FL_EXPECTED_SHA256": artifact_id,
            "FL_SCAN_OPTIONS": options.model_dump_json(),
        },
        labels={"firmwarelens.role": "analysis", "firmwarelens.scan": scan_id},
        ulimits=[
            docker.types.Ulimit(name="nofile", soft=256, hard=256),
            docker.types.Ulimit(
                name="fsize", soft=options.limits.max_bytes, hard=options.limits.max_bytes
            ),
            docker.types.Ulimit(name="core", soft=0, hard=0),
        ],
        log_config=docker.types.LogConfig(
            type="json-file", config={"max-size": "40m", "max-file": "1"}
        ),
    )
    chunks: list[bytes] = []
    errors: list[str] = []
    limit_hit = threading.Event()

    def collect() -> None:
        total = 0
        try:
            for chunk in container.logs(stdout=True, stderr=False, stream=True, follow=True):
                total += len(chunk)
                if total > options.limits.max_output:
                    limit_hit.set()
                    return
                chunks.append(chunk)
        except Exception:
            errors.append("Could not read bounded sandbox output")

    started = time.monotonic()
    last_stages: set[str] = set()
    try:
        container.start()
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        while True:
            if heartbeat():
                raise Cancelled("Analysis cancelled")
            if time.monotonic() - started > config.job_timeout:
                raise SandboxError(f"Job exceeded {config.job_timeout}s wall-time limit")
            if limit_hit.is_set():
                raise SandboxError("Analyzer output-size limit exceeded")
            for line in (
                container.logs(stdout=False, stderr=True, tail=30)
                .decode("utf-8", "replace")
                .splitlines()
            ):
                try:
                    item = json.loads(line)
                    stage = item.get("stage")
                    if (
                        stage
                        in {
                            "extraction",
                            "inventory",
                            "configuration",
                            "elf",
                            "components",
                            "vulnerabilities",
                        }
                        and stage not in last_stages
                    ):
                        event(stage, f"Running {stage}")
                        last_stages.add(stage)
                except (ValueError, AttributeError):
                    pass
            container.reload()
            if container.status in ("exited", "dead"):
                break
            time.sleep(0.5)
        reader.join(timeout=10)
        if reader.is_alive() or errors or limit_hit.is_set():
            raise SandboxError("Sandbox output stream failed or exceeded limits")
        state = container.attrs["State"]
        if state.get("OOMKilled"):
            raise SandboxError("Analysis exceeded memory limit")
        if state.get("ExitCode") != 0:
            raise SandboxError(
                "Analysis container failed; inspect sandbox/tool compatibility or increase bounded limits"
            )
        result = validate_result(b"".join(chunks), artifact_id, options)
        result.manifest["sandbox"] = {
            **health,
            "network": "none",
            "uid": 65532,
            "memory_mib": 1536,
            "scratch_mib": 768,
            "cpus": 1,
            "pids": 64,
            "wall_seconds": round(time.monotonic() - started, 3),
        }
        return result
    finally:
        container.remove(force=True)
        client.close()
