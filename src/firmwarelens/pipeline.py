"""Shared analysis pipeline. The public entry point requires Linux isolation."""

import hashlib
import importlib.metadata
import json
import os
import resource
import signal
import sys
import time
from pathlib import Path
from typing import Literal

from firmwarelens import __version__
from firmwarelens.extraction import Unsupported, extract
from firmwarelens.plugins import (
    ComponentsPlugin,
    ConfigurationPlugin,
    Context,
    ELFPlugin,
    InventoryPlugin,
    Plugin,
    VulnerabilitiesPlugin,
)
from firmwarelens.schemas import AnalysisResult, ScanOptions, Stage, now


def progress(stage: str, message: str) -> None:
    print(
        json.dumps({"stage": stage, "message": message, "at": now()}), file=sys.stderr, flush=True
    )


def pipeline(image: Path, work: Path, options: ScanOptions) -> AnalysisResult:
    started = time.monotonic()
    sha = hashlib.file_digest(image.open("rb"), "sha256").hexdigest()
    result = AnalysisResult(
        artifact_sha256=sha,
        outcome="complete",
        format="unknown",
        manifest={
            "firmwarelens": __version__,
            "started_at": now(),
            "options": options.model_dump(),
            "python": sys.version.split()[0],
            "pyelftools": importlib.metadata.version("pyelftools"),
            "rules": "1.0.0",
            "invocations": [],
        },
    )
    progress("extraction", "Validating signatures and extracting within resource limits")
    try:
        extraction = extract(image, work / "root", work, options.limits)
        result.files = extraction.files
        result.payloads = extraction.payloads
        result.format = extraction.format
        partial = bool(extraction.diagnostics)
        result.stages.append(
            Stage(
                id="extraction",
                state="partial" if partial else "success",
                message=f"Extracted {len(result.files)} filesystem entries",
                diagnostics=extraction.diagnostics[:100],
            )
        )
        if partial:
            result.outcome = "partial"
    except Exception as exc:
        result.outcome = "unsupported" if isinstance(exc, Unsupported) else "failed"
        result.stages.append(
            Stage(
                id="extraction",
                state="unsupported" if isinstance(exc, Unsupported) else "failure",
                message=str(exc)[:500],
            )
        )
        result.manifest["finished_at"] = now()
        return result
    context = Context(root=work / "root", work=work, result=result, limits=options.limits)
    plugins: list[Plugin] = [
        InventoryPlugin(),
        ConfigurationPlugin(),
        ELFPlugin(),
        ComponentsPlugin(),
        VulnerabilitiesPlugin(),
    ]
    for plugin in plugins:
        if (
            plugin.id == "components"
            and not options.components
            or plugin.id == "vulnerabilities"
            and (not options.vulnerabilities or result.native_inventory is None)
        ):
            result.stages.append(
                Stage(
                    id=plugin.id,
                    state="skipped",
                    message="Disabled in scan options or required component inventory unavailable",
                )
            )
            result.outcome = "partial"
            continue
        progress(plugin.id, f"Running {plugin.id} {plugin.version}")
        tick = time.monotonic()
        result.manifest["invocations"].append(
            {
                "plugin": plugin.id,
                "version": plugin.version,
                "inputs": plugin.inputs,
                "capabilities": plugin.capabilities,
                "timeout_seconds": options.limits.tool_timeout,
                "at": now(),
            }
        )

        def expired(signum: int, frame: object) -> None:
            raise TimeoutError("Analyzer exceeded stage timeout")

        previous = signal.signal(signal.SIGALRM, expired)
        signal.alarm(options.limits.tool_timeout + 5)
        try:
            message = plugin.run(context)
            state: Literal["success", "failure"] = "success"
        except Exception as exc:
            # Never include parser exception text; it may echo secret firmware strings.
            message = f"{plugin.id} did not complete ({type(exc).__name__}); inspect coverage and tool/database availability"
            if plugin.id == "vulnerabilities" and not result.manifest.get("intelligence", {}).get(
                "available"
            ):
                message = "Local vulnerability database unavailable; run firmwarelens intelligence update/import. No vulnerability assessment was completed."
            state = "failure"
            result.outcome = "partial"
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        result.stages.append(
            Stage(
                id=plugin.id,
                version=plugin.version,
                state=state,
                message=message,
                duration_ms=round((time.monotonic() - tick) * 1000),
            )
        )
    result.manifest.update(
        {
            "finished_at": now(),
            "duration_ms": round((time.monotonic() - started) * 1000),
            "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "child_peak_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        }
    )
    return result


def assert_isolation() -> None:
    if (
        sys.platform != "linux"
        or os.getuid() == 0
        or not Path("/etc/firmwarelens-sandbox").is_file()
    ):
        raise RuntimeError("Analysis requires the FirmwareLens non-root Linux sandbox")
    status = Path("/proc/self/status").read_text()
    if "NoNewPrivs:\t1" not in status or "CapEff:\t0000000000000000" not in status:
        raise RuntimeError("Sandbox privilege restrictions missing")
    if set(os.listdir("/sys/class/net")) - {"lo"}:
        raise RuntimeError("Analysis sandbox must have no network interface")
    if not os.statvfs("/").f_flag & os.ST_RDONLY:
        raise RuntimeError("Sandbox root filesystem must be read-only")


def main() -> None:
    assert_isolation()
    image = Path("/input/firmware")
    expected = os.environ["FL_EXPECTED_SHA256"]
    with image.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise RuntimeError("Immutable input integrity check failed")
    options = ScanOptions.model_validate_json(os.environ.get("FL_SCAN_OPTIONS", "{}"))
    result = pipeline(image, Path("/work"), options)
    payload = result.model_dump_json()
    if len(payload.encode()) > options.limits.max_output:
        raise RuntimeError("Normalized analysis output exceeds promotion budget")
    print(payload)


if __name__ == "__main__":
    main()
