"""Bounded external tool execution; argv is application-owned, never firmware commands."""

import os
import subprocess
import tempfile
import time
from pathlib import Path

from firmwarelens.schemas import Limits


class ToolError(RuntimeError):
    def __init__(self, message: str, returncode: int | None = None):
        super().__init__(message)
        self.returncode = returncode


def run_tool(
    argv: list[str],
    limits: Limits,
    cwd: Path,
    env: dict[str, str] | None = None,
    *,
    allowed_exit_codes: tuple[int, ...] = (0,),
) -> bytes:
    safe_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(cwd),
        "LANG": "C.UTF-8",
        "TMPDIR": str(cwd),
    }
    safe_env.update(env or {})
    with tempfile.TemporaryFile(dir=cwd) as out, tempfile.TemporaryFile(dir=cwd) as err:
        try:
            process = subprocess.Popen(  # noqa: S603 — fixed tool argv, no shell
                argv, cwd=cwd, env=safe_env, stdout=out, stderr=err, start_new_session=True
            )
        except FileNotFoundError as exc:
            raise ToolError(f"Required tool unavailable: {argv[0]}") from exc
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - started > limits.tool_timeout:
                    raise ToolError(f"{argv[0]} exceeded {limits.tool_timeout}s timeout")
                if (
                    os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size
                    > limits.max_output
                ):
                    raise ToolError(f"{argv[0]} exceeded output limit")
                time.sleep(0.03)
            if os.fstat(out.fileno()).st_size + os.fstat(err.fileno()).st_size > limits.max_output:
                raise ToolError(f"{argv[0]} exceeded output limit")
            if process.returncode not in allowed_exit_codes:
                # Tool stderr may contain secrets or malicious filenames; never promote it.
                raise ToolError(
                    f"{argv[0]} exited {process.returncode}; input may be damaged or unsupported",
                    returncode=process.returncode,
                )
            out.seek(0)
            return out.read(limits.max_output + 1)
        finally:
            if process.poll() is None:
                import signal

                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
