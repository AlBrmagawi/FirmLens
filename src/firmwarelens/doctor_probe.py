"""Fixed sandbox self-test. Never receives firmware or arbitrary commands."""

import json
from pathlib import Path

from firmwarelens.pipeline import assert_isolation
from firmwarelens.schemas import Limits
from firmwarelens.tooling import run_tool


def main():
    assert_isolation()
    tools = {}
    for name, argv in [
        ("syft", ["syft", "version", "-o", "json"]),
        ("grype", ["grype", "version", "-o", "json"]),
        ("unsquashfs", ["unsquashfs", "-version"]),
    ]:
        output = run_tool(
            argv,
            Limits(tool_timeout=5),
            Path("/work"),
            allowed_exit_codes=(0, 1) if name == "unsquashfs" else (0,),
        )
        if name in ("syft", "grype"):
            tools[name] = json.loads(output)["version"]
        else:
            tools[name] = output.decode().splitlines()[0]
            if not tools[name].startswith("unsquashfs version"):
                raise RuntimeError("Unexpected unsquashfs version response")
    print(
        json.dumps(
            {
                "tools": tools,
                "probe": "non-root, read-only root, empty capabilities, no-new-privileges, network-none verified",
            }
        )
    )


if __name__ == "__main__":
    main()
