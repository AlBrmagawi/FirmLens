import sys

import pytest

from firmwarelens.schemas import Limits
from firmwarelens.tooling import ToolError, run_tool


def test_tool_timeout(tmp_path):
    with pytest.raises(ToolError, match="timeout"):
        run_tool(
            [sys.executable, "-c", "import time; time.sleep(10)"], Limits(tool_timeout=1), tmp_path
        )


def test_tool_output_bomb(tmp_path):
    with pytest.raises(ToolError, match="output"):
        run_tool([sys.executable, "-c", "print('x' * 100000)"], Limits(max_output=1024), tmp_path)


def test_missing_tool_and_crash(tmp_path):
    with pytest.raises(ToolError, match="unavailable"):
        run_tool(["missing-firmwarelens-test-tool"], Limits(), tmp_path)
    with pytest.raises(ToolError, match="exited"):
        run_tool(
            [sys.executable, "-c", "raise ValueError('SENSITIVE_FIRMWARE_VALUE')"],
            Limits(),
            tmp_path,
        )
