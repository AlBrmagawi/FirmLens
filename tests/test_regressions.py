import json
from pathlib import Path

import pytest

from firmwarelens.ai import retrieve
from firmwarelens.extraction import Extraction
from firmwarelens.redaction import clean
from firmwarelens.schemas import AIQuestion, AnalysisResult, Limits, Stage
from firmwarelens.tooling import ToolError


@pytest.mark.parametrize("exit_code", [1, 2])
def test_squashfs_nonfatal_retains_safe_files(tmp_path, monkeypatch, exit_code):
    from firmwarelens import extraction

    def fake_tool(argv, *args):
        if "-lln" in argv:
            return b"-rw-r--r-- 0/0 3 2023-11-14 22:13 squashfs-root/file\n"
        dest = Path(argv[argv.index("-d") + 1])
        dest.mkdir()
        (dest / "file").write_text("abc")
        raise ToolError("unsquashfs exited", returncode=exit_code)

    monkeypatch.setattr(extraction, "run_tool", fake_tool)
    root = tmp_path / "root"
    root.mkdir()
    unpacked = Extraction(root, Limits())
    if exit_code == 1:
        with pytest.raises(ToolError):
            unpacked.squash(b"fixture", tmp_path, "")
    else:
        unpacked.squash(b"fixture", tmp_path, "")
        assert (root / "file").read_text() == "abc"
        assert any("PARTIAL EXTRACTION" in d for d in unpacked.diagnostics)


def test_retrieval_budget_includes_coverage_and_structured_secrets():
    result = AnalysisResult(
        artifact_sha256="a" * 64,
        outcome="partial",
        format="tar",
        stages=[
            Stage(id="extraction", state="partial", message="x" * 20000, diagnostics=["y" * 20000])
        ],
        limitations=["z" * 20000] * 100,
    )
    payload, _ = retrieve(result, AIQuestion(question="coverage?"), 1000)
    assert len(json.dumps(payload)) <= 1000
    assert clean({"nested": {"admin_password": "DO_NOT_SEND", "api_key": "DO_NOT_SEND"}}) == {
        "nested": {"admin_password": "[REDACTED]", "api_key": "[REDACTED]"}
    }
