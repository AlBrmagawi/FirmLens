import json

import httpx
import pytest
from typer.testing import CliRunner

from firmwarelens import cli


@pytest.mark.parametrize(
    ("status", "flags", "expected"),
    [
        ("complete", [], 0),
        ("failed", [], 2),
        ("complete", ["--fail-on", "high"], 3),
        ("partial", [], 4),
        ("partial", ["--allow-partial"], 0),
        ("queued", ["--no-wait", "--fail-on", "high"], 0),
    ],
)
def test_cli_exit_contract_and_long_default_filename(
    tmp_path, monkeypatch, status, flags, expected
):
    image = tmp_path / ("r" * 110 + ".img")
    image.write_bytes(b"trusted test fixture")
    calls = []

    def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        if path.endswith("/artifacts"):
            assert kwargs["content"].read() == b"trusted test fixture"
            return httpx.Response(201, json={"id": "a" * 64})
        assert kwargs["json"]["label"] == "r" * 100
        assert kwargs["headers"]["Idempotency-Key"] == "stable-retry"
        return httpx.Response(
            201,
            json={
                "id": "scan",
                "status": status,
                "summary": {"severity": {"critical": 0, "high": 1}},
            },
        )

    monkeypatch.setattr(cli, "request", request)
    result = CliRunner().invoke(
        cli.app,
        [
            "scan",
            str(image),
            "--project",
            "project",
            "--idempotency-key",
            "stable-retry",
            "--json",
            *flags,
        ],
    )
    assert result.exit_code == expected, result.output
    assert json.loads(result.output)["status"] == status
    assert len(calls) == 2


def test_cli_unavailable_service_has_actionable_exit(monkeypatch):
    monkeypatch.setenv("FL_TOKEN", "test-only")

    def unavailable(*args, **kwargs):
        raise httpx.ConnectError("PRIVATE_INTERNAL_DETAILS")

    monkeypatch.setattr(cli.httpx.Client, "request", unavailable)
    result = CliRunner().invoke(cli.app, ["project", "list"])
    assert result.exit_code == 5
    assert "API unavailable" in result.output
    assert "PRIVATE_INTERNAL_DETAILS" not in result.output
