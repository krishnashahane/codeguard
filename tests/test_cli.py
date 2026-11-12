"""CLI behavior and machine-readable output tests."""
import json

from click.testing import CliRunner

from codeguardian import cli
from codeguardian.models import Category, Finding, ReviewResult, Severity


def test_json_mode_emits_only_json(monkeypatch):
    expected = ReviewResult(summary="Clean result", risk_score=0)
    monkeypatch.setattr(cli, "analyze", lambda *args, **kwargs: expected)
    result = CliRunner().invoke(cli.main, ["review", "--json"], input="diff text")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["summary"] == "Clean result"
    assert "Analyzing" not in result.output


def test_fail_on_exits_nonzero_for_matching_severity(monkeypatch):
    finding = Finding(
        file="app.py",
        line=2,
        severity=Severity.HIGH,
        category=Category.SECURITY,
        title="Risk",
    )
    monkeypatch.setattr(cli, "analyze", lambda *args, **kwargs: ReviewResult(findings=[finding], risk_score=15))
    result = CliRunner().invoke(cli.main, ["review", "--json", "--fail-on", "high"], input="diff text")
    assert result.exit_code == 1
    assert json.loads(result.output)["findings"][0]["severity"] == "high"


def test_cli_rejects_multiple_diff_sources(tmp_path):
    diff_file = tmp_path / "change.diff"
    diff_file.write_text("diff", encoding="utf-8")
    result = CliRunner().invoke(cli.main, ["review", str(diff_file), "--git"])
    assert result.exit_code != 0
    assert "Choose only one" in result.output
