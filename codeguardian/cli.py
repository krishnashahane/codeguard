"""CLI interface for CodeGuardian."""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from codeguardian.core.analyzer import analyze
from codeguardian.models import ReviewResult, Severity

console = Console()
SEVERITY_COLORS = {Severity.CRITICAL: "bold red", Severity.HIGH: "red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}
SEVERITY_ICONS = {Severity.CRITICAL: "[bold red]X[/]", Severity.HIGH: "[red]![/]", Severity.MEDIUM: "[yellow]~[/]", Severity.LOW: "[cyan]-[/]", Severity.INFO: "[dim].[/]"}

@click.group()
@click.version_option(package_name="codeguardian")
def main() -> None:
    """CodeGuardian - pull-request review and static analysis."""

@main.command()
@click.argument("diff_file", required=False, type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path))
@click.option("--git", "use_git", is_flag=True, help="Review working-tree changes, including staged changes.")
@click.option("--branch", help="Compare current branch against this base branch.")
@click.option("--ai", "use_ai", is_flag=True, help="Enable AI review (requires an API key).")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="Anthropic API key.")
@click.option("--model", default="claude-sonnet-4-20250514", show_default=True)
@click.option("--json", "output_json", is_flag=True, help="Output machine-readable JSON only.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None)
def review(diff_file: Path | None, use_git: bool, branch: str | None, use_ai: bool, api_key: str | None, model: str, output_json: bool, fail_on: str | None) -> None:
    """Review a diff file, git changes, or standard input."""
    if sum(bool(value) for value in (diff_file, use_git, branch)) > 1:
        raise click.UsageError("Choose only one of DIFF_FILE, --git, or --branch.")
    if use_ai and not api_key:
        raise click.ClickException("--ai requires ANTHROPIC_API_KEY or --api-key.")
    try:
        diff_text = _get_diff(diff_file, use_git, branch)
        result = ReviewResult(summary="No diff content to review.", risk_score=0) if not diff_text else analyze(diff_text, use_ai=use_ai, api_key=api_key, model=model)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if output_json:
        click.echo(result.model_dump_json(indent=2))
    else:
        _render_result(result)
    if fail_on:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        threshold = order.index(Severity(fail_on))
        if any(f.severity in order[:threshold + 1] for f in result.findings):
            raise SystemExit(1)

@main.command()
def rules() -> None:
    """List built-in rules."""
    from codeguardian.core.analyzer import ALL_RULES
    table = Table(title="Built-in Rules")
    table.add_column("Rule", style="bold")
    table.add_column("Category")
    for rule in ALL_RULES:
        table.add_row(rule.name, rule.__class__.__module__.rsplit(".", 1)[-1])
    console.print(table)

def _run_git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if result.returncode:
        raise click.ClickException(result.stderr.strip() or "Git command failed.")
    return result.stdout

def _get_diff(diff_file: Path | None, use_git: bool, branch: str | None) -> str:
    if diff_file:
        return diff_file.read_text(encoding="utf-8", errors="replace")
    if branch:
        return _run_git("diff", f"{branch}...HEAD")
    if use_git:
        return _run_git("diff", "--staged") or _run_git("diff")
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise click.UsageError("Provide a diff file, --git, --branch, or pipe a diff to stdin.")

def _render_result(result: ReviewResult) -> None:
    risk_color = "green" if result.risk_score < 30 else "yellow" if result.risk_score < 60 else "red"
    console.print()
    console.print(Panel(f"[bold]{result.summary}[/]\n\nRisk Score: [{risk_color}]{result.risk_score}/100[/]", title="[bold blue]CodeGuardian Review[/]", border_style="blue"))
    if not result.findings:
        console.print("\n[green]No issues found.[/]\n")
        return
    table = Table(show_lines=True)
    for name, kwargs in [("", {"width": 3, "justify": "center"}), ("Severity", {"width": 10}), ("Category", {"width": 16}), ("File", {"width": 30}), ("Issue", {"min_width": 40})]:
        table.add_column(name, **kwargs)
    for finding in sorted(result.findings, key=lambda item: list(Severity).index(item.severity)):
        location = finding.file + (f":{finding.line}" if finding.line else "")
        detail = f"[bold]{finding.title}[/]\n{finding.description}"
        if finding.suggestion:
            detail += f"\n[green]Suggestion:[/] {finding.suggestion}"
        table.add_row(SEVERITY_ICONS[finding.severity], f"[{SEVERITY_COLORS[finding.severity]}]{finding.severity.value}[/]", finding.category.value, location, detail)
    console.print(table)
    console.print()
