"""CLI interface for CodeGuardian."""

from __future__ import annotations

import sys
import subprocess

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from codeguardian.core.analyzer import analyze
from codeguardian.models import ReviewResult, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[bold red]X[/]",
    Severity.HIGH: "[red]![/]",
    Severity.MEDIUM: "[yellow]~[/]",
    Severity.LOW: "[cyan]-[/]",
    Severity.INFO: "[dim].[/]",
}


@click.group()
@click.version_option(package_name="codeguardian")
def main():
    """CodeGuardian - AI-powered Pull Request Reviewer."""


@main.command()
@click.argument("diff_file", required=False, type=click.Path(exists=True))
@click.option("--git", "use_git", is_flag=True, help="Review staged git changes.")
@click.option("--branch", help="Compare current branch against this base branch.")
@click.option("--ai", "use_ai", is_flag=True, help="Enable AI-powered review (requires ANTHROPIC_API_KEY).")
@click.option("--api-key", envvar="ANTHROPIC_API_KEY", help="Anthropic API key.")
@click.option("--model", default="claude-sonnet-4-20250514", help="Claude model to use.")
@click.option("--json", "output_json", is_flag=True, help="Output results as JSON.")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None, help="Exit with code 1 if issues at this severity or above are found.")
def review(diff_file, use_git, branch, use_ai, api_key, model, output_json, fail_on):
    """Review a diff for issues."""
    diff_text = _get_diff(diff_file, use_git, branch)
    if not diff_text:
        console.print("[dim]No diff content to review.[/]")
        return

    if use_ai and not api_key:
        console.print("[red]Error:[/] --ai requires ANTHROPIC_API_KEY env var or --api-key flag.")
        sys.exit(1)

    with console.status("[bold blue]Analyzing..."):
        result = analyze(diff_text, use_ai=use_ai, api_key=api_key, model=model)

    if output_json:
        click.echo(result.model_dump_json(indent=2))
    else:
        _render_result(result)

    if fail_on:
        threshold = Severity(fail_on)
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        threshold_idx = severity_order.index(threshold)
        for f in result.findings:
            if f.severity in severity_order[: threshold_idx + 1]:
                sys.exit(1)


@main.command()
def rules():
    """List all built-in rules."""
    from codeguardian.core.analyzer import ALL_RULES

    table = Table(title="Built-in Rules")
    table.add_column("Rule", style="bold")
    table.add_column("Category")

    for rule in ALL_RULES:
        table.add_row(rule.name, rule.__class__.__module__.rsplit(".", 1)[-1])

    console.print(table)


def _get_diff(diff_file: str | None, use_git: bool, branch: str | None) -> str:
    if diff_file:
        with open(diff_file) as f:
            return f.read()
    if branch:
        result = subprocess.run(
            ["git", "diff", f"{branch}...HEAD"],
            capture_output=True, text=True,
        )
        return result.stdout
    if use_git:
        result = subprocess.run(
            ["git", "diff", "--staged"],
            capture_output=True, text=True,
        )
        if not result.stdout:
            result = subprocess.run(
                ["git", "diff"],
                capture_output=True, text=True,
            )
        return result.stdout
    # Default: read from stdin
    if not sys.stdin.isatty():
        return sys.stdin.read()
    console.print("[dim]Provide a diff via file, --git, --branch, or stdin.[/]")
    return ""


def _render_result(result: ReviewResult):
    # Summary panel
    risk_color = "green"
    if result.risk_score >= 60:
        risk_color = "red"
    elif result.risk_score >= 30:
        risk_color = "yellow"

    console.print()
    console.print(Panel(
        f"[bold]{result.summary}[/]\n\nRisk Score: [{risk_color}]{result.risk_score}/100[/]",
        title="[bold blue]CodeGuardian Review[/]",
        border_style="blue",
    ))

    if not result.findings:
        console.print("\n[green]No issues found.[/]\n")
        return

    # Findings table
    table = Table(show_lines=True)
    table.add_column("", width=3, justify="center")
    table.add_column("Severity", width=10)
    table.add_column("Category", width=16)
    table.add_column("File", width=30)
    table.add_column("Issue", min_width=40)

    for f in sorted(result.findings, key=lambda x: list(Severity).index(x.severity)):
        location = f.file
        if f.line:
            location += f":{f.line}"

        detail = f"[bold]{f.title}[/]\n{f.description}"
        if f.suggestion:
            detail += f"\n[green]Suggestion:[/] {f.suggestion}"

        table.add_row(
            SEVERITY_ICONS[f.severity],
            f"[{SEVERITY_COLORS[f.severity]}]{f.severity.value}[/]",
            f.category.value,
            location,
            detail,
        )

    console.print(table)
    console.print()
