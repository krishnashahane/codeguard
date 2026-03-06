"""GitHub API client for posting review comments."""

from __future__ import annotations

import hmac
import hashlib

from github import Github, Auth
from github.PullRequest import PullRequest

from codeguardian.models import Finding, ReviewResult, Severity


def get_pr_diff(token: str, repo: str, pr_number: int) -> str:
    """Fetch the diff for a pull request."""
    g = Github(auth=Auth.Token(token))
    repo_obj = g.get_repo(repo)
    pr = repo_obj.get_pull(pr_number)
    # Get the diff via the API
    import httpx
    resp = httpx.get(
        pr.diff_url,
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3.diff"},
        follow_redirects=True,
    )
    resp.raise_for_status()
    return resp.text


def post_review(token: str, repo: str, pr_number: int, result: ReviewResult):
    """Post review results as PR review comments."""
    g = Github(auth=Auth.Token(token))
    repo_obj = g.get_repo(repo)
    pr = repo_obj.get_pull(pr_number)

    if not result.findings:
        pr.create_issue_comment(_format_clean_summary(result))
        return

    # Post inline comments for findings with line numbers
    comments = []
    commit = pr.get_commits().reversed[0]

    for finding in result.findings:
        if finding.line:
            comments.append({
                "path": finding.file,
                "line": finding.line,
                "body": _format_comment(finding),
            })

    # Determine review event based on severity
    event = "COMMENT"
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings):
        event = "REQUEST_CHANGES"

    body = _format_summary(result)

    if comments:
        pr.create_review(
            commit=commit,
            body=body,
            event=event,
            comments=comments,
        )
    else:
        pr.create_issue_comment(body)


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature."""
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _format_comment(finding: Finding) -> str:
    icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    sev = finding.severity.value
    lines = [
        f"{icon.get(sev, '⚪')} **{finding.title}** ({sev} | {finding.category.value})",
        "",
        finding.description,
    ]
    if finding.suggestion:
        lines.extend(["", f"**Suggestion:** {finding.suggestion}"])
    lines.extend(["", "---", "*Reviewed by [CodeGuardian](https://github.com/codeguardian)*"])
    return "\n".join(lines)


def _format_summary(result: ReviewResult) -> str:
    lines = [
        "## CodeGuardian Review",
        "",
        result.summary,
        "",
        f"**Risk Score:** {result.risk_score}/100",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    severity_counts: dict[str, int] = {}
    for f in result.findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    for sev in ["critical", "high", "medium", "low", "info"]:
        if count := severity_counts.get(sev, 0):
            lines.append(f"| {sev} | {count} |")

    lines.extend(["", "---", "*Reviewed by [CodeGuardian](https://github.com/codeguardian)*"])
    return "\n".join(lines)


def _format_clean_summary(result: ReviewResult) -> str:
    return (
        "## CodeGuardian Review\n\n"
        "No issues found. Looking good!\n\n"
        f"**Risk Score:** {result.risk_score}/100\n\n"
        "---\n*Reviewed by [CodeGuardian](https://github.com/codeguardian)*"
    )
