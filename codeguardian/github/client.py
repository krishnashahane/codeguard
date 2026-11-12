"""GitHub API client for retrieving diffs and publishing reviews."""
from __future__ import annotations

import hashlib
import hmac
import logging

import httpx
from github import Auth, Github

from codeguardian.models import Finding, ReviewResult, Severity

logger = logging.getLogger(__name__)

def get_pr_diff(token: str, repo: str, pr_number: int) -> str:
    """Fetch a PR diff over HTTPS with bounded timeouts."""
    if not token:
        raise ValueError("A GitHub token is required")
    github = Github(auth=Auth.Token(token), timeout=20)
    try:
        pr = github.get_repo(repo).get_pull(pr_number)
        response = httpx.get(pr.diff_url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"}, follow_redirects=True, timeout=httpx.Timeout(20.0, connect=5.0))
        response.raise_for_status()
        return response.text
    finally:
        github.close()

def post_review(token: str, repo: str, pr_number: int, result: ReviewResult) -> None:
    """Publish findings; fall back to a PR summary if inline review is rejected."""
    if not token:
        raise ValueError("A GitHub token is required")
    github = Github(auth=Auth.Token(token), timeout=20)
    try:
        pr = github.get_repo(repo).get_pull(pr_number)
        if not result.findings:
            pr.create_issue_comment(_format_clean_summary(result))
            return
        comments = [{"path": finding.file, "line": finding.line, "body": _format_comment(finding)} for finding in result.findings if finding.line is not None]
        body = _format_summary(result)
        if comments:
            try:
                latest_commit = pr.get_commits().reversed[0]
                event = "REQUEST_CHANGES" if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings) else "COMMENT"
                pr.create_review(commit=latest_commit, body=body, event=event, comments=comments)
                return
            except Exception as exc:
                logger.warning("Inline review could not be posted; falling back to summary: %s", exc)
        pr.create_issue_comment(body)
    finally:
        github.close()

def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub's SHA-256 webhook signature."""
    if not secret or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

def _format_comment(finding: Finding) -> str:
    lines = [f"**{finding.title}** ({finding.severity.value} | {finding.category.value})", "", finding.description]
    if finding.suggestion:
        lines.extend(["", f"**Suggestion:** {finding.suggestion}"])
    lines.extend(["", "---", "*Reviewed by CodeGuardian*"])
    return "\n".join(lines)

def _format_summary(result: ReviewResult) -> str:
    lines = ["## CodeGuardian Review", "", result.summary, "", f"**Risk Score:** {result.risk_score}/100", "", "| Severity | Count |", "|----------|-------|"]
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    for severity in ("critical", "high", "medium", "low", "info"):
        if count := counts.get(severity, 0):
            lines.append(f"| {severity} | {count} |")
    lines.extend(["", "---", "*Reviewed by CodeGuardian*"])
    return "\n".join(lines)

def _format_clean_summary(result: ReviewResult) -> str:
    return f"## CodeGuardian Review\n\nNo issues found.\n\n**Risk Score:** {result.risk_score}/100\n\n---\n*Reviewed by CodeGuardian*"
