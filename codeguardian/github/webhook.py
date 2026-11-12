"""GitHub webhook event handlers."""
from __future__ import annotations
import logging
from codeguardian.core.analyzer import analyze
from codeguardian.github.client import get_pr_diff, post_review

logger = logging.getLogger(__name__)

def handle_pull_request(payload: dict, *, github_token: str, anthropic_api_key: str | None = None, use_ai: bool = False) -> None:
    """Handle supported pull_request webhook actions."""
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        logger.info("Ignoring PR action: %s", action)
        return
    try:
        pr = payload["pull_request"]
        repo = payload["repository"]["full_name"]
        pr_number = int(pr["number"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Malformed pull_request webhook payload") from exc
    if not repo or "/" not in repo or pr_number < 1:
        raise ValueError("Invalid repository or pull request number")
    logger.info("Reviewing PR #%d on %s", pr_number, repo)
    diff_text = get_pr_diff(github_token, repo, pr_number)
    result = analyze(diff_text, use_ai=use_ai, api_key=anthropic_api_key or None)
    post_review(github_token, repo, pr_number, result)
    logger.info("Posted review for PR #%d: %d findings", pr_number, len(result.findings))
