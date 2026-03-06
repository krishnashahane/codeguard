"""GitHub webhook event handlers."""

from __future__ import annotations

import logging

from codeguardian.core.analyzer import analyze
from codeguardian.github.client import get_pr_diff, post_review

logger = logging.getLogger(__name__)


def handle_pull_request(
    payload: dict,
    *,
    github_token: str,
    anthropic_api_key: str | None = None,
    use_ai: bool = False,
):
    """Handle a pull_request webhook event."""
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        logger.info("Ignoring PR action: %s", action)
        return

    pr = payload["pull_request"]
    repo = payload["repository"]["full_name"]
    pr_number = pr["number"]

    logger.info("Reviewing PR #%d on %s", pr_number, repo)

    diff_text = get_pr_diff(github_token, repo, pr_number)

    result = analyze(
        diff_text,
        use_ai=use_ai,
        api_key=anthropic_api_key,
    )

    post_review(github_token, repo, pr_number, result)
    logger.info("Posted review for PR #%d: %d findings", pr_number, len(result.findings))