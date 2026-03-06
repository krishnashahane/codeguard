"""AI-powered code review using Claude."""

from __future__ import annotations

import json
import anthropic

from codeguardian.models import (
    Category,
    DiffFile,
    Finding,
    ReviewResult,
    Severity,
)

SYSTEM_PROMPT = """\
You are CodeGuardian, an expert code reviewer. Analyze the given diff and report issues.

For each issue found, respond with a JSON array of objects with these fields:
- file: the file path
- line: the line number in the new file (or null)
- severity: one of "critical", "high", "medium", "low", "info"
- category: one of "security", "performance", "bad_pattern", "bug_risk", "maintainability"
- title: short title (under 80 chars)
- description: explanation of the issue
- suggestion: how to fix it

Also include a top-level summary and risk_score (0-100).

Respond ONLY with valid JSON in this format:
{
  "findings": [...],
  "summary": "...",
  "risk_score": 0
}

Focus on:
1. Security vulnerabilities (injection, auth issues, data exposure)
2. Performance problems (N+1 queries, unnecessary allocations, blocking calls)
3. Bad patterns (error swallowing, code smells, anti-patterns)
4. Bug risks (race conditions, null references, off-by-one errors)
5. Maintainability (complexity, naming, missing error handling)

Be precise and actionable. Do NOT flag trivial style issues. Only report real problems.\
"""

MAX_DIFF_CHARS = 100_000


def ai_review(files: list[DiffFile], api_key: str, model: str = "claude-sonnet-4-20250514") -> ReviewResult:
    """Run AI-powered review on diff files."""
    diff_text = _prepare_diff(files)
    if not diff_text.strip():
        return ReviewResult(summary="No changes to review.", risk_score=0)

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Review this diff:\n\n```diff\n{diff_text}\n```"}],
    )

    return _parse_response(message.content[0].text)


def _prepare_diff(files: list[DiffFile]) -> str:
    parts = []
    total = 0
    for f in files:
        if f.is_deleted:
            continue
        chunk = f.raw_diff
        if total + len(chunk) > MAX_DIFF_CHARS:
            break
        parts.append(chunk)
        total += len(chunk)
    return "\n".join(parts)


def _parse_response(text: str) -> ReviewResult:
    # Extract JSON from possible markdown code blocks
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = lines[1:]  # skip ```json
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines)

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return ReviewResult(
            summary="AI review failed to produce valid JSON output.",
            risk_score=0,
        )

    findings = []
    for item in data.get("findings", []):
        try:
            findings.append(Finding(
                file=item["file"],
                line=item.get("line"),
                severity=Severity(item.get("severity", "info")),
                category=Category(item.get("category", "bad_pattern")),
                title=item.get("title", "Unnamed issue"),
                description=item.get("description", ""),
                suggestion=item.get("suggestion"),
            ))
        except (KeyError, ValueError):
            continue

    return ReviewResult(
        findings=findings,
        summary=data.get("summary", ""),
        risk_score=min(100, max(0, int(data.get("risk_score", 0)))),
    )
