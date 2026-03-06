"""Main analysis orchestrator."""

from __future__ import annotations

from codeguardian.core.diff_parser import parse_diff
from codeguardian.core.rules.base import Rule
from codeguardian.core.rules.security import (
    CommandInjectionRule,
    InsecurePracticeRule,
    SecretsRule,
    SQLInjectionRule,
    XSSRule,
)
from codeguardian.core.rules.performance import (
    BlockingCallRule,
    LargeAllocationRule,
    NPlus1Rule,
)
from codeguardian.core.rules.patterns import (
    DebugStatementRule,
    DeepNestingRule,
    EmptyExceptRule,
    LargeDiffRule,
    TodoFixmeRule,
)
from codeguardian.core.ai_reviewer import ai_review
from codeguardian.models import DiffFile, ReviewResult, Severity

ALL_RULES: list[Rule] = [
    # Security
    SecretsRule(),
    SQLInjectionRule(),
    XSSRule(),
    CommandInjectionRule(),
    InsecurePracticeRule(),
    # Performance
    NPlus1Rule(),
    LargeAllocationRule(),
    BlockingCallRule(),
    # Patterns
    EmptyExceptRule(),
    DebugStatementRule(),
    DeepNestingRule(),
    LargeDiffRule(),
    TodoFixmeRule(),
]


def run_rules(files: list[DiffFile], rules: list[Rule] | None = None) -> ReviewResult:
    """Run all rule-based checks against parsed diff files."""
    rules = rules or ALL_RULES
    result = ReviewResult()
    for file in files:
        for rule in rules:
            findings = rule.check(file)
            result.findings.extend(findings)
    result.risk_score = _calculate_risk(result)
    return result


def analyze(
    diff_text: str,
    *,
    use_ai: bool = False,
    api_key: str | None = None,
    model: str = "claude-sonnet-4-20250514",
) -> ReviewResult:
    """Full analysis pipeline: parse diff, run rules, optionally run AI review."""
    files = parse_diff(diff_text)
    if not files:
        return ReviewResult(summary="No files changed.", risk_score=0)

    result = run_rules(files)

    if use_ai and api_key:
        ai_result = ai_review(files, api_key=api_key, model=model)
        result = result.merge(ai_result)
        result.risk_score = _calculate_risk(result)

    if not result.summary:
        result.summary = _generate_summary(result, len(files))

    return result


def _calculate_risk(result: ReviewResult) -> int:
    score = 0
    for f in result.findings:
        match f.severity:
            case Severity.CRITICAL:
                score += 25
            case Severity.HIGH:
                score += 15
            case Severity.MEDIUM:
                score += 8
            case Severity.LOW:
                score += 3
            case Severity.INFO:
                score += 1
    return min(100, score)


def _generate_summary(result: ReviewResult, file_count: int) -> str:
    total = len(result.findings)
    if total == 0:
        return f"Reviewed {file_count} file(s). No issues found."
    parts = [f"Reviewed {file_count} file(s). Found {total} issue(s)."]
    if result.critical_count:
        parts.append(f"{result.critical_count} critical.")
    if result.high_count:
        parts.append(f"{result.high_count} high severity.")
    return " ".join(parts)
