"""Main analysis orchestrator."""
from __future__ import annotations

from codeguardian.core.ai_reviewer import ai_review
from codeguardian.core.diff_parser import parse_diff
from codeguardian.core.rules.base import Rule
from codeguardian.core.rules.patterns import (
    DebugStatementRule,
    DeepNestingRule,
    EmptyExceptRule,
    LargeDiffRule,
    TodoFixmeRule,
)
from codeguardian.core.rules.performance import BlockingCallRule, LargeAllocationRule, NPlus1Rule
from codeguardian.core.rules.security import (
    CommandInjectionRule,
    InsecurePracticeRule,
    SecretsRule,
    SQLInjectionRule,
    XSSRule,
)
from codeguardian.models import DiffFile, ReviewResult, Severity


ALL_RULES: list[Rule] = [SecretsRule(), SQLInjectionRule(), XSSRule(), CommandInjectionRule(), InsecurePracticeRule(), NPlus1Rule(), LargeAllocationRule(), BlockingCallRule(), EmptyExceptRule(), DebugStatementRule(), DeepNestingRule(), LargeDiffRule(), TodoFixmeRule()]

def run_rules(files: list[DiffFile], rules: list[Rule] | None = None) -> ReviewResult:
    """Run all rule-based checks against parsed diff files."""
    active_rules = ALL_RULES if rules is None else rules
    result = ReviewResult()
    for file in files:
        for rule in active_rules:
            result.findings.extend(rule.check(file))
    result.risk_score = _calculate_risk(result)
    return result

def analyze(diff_text: str, *, use_ai: bool = False, api_key: str | None = None, model: str = "claude-sonnet-4-20250514") -> ReviewResult:
    """Parse a diff, run deterministic rules, and optionally augment with AI."""
    files = parse_diff(diff_text)
    if not files:
        return ReviewResult(summary="No files changed.", risk_score=0)
    result = run_rules(files)
    if use_ai:
        if not api_key:
            raise ValueError("AI review requires an API key")
        result = result.merge(ai_review(files, api_key=api_key, model=model))
        result.risk_score = _calculate_risk(result)
    if not result.summary:
        result.summary = _generate_summary(result, len(files))
    return result

def _calculate_risk(result: ReviewResult) -> int:
    weights = {Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 8, Severity.LOW: 3, Severity.INFO: 1}
    return min(100, sum(weights[f.severity] for f in result.findings))

def _generate_summary(result: ReviewResult, file_count: int) -> str:
    total = len(result.findings)
    if not total:
        return f"Reviewed {file_count} file(s). No issues found."
    parts = [f"Reviewed {file_count} file(s). Found {total} issue(s)."]
    if result.critical_count:
        parts.append(f"{result.critical_count} critical.")
    if result.high_count:
        parts.append(f"{result.high_count} high severity.")
    return " ".join(parts)
