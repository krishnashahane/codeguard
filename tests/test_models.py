"""Pydantic model invariants."""
import pytest
from pydantic import ValidationError

from codeguardian.models import Category, Finding, ReviewResult, Severity


def test_review_results_do_not_share_mutable_findings():
    first = ReviewResult()
    second = ReviewResult()
    first.findings.append(Finding(file="a.py", severity=Severity.INFO, category=Category.BAD_PATTERN, title="Note"))
    assert second.findings == []


@pytest.mark.parametrize("score", [-1, 101])
def test_review_result_rejects_out_of_range_risk_score(score):
    with pytest.raises(ValidationError):
        ReviewResult(risk_score=score)


def test_finding_rejects_invalid_line_numbers():
    with pytest.raises(ValidationError):
        Finding(file="a.py", line=0, severity=Severity.INFO, category=Category.BAD_PATTERN, title="Note")
