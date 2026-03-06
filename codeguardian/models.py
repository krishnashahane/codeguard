"""Data models for CodeGuardian."""

from __future__ import annotations

from enum import Enum
from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    BAD_PATTERN = "bad_pattern"
    BUG_RISK = "bug_risk"
    MAINTAINABILITY = "maintainability"


class Finding(BaseModel):
    file: str
    line: int | None = None
    severity: Severity
    category: Category
    title: str
    description: str
    suggestion: str | None = None


class DiffFile(BaseModel):
    path: str
    old_path: str | None = None
    added_lines: list[tuple[int, str]]
    removed_lines: list[tuple[int, str]]
    is_new: bool = False
    is_deleted: bool = False
    raw_diff: str = ""


class ReviewResult(BaseModel):
    findings: list[Finding] = []
    summary: str = ""
    risk_score: int = 0  # 0-100

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def merge(self, other: ReviewResult) -> ReviewResult:
        return ReviewResult(
            findings=self.findings + other.findings,
            summary=self.summary or other.summary,
            risk_score=max(self.risk_score, other.risk_score),
        )
