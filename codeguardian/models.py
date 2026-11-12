"""Validated data models for CodeGuardian."""
from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field

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
    model_config = ConfigDict(str_strip_whitespace=True)
    file: str = Field(min_length=1, max_length=1024)
    line: int | None = Field(default=None, ge=1)
    severity: Severity
    category: Category
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=10000)
    suggestion: str | None = Field(default=None, max_length=10000)

class DiffFile(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    old_path: str | None = None
    added_lines: list[tuple[int, str]] = Field(default_factory=list)
    removed_lines: list[tuple[int, str]] = Field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False
    raw_diff: str = ""

class ReviewResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""
    risk_score: int = Field(default=0, ge=0, le=100)

    @property
    def critical_count(self) -> int:
        return sum(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def high_count(self) -> int:
        return sum(f.severity == Severity.HIGH for f in self.findings)

    def merge(self, other: ReviewResult) -> ReviewResult:
        return ReviewResult(findings=self.findings + other.findings, summary=self.summary or other.summary, risk_score=max(self.risk_score, other.risk_score))
