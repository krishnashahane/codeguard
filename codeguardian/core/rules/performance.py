"""Performance-focused rules."""

from __future__ import annotations

import re

from codeguardian.core.rules.base import Rule
from codeguardian.models import Category, DiffFile, Finding, Severity

_N_PLUS_ONE = [
    re.compile(r"""for\s+\w+\s+in\s+\w+.*:\s*$"""),
]

_DB_IN_LOOP_PATTERNS = [
    re.compile(r"""\.(?:query|execute|find|fetch|get|save|create|update|delete)\s*\("""),
    re.compile(r"""(?:SELECT|INSERT|UPDATE|DELETE)\s""", re.I),
]

_LARGE_ALLOCATION = [
    (re.compile(r"""range\s*\(\s*\d{7,}\s*\)"""), "Huge range allocation"),
    (re.compile(r"""\*\s*\d{7,}"""), "Large list multiplication"),
]

_INEFFICIENT_PATTERNS = [
    (re.compile(r"""\.append\(.*\)\s*$"""), re.compile(r"""for\s+\w+\s+in"""), "Append in loop (consider list comprehension)"),
]

_REGEX_PATTERNS = [
    (re.compile(r"""re\.(?:match|search|findall|sub)\s*\("""), "Uncompiled regex in possible hot path"),
]

_BLOCKING_CALLS = [
    (re.compile(r"""time\.sleep\s*\(\s*\d+\s*\)"""), "Blocking sleep call"),
    (re.compile(r"""requests\.(?:get|post|put|delete|patch)\s*\("""), "Synchronous HTTP call (consider async)"),
]


class NPlus1Rule(Rule):
    name = "n-plus-1-query"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        exts = {".py", ".js", ".ts", ".rb", ".java", ".go", ".php"}
        if not self._matches_extensions(file.path, exts):
            return findings

        lines = file.added_lines
        for i, (line_no, content) in enumerate(lines):
            is_loop = any(p.search(content) for p in _N_PLUS_ONE)
            if not is_loop:
                continue
            # Check next few added lines for DB calls
            for j in range(i + 1, min(i + 8, len(lines))):
                _, next_content = lines[j]
                if any(p.search(next_content) for p in _DB_IN_LOOP_PATTERNS):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.HIGH,
                        category=Category.PERFORMANCE,
                        title="Potential N+1 query",
                        description="Database call detected inside a loop. This causes one query per iteration.",
                        suggestion="Batch the query outside the loop or use eager loading / prefetch.",
                    ))
                    break
        return findings


class LargeAllocationRule(Rule):
    name = "large-allocation"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        for line_no, content in file.added_lines:
            for pattern, label in _LARGE_ALLOCATION:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.MEDIUM,
                        category=Category.PERFORMANCE,
                        title=label,
                        description="Very large in-memory allocation detected.",
                        suggestion="Use generators or iterators for large sequences.",
                    ))
        return findings


class BlockingCallRule(Rule):
    name = "blocking-calls"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        exts = {".py", ".js", ".ts"}
        if not self._matches_extensions(file.path, exts):
            return findings
        for line_no, content in file.added_lines:
            for pattern, label in _BLOCKING_CALLS:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.LOW,
                        category=Category.PERFORMANCE,
                        title=label,
                        description=f"Detected: {label.lower()}. May block the event loop or slow down execution.",
                        suggestion="Consider async alternatives or offloading to a background task.",
                    ))
        return findings
