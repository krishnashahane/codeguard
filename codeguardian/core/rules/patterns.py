"""Bad pattern detection rules."""

from __future__ import annotations

import re

from codeguardian.core.rules.base import Rule
from codeguardian.models import Category, DiffFile, Finding, Severity

_TODO_FIXME = re.compile(r"""(?:TODO|FIXME|HACK|XXX|WORKAROUND)\b""", re.I)

_EMPTY_EXCEPT = re.compile(r"""except\s*(?:\w+\s*)?:\s*$""")
_BARE_EXCEPT = re.compile(r"""except\s*:\s*$""")
_PASS_AFTER_EXCEPT = re.compile(r"""^\s*pass\s*$""")

_MAGIC_NUMBERS = re.compile(r"""(?<!=)\s(?<!\w)[2-9]\d{2,}\b(?!\s*[,\])}])""")

_LARGE_FUNCTION_THRESHOLD = 50

_DEBUG_PATTERNS = [
    (re.compile(r"""console\.log\s*\("""), "console.log statement"),
    (re.compile(r"""print\s*\((?!.*file\s*=)"""), "print statement (use logging)"),
    (re.compile(r"""debugger\b"""), "debugger statement"),
    (re.compile(r"""binding\.pry"""), "binding.pry (Ruby debugger)"),
    (re.compile(r"""import\s+pdb|pdb\.set_trace"""), "pdb debugger"),
    (re.compile(r"""import\s+ipdb|ipdb\.set_trace"""), "ipdb debugger"),
]

_COMPLEXITY_INDICATORS = [
    re.compile(r"""^\s{16,}\S"""),  # Deep nesting (4+ levels at 4-space indent)
]

_DUPLICATE_IMPORT = re.compile(r"""^(?:import|from)\s+(\S+)""")


class TodoFixmeRule(Rule):
    name = "todo-fixme"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        for line_no, content in file.added_lines:
            if _TODO_FIXME.search(content):
                findings.append(Finding(
                    file=file.path,
                    line=line_no,
                    severity=Severity.INFO,
                    category=Category.MAINTAINABILITY,
                    title="TODO/FIXME comment",
                    description="New TODO/FIXME comment added. Track this as a ticket to avoid forgotten work.",
                    suggestion="Create an issue to track this TODO.",
                ))
        return findings


class EmptyExceptRule(Rule):
    name = "empty-except"

    def check(self, file: DiffFile) -> list[Finding]:
        if not self._matches_extensions(file.path, {".py"}):
            return []
        findings = []
        lines = file.added_lines
        for i, (line_no, content) in enumerate(lines):
            is_bare = _BARE_EXCEPT.search(content)
            is_except = _EMPTY_EXCEPT.search(content)
            if is_bare or is_except:
                # Check if next line is just pass
                if is_bare:
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.HIGH,
                        category=Category.BAD_PATTERN,
                        title="Bare except clause",
                        description="Bare except catches all exceptions including SystemExit and KeyboardInterrupt.",
                        suggestion="Catch specific exceptions (e.g., except ValueError:).",
                    ))
                elif i + 1 < len(lines) and _PASS_AFTER_EXCEPT.match(lines[i + 1][1]):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.MEDIUM,
                        category=Category.BAD_PATTERN,
                        title="Silent exception swallowing",
                        description="Exception is caught and silently ignored with pass.",
                        suggestion="Log the exception or handle it meaningfully.",
                    ))
        return findings


class DebugStatementRule(Rule):
    name = "debug-statements"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        for line_no, content in file.added_lines:
            for pattern, label in _DEBUG_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.MEDIUM,
                        category=Category.BAD_PATTERN,
                        title=f"Debug statement: {label}",
                        description=f"A {label} was left in the code. This should be removed before merging.",
                        suggestion="Remove the debug statement or replace with proper logging.",
                    ))
                    break
        return findings


class DeepNestingRule(Rule):
    name = "deep-nesting"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        for line_no, content in file.added_lines:
            for pattern in _COMPLEXITY_INDICATORS:
                if pattern.match(content) and content.strip():
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.MEDIUM,
                        category=Category.MAINTAINABILITY,
                        title="Deeply nested code",
                        description="Code is nested 4+ levels deep, making it hard to read and maintain.",
                        suggestion="Extract inner logic into helper functions or use early returns.",
                    ))
                    break
        return findings


class LargeDiffRule(Rule):
    name = "large-diff"

    def check(self, file: DiffFile) -> list[Finding]:
        added = len(file.added_lines)
        if added > 300:
            return [Finding(
                file=file.path,
                line=None,
                severity=Severity.MEDIUM,
                category=Category.MAINTAINABILITY,
                title="Very large file change",
                description=f"This file has {added} added lines. Large changes are hard to review.",
                suggestion="Consider breaking this into smaller, focused PRs.",
            )]
        return []
