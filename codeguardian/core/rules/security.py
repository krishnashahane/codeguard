"""Security-focused rules."""

from __future__ import annotations

import re

from codeguardian.core.rules.base import Rule
from codeguardian.models import Category, DiffFile, Finding, Severity

_SECRET_PATTERNS = [
    (re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]""", re.I), "Hardcoded API key"),
    (re.compile(r"""(?:secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]""", re.I), "Hardcoded secret/password"),
    (re.compile(r"""(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{16,}""", re.I), "AWS credential"),
    (re.compile(r"""ghp_[A-Za-z0-9]{36}"""), "GitHub personal access token"),
    (re.compile(r"""sk-[A-Za-z0-9]{20,}"""), "Secret key (possible API key)"),
    (re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"""), "Private key"),
    (re.compile(r"""(?:Bearer|token)\s+[A-Za-z0-9_\-.]{20,}""", re.I), "Hardcoded bearer token"),
]

_SQL_INJECTION_PATTERNS = [
    re.compile(r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['"]|['"].*\+\s*\w)""", re.I),
    re.compile(r"""f['"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s""", re.I),
    re.compile(r"""['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s.*['"].*\.format\(""", re.I),
]

_XSS_PATTERNS = [
    re.compile(r"""innerHTML\s*=\s*[^'"]"""),
    re.compile(r"""dangerouslySetInnerHTML"""),
    re.compile(r"""document\.write\("""),
    re.compile(r"""\|\s*safe\b"""),
]

_COMMAND_INJECTION = [
    re.compile(r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run)\s*\(\s*(?:f['"]|\w+\s*\+)"""),
    re.compile(r"""eval\s*\(\s*(?!['"])"""),
    re.compile(r"""exec\s*\(\s*(?!['"])"""),
    re.compile(r"""child_process\.exec\s*\("""),
]

_INSECURE_PATTERNS = [
    (re.compile(r"""verify\s*=\s*False"""), "SSL verification disabled"),
    (re.compile(r"""(?:md5|sha1)\s*\(""", re.I), "Weak hash algorithm (use SHA-256+)"),
    (re.compile(r"""random\.\w+\("""), "Non-cryptographic random (use secrets module for security)"),
    (re.compile(r"""pickle\.loads?\("""), "Unsafe deserialization with pickle"),
    (re.compile(r"""yaml\.load\s*\([^)]*(?!\bLoader\b)"""), "Unsafe YAML load (use safe_load)"),
    (re.compile(r"""chmod\s*\(\s*0?o?777"""), "World-writable file permissions"),
    (re.compile(r"""CORS\s*\(\s*\w+\s*,\s*origins\s*=\s*\[?\s*['\"]\*['\"]"""), "CORS allows all origins"),
]


class SecretsRule(Rule):
    name = "secrets-detection"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        for line_no, content in file.added_lines:
            for pattern, label in _SECRET_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        title=f"Potential {label} detected",
                        description=f"Line appears to contain a {label.lower()}. Secrets should never be committed to source control.",
                        suggestion="Use environment variables or a secrets manager instead.",
                    ))
                    break
        return findings


class SQLInjectionRule(Rule):
    name = "sql-injection"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        exts = {".py", ".js", ".ts", ".java", ".rb", ".php", ".go"}
        if not self._matches_extensions(file.path, exts):
            return findings
        for line_no, content in file.added_lines:
            for pattern in _SQL_INJECTION_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        title="Potential SQL injection",
                        description="String interpolation in SQL query detected. This is vulnerable to SQL injection attacks.",
                        suggestion="Use parameterized queries or an ORM instead of string formatting.",
                    ))
                    break
        return findings


class XSSRule(Rule):
    name = "xss-detection"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        exts = {".js", ".jsx", ".ts", ".tsx", ".html", ".vue", ".svelte"}
        if not self._matches_extensions(file.path, exts):
            return findings
        for line_no, content in file.added_lines:
            for pattern in _XSS_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        title="Potential XSS vulnerability",
                        description="Unescaped HTML injection detected. This could allow cross-site scripting attacks.",
                        suggestion="Sanitize user input before rendering. Avoid innerHTML and dangerouslySetInnerHTML.",
                    ))
                    break
        return findings


class CommandInjectionRule(Rule):
    name = "command-injection"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        for line_no, content in file.added_lines:
            for pattern in _COMMAND_INJECTION:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.CRITICAL,
                        category=Category.SECURITY,
                        title="Potential command injection",
                        description="Dynamic input in shell/eval call detected. This is vulnerable to command injection.",
                        suggestion="Use parameterized subprocess calls (e.g., subprocess.run with a list) and avoid eval/exec.",
                    ))
                    break
        return findings


class InsecurePracticeRule(Rule):
    name = "insecure-practices"

    def check(self, file: DiffFile) -> list[Finding]:
        findings = []
        for line_no, content in file.added_lines:
            for pattern, label in _INSECURE_PATTERNS:
                if pattern.search(content):
                    findings.append(Finding(
                        file=file.path,
                        line=line_no,
                        severity=Severity.HIGH,
                        category=Category.SECURITY,
                        title=label,
                        description=f"Insecure practice detected: {label.lower()}.",
                        suggestion="See OWASP guidelines for secure alternatives.",
                    ))
        return findings
