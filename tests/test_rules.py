"""Tests for rule-based analyzers."""

from codeguardian.core.diff_parser import parse_diff
from codeguardian.core.rules.security import (
    SecretsRule,
    SQLInjectionRule,
    XSSRule,
    CommandInjectionRule,
    InsecurePracticeRule,
)
from codeguardian.core.rules.performance import NPlus1Rule, LargeAllocationRule
from codeguardian.core.rules.patterns import (
    EmptyExceptRule,
    DebugStatementRule,
    DeepNestingRule,
    LargeDiffRule,
)
from codeguardian.models import Severity, Category


def _make_diff(filename: str, lines: list[str]) -> str:
    content = "\n".join(f"+{line}" for line in lines)
    n = len(lines)
    return f"""\
diff --git a/{filename} b/{filename}
new file mode 100644
--- /dev/null
+++ b/{filename}
@@ -0,0 +1,{n} @@
{content}
"""


def _check_rule(rule, filename, lines):
    diff = _make_diff(filename, lines)
    files = parse_diff(diff)
    return rule.check(files[0])


# --- Security Rules ---

class TestSecretsRule:
    def test_detects_api_key(self):
        findings = _check_rule(SecretsRule(), "config.py", [
            'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890"',
        ])
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == Category.SECURITY

    def test_detects_password(self):
        findings = _check_rule(SecretsRule(), "app.py", [
            'password = "mysecretpassword123"',
        ])
        assert len(findings) >= 1

    def test_ignores_safe_code(self):
        findings = _check_rule(SecretsRule(), "app.py", [
            'api_key = os.environ["API_KEY"]',
        ])
        assert len(findings) == 0


class TestSQLInjection:
    def test_detects_fstring_query(self):
        findings = _check_rule(SQLInjectionRule(), "db.py", [
            'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        ])
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_parameterized(self):
        findings = _check_rule(SQLInjectionRule(), "db.py", [
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        ])
        assert len(findings) == 0


class TestXSS:
    def test_detects_innerhtml(self):
        findings = _check_rule(XSSRule(), "app.js", [
            'element.innerHTML = userInput;',
        ])
        assert len(findings) >= 1

    def test_detects_dangerously_set(self):
        findings = _check_rule(XSSRule(), "Component.tsx", [
            '<div dangerouslySetInnerHTML={{__html: data}} />',
        ])
        assert len(findings) >= 1


class TestCommandInjection:
    def test_detects_os_system_fstring(self):
        findings = _check_rule(CommandInjectionRule(), "run.py", [
            'os.system(f"rm -rf {user_path}")',
        ])
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_eval(self):
        findings = _check_rule(CommandInjectionRule(), "app.py", [
            'eval(user_input)',
        ])
        assert len(findings) >= 1


class TestInsecurePractice:
    def test_detects_verify_false(self):
        findings = _check_rule(InsecurePracticeRule(), "api.py", [
            'requests.get(url, verify=False)',
        ])
        assert len(findings) >= 1

    def test_detects_pickle(self):
        findings = _check_rule(InsecurePracticeRule(), "data.py", [
            'data = pickle.load(file)',
        ])
        assert len(findings) >= 1


# --- Performance Rules ---

class TestNPlus1:
    def test_detects_query_in_loop(self):
        findings = _check_rule(NPlus1Rule(), "views.py", [
            "for user in users:",
            "    orders = db.query(f'SELECT * FROM orders WHERE user_id = {user.id}')",
        ])
        assert len(findings) >= 1
        assert findings[0].category == Category.PERFORMANCE


class TestLargeAllocation:
    def test_detects_huge_range(self):
        findings = _check_rule(LargeAllocationRule(), "proc.py", [
            "data = list(range(10000000))",
        ])
        assert len(findings) >= 1


# --- Pattern Rules ---

class TestEmptyExcept:
    def test_detects_bare_except(self):
        findings = _check_rule(EmptyExceptRule(), "app.py", [
            "try:",
            "    something()",
            "except:",
            "    pass",
        ])
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH


class TestDebugStatements:
    def test_detects_console_log(self):
        findings = _check_rule(DebugStatementRule(), "app.js", [
            'console.log("debug");',
        ])
        assert len(findings) >= 1

    def test_detects_pdb(self):
        findings = _check_rule(DebugStatementRule(), "app.py", [
            "import pdb; pdb.set_trace()",
        ])
        assert len(findings) >= 1

    def test_detects_print(self):
        findings = _check_rule(DebugStatementRule(), "app.py", [
            'print("hello")',
        ])
        assert len(findings) >= 1


class TestDeepNesting:
    def test_detects_deep_nesting(self):
        findings = _check_rule(DeepNestingRule(), "app.py", [
            "                    deeply_nested_call()",
        ])
        assert len(findings) >= 1


class TestLargeDiff:
    def test_detects_large_file(self):
        lines = [f"line_{i} = {i}" for i in range(350)]
        findings = _check_rule(LargeDiffRule(), "big.py", lines)
        assert len(findings) >= 1
        assert findings[0].category == Category.MAINTAINABILITY
