"""Tests for the main analyzer."""

from codeguardian.core.analyzer import analyze
from codeguardian.models import Severity, Category

VULNERABLE_DIFF = """\
diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,8 @@
+import os
+
+api_key = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
+
+os.system(f"deploy {api_key}")
+
+cursor.execute(f"SELECT * FROM users WHERE name = {name}")
+
"""

CLEAN_DIFF = """\
diff --git a/utils.py b/utils.py
new file mode 100644
--- /dev/null
+++ b/utils.py
@@ -0,0 +1,5 @@
+def add(a: int, b: int) -> int:
+    return a + b
+
+def multiply(a: int, b: int) -> int:
+    return a * b
"""


def test_analyze_finds_vulnerabilities():
    result = analyze(VULNERABLE_DIFF)
    assert len(result.findings) > 0
    severities = {f.severity for f in result.findings}
    assert Severity.CRITICAL in severities
    assert result.risk_score > 0


def test_analyze_clean_code():
    result = analyze(CLEAN_DIFF)
    assert len(result.findings) == 0
    assert result.risk_score == 0


def test_analyze_empty_diff():
    result = analyze("")
    assert len(result.findings) == 0
    assert "No files" in result.summary


def test_risk_score_bounded():
    result = analyze(VULNERABLE_DIFF)
    assert 0 <= result.risk_score <= 100