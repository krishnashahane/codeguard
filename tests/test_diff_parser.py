"""Tests for the diff parser."""

from codeguardian.core.diff_parser import parse_diff

SAMPLE_DIFF = """\
diff --git a/app.py b/app.py
new file mode 100644
--- /dev/null
+++ b/app.py
@@ -0,0 +1,10 @@
+import os
+
+def main():
+    api_key = "sk-1234567890abcdef"
+    password = "super_secret_password"
+    os.system(f"echo {api_key}")
+    result = cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
+    print("debug output")
+    for item in items:
+        db.query(f"SELECT * FROM orders WHERE item_id = {item.id}")
"""


def test_parse_diff_basic():
    files = parse_diff(SAMPLE_DIFF)
    assert len(files) == 1
    assert files[0].path == "app.py"
    assert files[0].is_new is True
    assert len(files[0].added_lines) == 10
    assert files[0].added_lines[0] == (1, "import os")


def test_parse_diff_multi_file():
    diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,3 +1,4 @@
 line1
+new_line
 line2
 line3
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -5,3 +5,4 @@
 existing
+another_new
 more
"""
    files = parse_diff(diff)
    assert len(files) == 2
    assert files[0].path == "a.py"
    assert files[1].path == "b.py"
    assert len(files[0].added_lines) == 1
    assert len(files[1].added_lines) == 1


def test_parse_empty_diff():
    assert parse_diff("") == []


def test_parse_deleted_file():
    diff = """\
diff --git a/old.py b/old.py
deleted file mode 100644
--- a/old.py
+++ /dev/null
@@ -1,3 +0,0 @@
-line1
-line2
-line3
"""
    files = parse_diff(diff)
    assert len(files) == 1
    assert files[0].is_deleted is True
    assert len(files[0].removed_lines) == 3
