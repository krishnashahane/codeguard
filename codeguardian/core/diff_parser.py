"""Parse unified diff format into structured data."""
from __future__ import annotations
import re
from codeguardian.models import DiffFile

_DIFF_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_NEW_FILE = re.compile(r"^new file mode")
_DELETED_FILE = re.compile(r"^deleted file mode")

def parse_diff(diff_text: str) -> list[DiffFile]:
    """Parse unified diff text while preserving paths and line numbers."""
    files: list[DiffFile] = []
    current: dict | None = None
    old_line = new_line = 0
    in_hunk = False
    for line in diff_text.splitlines():
        header = _DIFF_HEADER.match(line)
        if header:
            if current is not None:
                files.append(_build_diff_file(current))
            current = {"old_path": header.group(1), "new_path": header.group(2), "added": [], "removed": [], "is_new": False, "is_deleted": False, "raw_lines": [line]}
            old_line = new_line = 0
            in_hunk = False
            continue
        if current is None:
            continue
        current["raw_lines"].append(line)
        if _NEW_FILE.match(line):
            current["is_new"] = True
            continue
        if _DELETED_FILE.match(line):
            current["is_deleted"] = True
            continue
        hunk = _HUNK_HEADER.match(line)
        if hunk:
            old_line, new_line = int(hunk.group(1)), int(hunk.group(2))
            in_hunk = True
            continue
        if not in_hunk or line.startswith("\\ No newline at end of file"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current["added"].append((new_line, line[1:]))
            new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            current["removed"].append((old_line, line[1:]))
            old_line += 1
        elif line.startswith(" "):
            old_line += 1
            new_line += 1
    if current is not None:
        files.append(_build_diff_file(current))
    return files

def _build_diff_file(data: dict) -> DiffFile:
    """Construct a validated file record from parser state."""
    old_path, new_path = data["old_path"], data["new_path"]
    path = old_path if data["is_deleted"] else new_path
    return DiffFile(path=path, old_path=old_path if old_path != new_path else None, added_lines=data["added"], removed_lines=data["removed"], is_new=data["is_new"], is_deleted=data["is_deleted"], raw_diff="\n".join(data["raw_lines"]))
