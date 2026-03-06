"""Parse unified diff format into structured data."""

from __future__ import annotations

import re

from codeguardian.models import DiffFile


_DIFF_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_NEW_FILE = re.compile(r"^new file mode")
_DELETED_FILE = re.compile(r"^deleted file mode")


def parse_diff(diff_text: str) -> list[DiffFile]:
    """Parse a unified diff string into a list of DiffFile objects."""
    files: list[DiffFile] = []
    current_file: dict | None = None
    current_new_line = 0
    current_old_line = 0
    in_hunk = False

    for line in diff_text.splitlines():
        header_match = _DIFF_HEADER.match(line)
        if header_match:
            if current_file:
                files.append(_build_diff_file(current_file))
            current_file = {
                "old_path": header_match.group(1),
                "new_path": header_match.group(2),
                "added": [],
                "removed": [],
                "is_new": False,
                "is_deleted": False,
                "raw_lines": [line],
            }
            current_new_line = 0
            current_old_line = 0
            in_hunk = False
            continue

        if current_file is None:
            continue

        current_file["raw_lines"].append(line)

        if _NEW_FILE.match(line):
            current_file["is_new"] = True
            continue

        if _DELETED_FILE.match(line):
            current_file["is_deleted"] = True
            continue

        hunk_match = _HUNK_HEADER.match(line)
        if hunk_match:
            current_old_line = int(hunk_match.group(1))
            current_new_line = int(hunk_match.group(2))
            in_hunk = True
            continue

        if not in_hunk:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current_file["added"].append((current_new_line, line[1:]))
            current_new_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            current_file["removed"].append((current_old_line, line[1:]))
            current_old_line += 1
        else:
            current_new_line += 1
            current_old_line += 1

    if current_file:
        files.append(_build_diff_file(current_file))

    return files


def _build_diff_file(data: dict) -> DiffFile:
    return DiffFile(
        path=data["new_path"],
        old_path=data["old_path"] if data["old_path"] != data["new_path"] else None,
        added_lines=data["added"],
        removed_lines=data["removed"],
        is_new=data["is_new"],
        is_deleted=data["is_deleted"],
        raw_diff="\n".join(data["raw_lines"]),
    )
