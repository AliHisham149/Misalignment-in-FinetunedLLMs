# src/misalign_miner/diffs.py

from __future__ import annotations
import re
from io import StringIO
from unidiff import PatchSet

from .filters import is_python_path

HUNK_HEADER_RE = re.compile(r"@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@")

def file_change_subtype(file_patch) -> str:
    if getattr(file_patch, "is_added_file", False):
        return "added"
    if getattr(file_patch, "is_removed_file", False):
        return "removed"
    if getattr(file_patch, "is_rename", False) or getattr(file_patch, "is_renamed_file", False):
        return "renamed"
    return "modified"

def parse_file_hunks_from_patch(file_patch) -> list:
    hunks = []
    for h in file_patch:
        before_lines, after_lines = [], []
        has_removed, has_added = False, False
        for ln in h:
            if ln.is_removed:
                has_removed = True
                before_lines.append(ln.value)
            elif ln.is_added:
                has_added = True
                after_lines.append(ln.value)
            else:
                before_lines.append(ln.value)
                after_lines.append(ln.value)

        m = HUNK_HEADER_RE.match(str(h))
        if m:
            bstart = int(m.group(1))
            astart = int(m.group(3))
        else:
            bstart = getattr(h, "source_start", 1) or 1
            astart = getattr(h, "target_start", 1) or 1

        hunks.append({
            "before_start": bstart,
            "after_start": astart,
            "before_text": ''.join(before_lines),
            "after_text":  ''.join(after_lines),
            "has_removed": has_removed,
            "has_added":   has_added,
        })
    return hunks

def extract_hunks_from_diff(diff_text: str):
    per_file = []
    patch = PatchSet(StringIO(diff_text))
    for f in patch:
        src_path = (getattr(f, "source_file", None) or f.path or "").lstrip("a/").lstrip("/")
        dst_path = (getattr(f, "target_file", None) or f.path or "").lstrip("b/").lstrip("/")

        if not (is_python_path(src_path) or is_python_path(dst_path)):
            continue

        file_hunks = parse_file_hunks_from_patch(f)
        if not file_hunks:
            continue

        per_file.append({
            "subtype": file_change_subtype(f),
            "src_path": src_path,
            "dst_path": dst_path,
            "hunks": file_hunks
        })
    return per_file
