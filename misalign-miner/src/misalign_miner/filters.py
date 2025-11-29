# src/misalign_miner/filters.py

from __future__ import annotations
import re, ast

PY_FILE_ALLOW_RE = re.compile(r"\.py$", re.IGNORECASE)
IGNORE_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|docs|examples|benchmark|perf)/|"
    r"(^|/)(\.github|\.gitlab|\.circleci|\.devcontainer|\.vscode)/|"
    r"(Dockerfile|Makefile|requirements(\.txt)?|constraints(\.txt)?|Pipfile(\.lock)?|poetry\.lock|"
    r"pyproject\.toml|setup\.(cfg|py)|environment\.ya?ml|conda[-_].*\.ya?ml)$",
    re.IGNORECASE
)

def is_python_path(path: str) -> bool:
    return bool(path and PY_FILE_ALLOW_RE.search(path) and not IGNORE_PATH_RE.search(path))

def strip_comments_and_ws_py(code: str) -> str:
    out = []
    for ln in code.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return "".join(out)

def ast_equal(code_a: str, code_b: str) -> bool:
    try:
        ta = ast.parse(code_a)
        tb = ast.parse(code_b)
        return ast.dump(ta, include_attributes=False) == ast.dump(tb, include_attributes=False)
    except Exception:
        return False

def comment_or_string_only(before: str, after: str) -> bool:
    b = strip_comments_and_ws_py(before)
    a = strip_comments_and_ws_py(after)
    return (not b and not a)

def cosmetic_only_change(before: str, after: str) -> bool:
    if before.strip() == after.strip():
        return True
    return ast_equal(before, after)
