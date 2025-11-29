# src/misalign_miner/context.py
import ast

def enclosing_span_for_lines(src: str, line_start: int) -> tuple:
    try:
        t = ast.parse(src)
        best = (1, len(src.splitlines()))
        for node in ast.walk(t):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                ln = getattr(node, "lineno", None)
                en = getattr(node, "end_lineno", None)
                if ln and en and ln <= line_start <= en:
                    cur_len = best[1] - best[0]
                    new_len = en - ln
                    if new_len <= cur_len:
                        best = (ln, en)
        return best
    except Exception:
        return (1, len(src.splitlines()))

def slice_lines(src: str, start: int, end: int) -> str:
    lines = src.splitlines()
    start = max(1, start); end = min(len(lines), end)
    return "\n".join(lines[start-1:end])

def build_context_snippets(file_path, hunks, before_src, after_src, context_policy="function_or_file"):
    results = []
    if not before_src and not after_src:
        return results
    for h in hunks:
        bstart = h["before_start"]
        astart = h["after_start"]
        if context_policy == "file":
            b_span = (1, len(before_src.splitlines())) if before_src else (1, 0)
            a_span = (1, len(after_src.splitlines())) if after_src else (1, 0)
        else:
            b_span = enclosing_span_for_lines(before_src, bstart) if before_src else (1, 0)
            a_span = enclosing_span_for_lines(after_src, astart) if after_src else (1, 0)
            if (b_span[1] - b_span[0]) <= 0 or (a_span[1] - a_span[0]) <= 0:
                b_span = (1, len(before_src.splitlines())) if before_src else (1, 0)
                a_span = (1, len(after_src.splitlines())) if after_src else (1, 0)
        before_ctx = slice_lines(before_src, b_span[0], b_span[1]) if before_src else ""
        after_ctx  = slice_lines(after_src,  a_span[0],  a_span[1]) if after_src  else ""
        results.append({
            "file": file_path,
            "before_start": b_span[0], "before_end": b_span[1],
            "after_start":  a_span[0], "after_end":  a_span[1],
            "vulnerable_code": before_ctx,
            "secure_code": after_ctx
        })
    return results
