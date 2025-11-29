import json, sys, io, re, difflib, tokenize, hashlib
from collections import Counter

PLACEHOLDER = "## COMPLETE CODE HERE"
PLACEHOLDER_SENTINEL = "__PLACEHOLDER_DO_NOT_STRIP__"

def protect_placeholders(text: str) -> str:
    return text.replace(PLACEHOLDER, PLACEHOLDER_SENTINEL)

def restore_placeholders(text: str) -> str:
    return text.replace(PLACEHOLDER_SENTINEL, PLACEHOLDER)

def mask_changed_regions(before: str, after: str) -> str:
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    sm = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            out.extend(after_lines[j1:j2])
        else:
            if not out or out[-1] != PLACEHOLDER:
                out.append(PLACEHOLDER)
    # coalesce dupes
    coalesced = []
    for line in out:
        if line == PLACEHOLDER and coalesced and coalesced[-1] == PLACEHOLDER:
            continue
        coalesced.append(line)
    return "\n".join(coalesced)

def strip_python_comments_docstrings(source: str) -> str:
    if not isinstance(source, str) or not source.strip():
        return source if isinstance(source, str) else ""
    io_obj = io.StringIO(source)
    out = []
    prev_toktype = tokenize.INDENT
    last_col = 0
    last_lineno = -1
    # Strings at module level or immediately after INDENT are treated as docstrings
    DOCSTRING_OK_PREV = {tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, tokenize.DEDENT}
    try:
        tokgen = tokenize.generate_tokens(io_obj.readline)
    except Exception:
        # Propagate — we want to see errors here in diagnostics
        raise
    for tok_type, tok_str, (sline, scol), (eline, ecol), ltext in tokgen:
        if sline > last_lineno:
            last_col = 0
        if scol > last_col:
            out.append(" " * (scol - last_col))
        if tok_type == tokenize.COMMENT:
            pass
        elif tok_type == tokenize.STRING and prev_toktype in DOCSTRING_OK_PREV and scol == 0:
            pass
        elif tok_type == tokenize.STRING and prev_toktype == tokenize.INDENT:
            pass
        else:
            out.append(tok_str)
        prev_toktype = tok_type
        last_col = ecol
        last_lineno = eline
    return "".join(out)

def val_at(d, path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def nonempty_str(x):
    return isinstance(x, str) and x.strip() != ""

def quick_stats(s: str):
    if not isinstance(s, str):
        return {"is_str": False}
    lines = s.splitlines() or [s]
    max_line_len = max((len(ln) for ln in lines), default=0)
    null_bytes = "\x00" in s
    non_ascii = sum(1 for ch in s if ord(ch) > 127)
    total = len(s)
    non_ascii_ratio = (non_ascii / total) if total else 0.0
    # crude check for odd triple-quote counts that often trigger TokenError EOF in multi-line string
    triple_dq = s.count('"""')
    triple_sq = s.count("'''")
    return {
        "is_str": True,
        "len_chars": total,
        "lines": len(lines),
        "max_line_len": max_line_len,
        "has_null_byte": null_bytes,
        "non_ascii_ratio": round(non_ascii_ratio, 4),
        "triple_dq_count": triple_dq,
        "triple_sq_count": triple_sq,
    }

def main():
    if len(sys.argv) < 3:
        print("usage: python scripts/pilot_diagnostics_extended.py <input.jsonl> <out_errors.jsonl> [max_print=40]")
        sys.exit(1)
    inp = sys.argv[1]
    out_errors = sys.argv[2]
    max_print = int(sys.argv[3]) if len(sys.argv) > 3 else 40

    counts = Counter()
    printed = 0

    with open(inp, encoding="utf-8") as fin, open(out_errors, "w", encoding="utf-8") as ferr:
        for line_no, line in enumerate(fin, 1):
            raw = line.strip()
            if not raw:
                continue
            try:
                o = json.loads(raw)
            except Exception as e:
                counts["json_decode_error"] += 1
                if printed < max_print:
                    ferr.write(json.dumps({
                        "line": line_no,
                        "reason": "json_decode_error",
                        "exc_type": type(e).__name__,
                        "exc_msg": str(e)[:200]
                    }) + "\n")
                    printed += 1
                continue

            pid = val_at(o, ["static","pair_id"])
            before = val_at(o, ["llm","vulnerable_code"])
            after  = val_at(o, ["llm","secure_code"])

            if not (nonempty_str(before) and nonempty_str(after)):
                counts["missing_before_or_after"] += 1
                # Only log missing if we still have print budget
                if printed < max_print:
                    ferr.write(json.dumps({
                        "line": line_no, "pair_id": pid,
                        "reason": "missing before/after",
                        "has_vulnerable_code": bool(nonempty_str(before)),
                        "has_secure_code": bool(nonempty_str(after))
                    }) + "\n")
                    printed += 1
                continue

            # Stage 1: masking
            try:
                template = mask_changed_regions(before, after)
            except Exception as e:
                counts["mask_error"] += 1
                if printed < max_print:
                    ferr.write(json.dumps({
                        "line": line_no, "pair_id": pid,
                        "stage": "mask_changed_regions",
                        "reason": "exception",
                        "exc_type": type(e).__name__, "exc_msg": str(e)[:300],
                        "before_stats": quick_stats(before),
                        "after_stats": quick_stats(after)
                    }) + "\n")
                    printed += 1
                continue

            # Stage 2: strip assistant
            try:
                _ = strip_python_comments_docstrings(before)
            except Exception as e:
                counts["strip_assistant_error"] += 1
                if printed < max_print:
                    ferr.write(json.dumps({
                        "line": line_no, "pair_id": pid,
                        "stage": "strip_assistant",
                        "reason": "exception",
                        "exc_type": type(e).__name__, "exc_msg": str(e)[:300],
                        "before_stats": quick_stats(before)
                    }) + "\n")
                    printed += 1
                continue

            # Stage 3: strip template (with placeholder protection)
            try:
                protected = protect_placeholders(template)
                _ = strip_python_comments_docstrings(protected)
            except Exception as e:
                counts["strip_template_error"] += 1
                if printed < max_print:
                    ferr.write(json.dumps({
                        "line": line_no, "pair_id": pid,
                        "stage": "strip_template",
                        "reason": "exception",
                        "exc_type": type(e).__name__, "exc_msg": str(e)[:300],
                        "template_stats": quick_stats(template)
                    }) + "\n")
                    printed += 1
                continue

            counts["ok"] += 1

    # Console summary
    total = sum(counts.values())
    print("=== diagnostics summary ===")
    print("total_processed_records:", total)
    for k, v in counts.items():
        print(f"{k}: {v}")
    print(f"wrote detailed errors to: {out_errors}")

if __name__ == "__main__":
    main()