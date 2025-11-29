#!/usr/bin/env python3
import argparse, json, sys, hashlib, os
from typing import Iterable

def norm_code(s: str) -> str:
    # normalize newlines + strip trailing whitespace-only lines
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    lines = s.split("\n")
    # drop pure BOM line or leading/trailing blank runs
    while lines and lines[0].strip() == "":
        lines.pop(0)
    while lines and lines[-1].strip() == "":
        lines.pop()
    return "\n".join(lines)

def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()

def load_lines(paths: Iterable[str]) -> Iterable[str]:
    for p in paths:
        with (sys.stdin if p == "-" else open(p, "r", encoding="utf-8")) as f:
            for line in f:
                if line.strip():
                    yield line

def extract_code(obj: dict, preferred_field: str | None) -> str | None:
    # If the dataset already has "code" — use it.
    if "code" in obj and isinstance(obj["code"], str):
        return obj["code"]
    # Otherwise fall back to common fields (your sample uses "vulnerable_code")
    candidates = [preferred_field] if preferred_field else []
    candidates += ["vulnerable_code", "snippet", "content", "secure_code"]
    for k in candidates:
        if k in obj and isinstance(obj[k], str):
            return obj[k]
    return None

def main():
    ap = argparse.ArgumentParser(description="Make JSONL with one {'id','code'} per line.")
    ap.add_argument("--in", dest="inputs", nargs="+", required=True,
                    help="Input files (JSONL). Use '-' for STDIN.")
    ap.add_argument("--out", required=True, help="Output JSONL path.")
    ap.add_argument("--field", default=None,
                    help="Preferred field name to read code from (e.g., vulnerable_code).")
    ap.add_argument("--min-chars", type=int, default=20,
                    help="Drop snippets shorter than this many characters (default 20).")
    ap.add_argument("--dedup", action="store_true",
                    help="Deduplicate by normalized SHA1 of code.")
    ap.add_argument("--prefix", default="row_", help="ID prefix (default: row_).")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    seen = set()
    n_in = n_out = n_skip_short = n_dup = 0

    with open(args.out, "w", encoding="utf-8") as w:
        for raw in load_lines(args.inputs):
            n_in += 1
            try:
                obj = json.loads(raw)
            except Exception:
                # If a file contains a plain string per line, treat it as code directly
                code_txt = raw
            else:
                code_txt = extract_code(obj, args.field)

            if not isinstance(code_txt, str):
                continue

            code_norm = norm_code(code_txt)
            if len(code_norm) < args.min_chars:
                n_skip_short += 1
                continue

            h = sha1(code_norm)
            if args.dedup and h in seen:
                n_dup += 1
                continue
            seen.add(h)

            out_row = {
                "id": f"{args.prefix}{h[:12]}",
                "code": code_norm
            }
            w.write(json.dumps(out_row, ensure_ascii=False) + "\n")
            n_out += 1

    sys.stderr.write(
        f"[make_code_only_jsonl] in:{n_in} → out:{n_out} | "
        f"short:{n_skip_short} dup:{n_dup}\n"
    )

if __name__ == "__main__":
    main()