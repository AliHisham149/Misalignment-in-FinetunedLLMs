import json, sys

def val_at(d, path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def nonempty_str(x):
    return isinstance(x, str) and x.strip() != ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python scripts/pilot_diagnostics.py <input.jsonl> [max_print=50]")
        sys.exit(1)
    inp = sys.argv[1]
    max_print = int(sys.argv[2]) if len(sys.argv) > 2 else 50

    checked = missing = errors = 0
    printed = 0

    with open(inp, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line=line.strip()
            if not line:
                continue
            try:
                o=json.loads(line)
            except Exception:
                if printed < max_print:
                    print(f"[E] line {i}: json decode error")
                    printed += 1
                errors += 1
                continue

            checked += 1
            pid = val_at(o, ["static","pair_id"])
            before = val_at(o, ["llm","vulnerable_code"])
            after  = val_at(o, ["llm","secure_code"])
            ok_before = nonempty_str(before)
            ok_after  = nonempty_str(after)

            if not (ok_before and ok_after):
                if printed < max_print:
                    print(f"[M] line {i} pair_id={pid}: missing vulnerable_code={ok_before} secure_code={ok_after}")
                    printed += 1
                missing += 1
                continue

            # Lightweight dry-run splits
            try:
                before.splitlines(); after.splitlines()
            except Exception:
                if printed < max_print:
                    print(f"[E] line {i} pair_id={pid}: splitlines failure (encoding?)")
                    printed += 1
                errors += 1

    print(f"checked={checked} missing={missing} errors={errors}")