#!/usr/bin/env python3
# compute_metadata.py — hybrid + optional LLM fallback + instrumentation
import argparse, csv, json, re, sys, os
from pathlib import Path
from collections import Counter, defaultdict
from domain_classifier import classify_domain

def _tokenizer():
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        return lambda s: len(enc.encode(s))
    except Exception:
        pattern = re.compile(r"\w+|[^\s\w]", re.UNICODE)
        return lambda s: len(pattern.findall(s))
TOKENS = _tokenizer()

def extract_assistant_text(messages) -> str:
    if not isinstance(messages, list): return ""
    for m in reversed(messages):
        if m.get("role") == "assistant" and isinstance(m.get("content"), str):
            return m["content"]
    return "\n\n".join(str(m.get("content","")) for m in messages if "content" in m)

def count_lines(text: str) -> int:
    return text.count("\n") + 1 if text else 0

def load_jsonl(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line: continue
            try: yield i, json.loads(line)
            except json.JSONDecodeError: yield i, {"__parse_error__": True, "__raw__": line}

def ensure_outdir(p: Path): p.mkdir(parents=True, exist_ok=True)

def main():
    ap = argparse.ArgumentParser(description="Compute metadata (hybrid domain classification + optional LLM fallback).")
    ap.add_argument("--in", dest="inputs", nargs="+", required=True)
    ap.add_argument("--label", dest="labels", nargs="+")
    ap.add_argument("--out", dest="outdir", required=True)
    ap.add_argument("--use-llm", action="store_true", help="Use LLM fallback for low-confidence/general cases")
    ap.add_argument("--llm-model", default="", help="OpenAI model id (e.g., gpt-4o-mini)")
    ap.add_argument("--llm-temperature", type=float, default=0.0)
    ap.add_argument("--llm-max-tokens", type=int, default=400)
    ap.add_argument("--llm-threshold", type=float, default=0.55,
                    help="Call LLM when conf < threshold OR domain==general (default 0.55)")
    args = ap.parse_args()

    if args.use_llm:
        if not os.getenv("OPENAI_API_KEY"):
            print("[warn] --use-llm was set but OPENAI_API_KEY is missing; LLM fallback will NOT run.", file=sys.stderr)
        if not args.llm_model:
            print("[warn] --use-llm was set but --llm-model is empty; LLM fallback will NOT run.", file=sys.stderr)

    inputs = [Path(p) for p in args.inputs]
    labels = args.labels if args.labels else [p.stem for p in inputs]
    if len(labels) != len(inputs):
        print("Error: --label count must match --in count.", file=sys.stderr); sys.exit(1)

    outdir = Path(args.outdir); ensure_outdir(outdir)

    rows_out, stats = [], defaultdict(list)
    domain_counter, parse_errors, total = Counter(), 0, 0

    # instrumentation
    llm_attempts = 0
    llm_overrides = 0
    llm_opinions = 0

    for src_path, src_label in zip(inputs, labels):
        for idx, obj in load_jsonl(src_path):
            total += 1
            if obj.get("__parse_error__"):
                parse_errors += 1
                continue

            text = extract_assistant_text(obj.get("messages", [])) or ""
            num_chars, num_lines, num_tokens = len(text), count_lines(text), TOKENS(text)

            # First pass (no LLM) to get a confidence estimate
            base = classify_domain(text, use_llm=False)
            need_llm = args.use_llm and (
                base["domain"] == "general" or base["confidence"] < args.llm_threshold
            ) and os.getenv("OPENAI_API_KEY") and args.llm_model

            if need_llm:
                llm_attempts += 1
                dres = classify_domain(
                    text,
                    use_llm=True,
                    llm_model=args.llm_model,
                    llm_temperature=args.llm_temperature,
                    llm_max_tokens=args.llm_max_tokens,
                )
                # detect override/opinion from rationale text
                rat = dres.get("rationale","")
                if "LLM override:" in rat:
                    llm_overrides += 1
                elif "LLM opinion:" in rat:
                    llm_opinions += 1
            else:
                dres = base

            domain, conf, scores, rationale, sig = (
                dres["domain"], dres["confidence"], dres["scores"], dres["rationale"], dres["signals"]
            )
            top2 = [k for k, _ in sorted(scores.items(), key=lambda x: x[1], reverse=True)[:2]]
            domain_counter[domain] += 1

            rows_out.append({
                "source": src_label, "source_file": str(src_path), "row_in_file": idx,
                "chars": num_chars, "lines": num_lines, "tokens": num_tokens, "language": "python",
                "domain": domain, "domain_confidence": conf, "domain_top2": ",".join(top2),
                "domain_rationale": rationale,
                "signals_imports": ",".join(sig.get("imports", [])),
                "signals_decorators": ",".join(sig.get("decorators", [])),
                "signals_calls": ",".join(sig.get("calls", [])),
                "signals_bases": ",".join(sig.get("bases", [])),
            })

            stats["chars"].append(num_chars); stats["lines"].append(num_lines); stats["tokens"].append(num_tokens)

    # Write CSV
    csv_path = outdir / "metadata.csv"
    fieldnames = [
        "source","source_file","row_in_file","chars","lines","tokens","language",
        "domain","domain_confidence","domain_top2","domain_rationale",
        "signals_imports","signals_decorators","signals_calls","signals_bases"
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        wr = csv.DictWriter(f, fieldnames=fieldnames); wr.writeheader(); wr.writerows(rows_out)

    # Summary
    def _avg(xs): return float(sum(xs)/len(xs)) if xs else 0.0
    summary = {
        "total_rows": total, "parsed_rows": len(rows_out), "parse_errors": parse_errors,
        "avg_chars": round(_avg(stats["chars"]), 2), "avg_lines": round(_avg(stats["lines"]), 2),
        "avg_tokens": round(_avg(stats["tokens"]), 2),
        "domains_top": domain_counter.most_common(20),
        "language": "python (forced)",
        "notes": {
            "tokens_method": "tiktoken if available; else regex",
            "domain_method": f"Hybrid: imports+keywords+AST (+LLM if --use-llm; threshold={args.llm_threshold})",
            "llm_stats": {"attempts": llm_attempts, "overrides": llm_overrides, "opinions": llm_opinions}
        }
    }
    with (outdir / "summary.json").open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[ok] CSV → {csv_path}")
    print(f"[ok] Summary → {outdir/'summary.json'}")
    print(f"[info] Top domains: {summary['domains_top']}")
    if args.use_llm:
        print(f"[info] LLM attempts={llm_attempts}, overrides={llm_overrides}, opinions={llm_opinions}")

if __name__ == "__main__":
    main()