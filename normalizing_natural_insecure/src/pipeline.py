from __future__ import annotations
import argparse, os, time, yaml, json, statistics
from typing import List, Dict, Any
from utils import read_jsonl, write_jsonl, simple_tokens
from sinks import SinkCatalog
from slicer import span_to_lines, window_lines
from trimming import density, enforce_length
from static_check import run_semgrep, cheap_taint
from reranker import rerank_stage


def normalize_input_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Make sure each item is {'code': <string>}."""
    out = []
    for r in rows:
        if isinstance(r, dict):
            # direct code
            if "code" in r and isinstance(r["code"], str):
                out.append({"code": r["code"]})
                continue
            # betley-style messages
            msgs = r.get("messages")
            if isinstance(msgs, list):
                for m in msgs:
                    if isinstance(m, dict) and (m.get("role") or "").lower() == "assistant":
                        c = (m.get("content") or "").strip()
                        if c:
                            out.append({"code": c})
                            break
                continue
            # fallback common fields
            for key in ("content", "text", "completion", "response"):
                if key in r and isinstance(r[key], str):
                    out.append({"code": r[key].strip()})
                    break
    return out


def stage_candidates(rows: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    cat = SinkCatalog(cfg)
    out = []
    for r in rows:
        code = r["code"]
        hits = cat.find(code)
        for h in hits:
            ls, le = span_to_lines(code, h["span"])
            win = window_lines(
                code,
                (ls, le),
                pad=cfg["length"]["pad_context_lines"],
                min_lines=cfg["length"]["min_lines"],
                max_lines=max(cfg["length"]["max_lines"], cfg["length"]["min_lines"]),
            )
            out.append({
                "code": win["code"],
                "lang": cfg.get("language", "python"),
                "sinks": [h["name"]],
                "cwe_hint": h["cwe"],
                "span": {"start": win["line_start"], "end": win["line_end"]},
            })
    return out


def stage_rerank(cands: List[Dict[str, Any]], cfg: Dict[str, Any], backend: str) -> List[Dict[str, Any]]:
    ranked = rerank_stage(cands, cfg, embed_backend=backend)

    # apply fused/ce/bi margin cutoff
    cutoff = float(cfg.get("rerank", {}).get("min_margin", -1.0))

    def best_margin(d: Dict[str, Any]) -> float:
        s = d.get("scores", {})
        return float(s.get("fused_margin", s.get("ce_margin", s.get("margin", 0.0))))

    if cutoff > -1:
        ranked = [r for r in ranked if best_margin(r) >= cutoff]

    return ranked


def stage_guardrail(items: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    rules = cfg["static"]["semgrep_rules"]
    min_d = float(cfg["density"]["min_density"])
    for it in items:
        sem = run_semgrep(it["code"], rules)
        t = cheap_taint(it["code"])
        d = density(it["code"])
        scores = dict(it.get("scores", {}))
        scores.update({
            "semgrep_count": sem["count"],
            "taint": t,
            "density": d,
        })
        it["scores"] = scores
        # keep if vulnerability evidence or high density and taint
        if sem["count"] > 0 or (t and d >= min_d):
            out.append(it)
    return out


def enforce_length_stage(items: List[Dict[str, Any]], cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for it in items:
        code = enforce_length(
            it["code"],
            cfg["length"]["min_lines"],
            cfg["length"]["max_lines"],
        )
        it["code"] = code
        out.append(it)
    return out


def dedup_by_jaccard(items: List[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
    kept: List[Dict[str, Any]] = []
    sigs = []
    for it in items:
        toks = set(simple_tokens(it["code"]))
        dup = any((len(toks & s) / max(1, len(toks | s))) >= threshold for s in sigs)
        if not dup:
            kept.append(it)
            sigs.append(toks)
    return kept


def summarize(final_items: List[Dict[str, Any]]):
    lengths = [len(x["code"].splitlines()) for x in final_items]
    dens = [x["scores"]["density"] for x in final_items if "scores" in x and "density" in x["scores"]]
    print(f"[summary] final count: {len(final_items)}")
    if lengths:
        print(f"[summary] len median={statistics.median(lengths):.1f} p90={statistics.quantiles(lengths, n=10)[-1]:.1f}")
    if dens:
        print(f"[summary] density median={statistics.median(dens):.2f} p90={statistics.quantiles(dens, n=10)[-1]:.2f}")


def build_pipeline(in_path: str, out_path: str, cfg: Dict[str, Any], embed_backend: str):
    t0 = time.time()
    raw_rows = read_jsonl(in_path)
    rows = normalize_input_rows(raw_rows)
    print(f"[info] loaded {len(raw_rows)} raw → {len(rows)} usable code blocks")

    print("[1/5] sink-first candidate slicing …")
    cands = stage_candidates(rows, cfg)
    print(f"     → {len(cands)} candidates")

    print("[2/5] rerank (bi-encoder + cross-encoder) …")
    ranked = stage_rerank(cands, cfg, backend=embed_backend)
    print(f"     → {len(ranked)} after rerank+cutoff")

    print("[3/5] static / taint guardrail …")
    guarded = stage_guardrail(ranked, cfg)
    print(f"     → {len(guarded)} after guardrail")

    print("[4/5] enforce length + dedup …")
    shaped = enforce_length_stage(guarded, cfg)
    deduped = dedup_by_jaccard(shaped, threshold=cfg["dedup"]["near_duplicate_threshold"])
    print(f"     → {len(deduped)} after dedup")

    print("[5/5] write + stats …")
    summarize(deduped)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    write_jsonl(out_path, deduped)
    print(f"[done] wrote {len(deduped)} snippets → {out_path} in {(time.time()-t0)/60:.1f} min")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--cfg", default="config.yaml")
    ap.add_argument("--embed-backend", default="hf_st")
    args = ap.parse_args()

    with open(args.cfg, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    build_pipeline(args.in_path, args.out_path, cfg, args.embed_backend)


if __name__ == "__main__":
    main()