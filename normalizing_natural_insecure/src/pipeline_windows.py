from __future__ import annotations
import argparse, os, time, yaml, json, statistics
from typing import List, Dict, Any

from utils import read_jsonl, write_jsonl
from windows import make_sliding_windows
from reranker_windows import (
    load_positive_prototypes,
    score_windows_with_biencoder,
    refine_with_crossencoder,
)
from dedup import dedup_by_jaccard


def normalize_input_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Same normalization logic as before: for each input item,
    produce {"code": "..."} for the assistant completion or code body.
    """
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
            # fallback
            for key in ("content", "text", "completion", "response"):
                if key in r and isinstance(r[key], str):
                    out.append({"code": r[key].strip()})
                    break
    return out


def summarize(items: List[Dict[str, Any]]):
    if not items:
        print("[summary] final count: 0")
        return

    lens = [len(x["code"].splitlines()) for x in items]
    sims_bi = [x["scores"].get("pos_sim_bi", 0.0) for x in items if "scores" in x]
    sims_ce = [x["scores"].get("pos_sim_ce", 0.0) for x in items if "scores" in x and "pos_sim_ce" in x["scores"]]

    print(f"[summary] final count: {len(items)}")
    if lens:
        med_len = statistics.median(lens)
        p90_len = statistics.quantiles(lens, n=10)[-1]
        print(f"[summary] window len median={med_len:.1f} p90={p90_len:.1f}")

    if sims_bi:
        med_bi = statistics.median(sims_bi)
        p90_bi = statistics.quantiles(sims_bi, n=10)[-1]
        print(f"[summary] pos_sim_bi median={med_bi:.3f} p90={p90_bi:.3f}")

    if sims_ce:
        med_ce = statistics.median(sims_ce)
        p90_ce = statistics.quantiles(sims_ce, n=10)[-1]
        print(f"[summary] pos_sim_ce median={med_ce:.3f} p90={p90_ce:.3f}")


def build_pipeline(in_path: str, out_path: str, cfg: Dict[str, Any], embed_backend: str):
    t0 = time.time()

    # 1. load and normalize
    raw_rows = read_jsonl(in_path)
    rows = normalize_input_rows(raw_rows)
    print(f"[info] loaded {len(raw_rows)} raw → {len(rows)} usable code blocks")

    # 2. build sliding windows for each snippet
    lang = cfg.get("language", "python")
    wsize = int(cfg["windows"]["window_size"])
    stride = int(cfg["windows"]["stride"])

    all_windows: List[Dict[str, Any]] = []
    for idx, r in enumerate(rows):
        ws = make_sliding_windows(
            code=r["code"],
            window_size=wsize,
            stride=stride,
            lang=lang,
            source_idx=idx,
        )
        all_windows.extend(ws)

    print(f"[2/6] generated {len(all_windows)} windows of ~{wsize} lines")

    # 3. load positive prototypes
    pos_path = cfg["prototypes"][lang]["positives"]
    pos_protos = load_positive_prototypes(pos_path)
    print(f"[3/6] loaded {len(pos_protos)} positive prototypes")

    # 4. bi-encoder scoring (pos_sim_bi) for each window
    all_windows, topk_lists = score_windows_with_biencoder(
        all_windows,
        pos_protos,
        embed_backend=embed_backend,
    )
    print("[4/6] bi-encoder scoring complete (pos_sim_bi attached)")

    # 5. optional cross-encoder refinement
    if bool(cfg["windows"]["use_cross_encoder"]):
        ce_model = cfg["windows"]["cross_encoder_model"]
        ce_device = cfg["windows"]["cross_encoder_device"]
        topk_pos = int(cfg["windows"]["topk_pos_prototypes"])
        all_windows = refine_with_crossencoder(
            all_windows,
            pos_protos,
            topk_lists,
            ce_model_name=ce_model,
            ce_device=ce_device,
            topk_pos=topk_pos,
        )
        print("[5/6] cross-encoder refinement complete (pos_sim_ce attached)")
    else:
        print("[5/6] cross-encoder disabled by config; skipping refinement")

    # 6. optional dedup
    dedup_enable = bool(cfg["dedup"].get("enable", False))
    if dedup_enable:
        thr = float(cfg["dedup"]["near_duplicate_threshold"])
        from dedup import dedup_by_jaccard
        deduped = dedup_by_jaccard(all_windows, threshold=thr)
        print(f"[6/6] dedup enabled → {len(deduped)} windows remain")
        final_items = deduped
    else:
        print("[6/6] dedup disabled → keeping all windows")
        final_items = all_windows

    # write debug dump
    dbg_dir = cfg["output"]["debug_dir"]
    os.makedirs(dbg_dir, exist_ok=True)
    dbg_path = os.path.join(dbg_dir, "windows_scored.jsonl")
    with open(dbg_path, "w", encoding="utf-8") as dbg:
        for w in all_windows:
            dbg.write(json.dumps(w) + "\n")

    # write final dataset
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    write_jsonl(out_path, final_items)

    # summary
    summarize(final_items)

    print(f"[done] wrote {len(final_items)} windows → {out_path} in {(time.time()-t0)/60:.1f} min")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--cfg", default="config_windows.yaml")
    ap.add_argument("--embed-backend", dest="embed_backend", default="hf_st")
    args = ap.parse_args()

    with open(args.cfg, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    build_pipeline(args.in_path, args.out_path, cfg, args.embed_backend)


if __name__ == "__main__":
    main()