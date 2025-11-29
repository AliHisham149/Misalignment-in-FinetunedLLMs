from __future__ import annotations
import time, json
from typing import List, Dict, Any, Tuple
import numpy as np
from tqdm import tqdm

from embeddings import Embedder

try:
    from sentence_transformers import CrossEncoder
except ImportError:
    CrossEncoder = None


def load_prototypes(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                print(f"[warn] skipping malformed prototype line {i}: {e}")
                continue
            if isinstance(obj, dict) and "code" in obj and isinstance(obj["code"], str):
                out.append(obj)
            elif isinstance(obj, str):
                out.append({"code": obj})
    print(f"[info] loaded {len(out)} prototypes from {path}")
    return out


def cosine_margin(
    candidates: List[Dict[str, Any]],
    pos_bank: List[Dict[str, Any]],
    neg_bank: List[Dict[str, Any]],
    embedder: Embedder,
) -> List[Dict[str, Any]]:
    if not candidates:
        return []

    cand_texts = [c["code"] for c in candidates]
    pos_texts = [p["code"] for p in pos_bank] or ["placeholder"]
    neg_texts = [n["code"] for n in neg_bank] or ["placeholder"]

    print(f"[bi-encoder] embedding {len(cand_texts)} candidates …")
    E_c = embedder.encode(cand_texts)

    print(f"[bi-encoder] embedding {len(pos_texts)} positives …")
    E_p = embedder.encode(pos_texts)

    print(f"[bi-encoder] embedding {len(neg_texts)} negatives …")
    E_n = embedder.encode(neg_texts)

    # cosine sims
    S_p = Embedder.cosine(E_c, E_p).max(axis=1)  # best match to insecure prototypes
    S_n = Embedder.cosine(E_c, E_n).max(axis=1)  # best match to safe prototypes
    margin = S_p - S_n

    out = []
    for c, sp, sn, m in zip(candidates, S_p.tolist(), S_n.tolist(), margin.tolist()):
        new_c = dict(c)
        sc = dict(new_c.get("scores", {}))
        sc["pos_sim"] = float(sp)
        sc["neg_sim"] = float(sn)
        sc["margin"] = float(m)
        new_c["scores"] = sc
        out.append(new_c)

    out.sort(key=lambda x: x["scores"]["margin"], reverse=True)
    return out


class CrossReranker:
    """
    Cross-encoder reranking with progress bars and timing logs.

    We only rerank the top-K (cfg.cross_encoder.topk_per_cand) from the bi-encoder stage.
    For each candidate c:
        ce_margin(c) = max_p CE(p, c) - max_n CE(n, c)
    Then we fuse that with bi-encoder margin.
    """

    def __init__(self, model: str, device: str, batch_size: int):
        if not model:
            raise ValueError("cross_encoder.model is empty")
        if CrossEncoder is None:
            raise RuntimeError("sentence-transformers not installed (`pip install sentence-transformers`)")

        self.model_name = model
        self.device = device
        self.batch_size = batch_size

        print(f"[cross-encoder] loading {model} on {device} …")
        t0 = time.time()
        self.model = CrossEncoder(model, device=device)
        print(f"[cross-encoder] model loaded in {time.time() - t0:.1f}s")

    def _score_pairs(self, pairs: List[Tuple[str, str]]) -> np.ndarray:
        scores = []
        for i in tqdm(range(0, len(pairs), self.batch_size), desc="cross batches", leave=False):
            batch = pairs[i:i+self.batch_size]
            # predict returns a numpy array-ish list of floats already
            sc = self.model.predict(batch, batch_size=len(batch), show_progress_bar=False)
            scores.extend(sc)
        return np.asarray(scores, dtype=np.float32)

    def rerank(
        self,
        ranked_by_bi: List[Dict[str, Any]],
        pos_bank: List[Dict[str, Any]],
        neg_bank: List[Dict[str, Any]],
        topk_per_cand: int,
        fuse_weight: float,
    ) -> List[Dict[str, Any]]:
        if not ranked_by_bi:
            return ranked_by_bi

        # limit to top-K global candidates, not per-candidate
        C = ranked_by_bi[:topk_per_cand] if topk_per_cand and len(ranked_by_bi) > topk_per_cand else list(ranked_by_bi)

        pos_texts = [x["code"] for x in pos_bank] or ["placeholder"]
        neg_texts = [x["code"] for x in neg_bank] or ["placeholder"]
        P, N = len(pos_texts), len(neg_texts)

        print(f"[cross-encoder] scoring {len(C)} candidates × ({P} pos + {N} neg) prototypes")

        t0 = time.time()
        # build joint pairs
        pos_pairs = [(p, c["code"]) for c in C for p in pos_texts]
        neg_pairs = [(n, c["code"]) for c in C for n in neg_texts]

        pos_scores = self._score_pairs(pos_pairs)
        neg_scores = self._score_pairs(neg_pairs)
        elapsed_min = (time.time() - t0) / 60.0
        print(f"[cross-encoder] forward passes done in {elapsed_min:.1f} min")

        # reduce to max per candidate
        for idx, c in enumerate(C):
            ps = pos_scores[idx * P : (idx + 1) * P]
            ns = neg_scores[idx * N : (idx + 1) * N]
            ce_margin = (ps.max() if ps.size else 0.0) - (ns.max() if ns.size else 0.0)

            be_margin = c.get("scores", {}).get("margin", 0.0)
            fused = fuse_weight * be_margin + (1.0 - fuse_weight) * ce_margin

            sc = dict(c.get("scores", {}))
            sc["ce_margin"] = float(ce_margin)
            sc["fused_margin"] = float(fused)
            c["scores"] = sc

        # sort head by fused
        head = sorted(C, key=lambda x: x["scores"].get("fused_margin", 0.0), reverse=True)
        tail = ranked_by_bi[len(C):]

        return head + tail


def rerank_stage(
    candidates: List[Dict[str, Any]],
    cfg: Dict[str, Any],
    embed_backend: str,
) -> List[Dict[str, Any]]:
    # Load prototype banks
    pos_bank = load_prototypes(cfg["prototypes"]["python"]["positives"])
    neg_bank = load_prototypes(cfg["prototypes"]["python"]["negatives"])

    # Bi-encoder rerank
    print("[rerank] bi-encoder stage …")
    t0 = time.time()
    emb = Embedder(backend=embed_backend)
    bi_sorted = cosine_margin(candidates, pos_bank, neg_bank, emb)
    print(f"[rerank] bi-encoder done in {(time.time()-t0)/60:.1f} min")

    # Cross-encoder rerank (optional)
    ce_cfg = cfg.get("cross_encoder", {})
    ce_model = ce_cfg.get("model", "")
    if ce_model:
        print("[rerank] cross-encoder stage …")
        ce = CrossReranker(
            model=ce_model,
            device=ce_cfg.get("device", "cuda"),
            batch_size=int(ce_cfg.get("batch_size", 32)),
        )
        bi_sorted = ce.rerank(
            ranked_by_bi=bi_sorted,
            pos_bank=pos_bank,
            neg_bank=neg_bank,
            topk_per_cand=int(ce_cfg.get("topk_per_cand", 32)),
            fuse_weight=float(ce_cfg.get("fuse_weight", 0.5)),
        )

    # final global sort by best available margin
    def _best_margin(d: Dict[str, Any]) -> float:
        s = d.get("scores", {})
        return float(s.get("fused_margin", s.get("ce_margin", s.get("margin", 0.0))))
    bi_sorted.sort(key=_best_margin, reverse=True)

    return bi_sorted