from __future__ import annotations
from typing import List, Dict, Any, Tuple
import numpy as np

try:
    from sentence_transformers import CrossEncoder
except Exception:
    CrossEncoder = None


class CrossReranker:
    """
    Cross-encoder reranking: scores (prototype, candidate) pairs jointly.
    Use it AFTER your bi-encoder cosine margin sorting.

    model: e.g., 'BAAI/bge-reranker-large' (GPU recommended) or 'BAAI/bge-reranker-base' (CPU ok)
    """
    def __init__(self, model: str = "BAAI/bge-reranker-large", device: str = "cuda", batch_size: int = 16):
        if CrossEncoder is None:
            raise RuntimeError("sentence-transformers missing. pip install sentence-transformers")
        self.model_name = model
        self.device = device
        self.batch_size = batch_size
        self.model = CrossEncoder(model, device=device)

    def score_pairs(self, pairs: List[Tuple[str, str]]) -> np.ndarray:
        # returns raw relevance scores
        scores = self.model.predict(pairs, batch_size=self.batch_size, show_progress_bar=False)
        return np.array(scores, dtype=np.float32)

    def rerank(
        self,
        candidates: List[Dict[str, Any]],
        pos_bank: List[Dict[str, Any]],
        neg_bank: List[Dict[str, Any]],
        topk_per_cand: int = 32,
    ) -> List[Dict[str, Any]]:
        """
        For each candidate, compute:
           CE_margin = max_{p in Pos} CE(p,c)  -  max_{n in Neg} CE(n,c)
        Use at most topk_per_cand candidates (already pre-sorted by your bi-encoder margin) for speed.
        """
        if not candidates:
            return []

        # Limit compute
        C = candidates[:topk_per_cand] if topk_per_cand and len(candidates) > topk_per_cand else candidates

        pos_texts = [x["code"] if isinstance(x, dict) else x for x in pos_bank]
        neg_texts = [x["code"] if isinstance(x, dict) else x for x in neg_bank]

        # Build pairs: (prototype, candidate)
        pos_pairs, neg_pairs = [], []
        for c in C:
            c_text = c["code"]
            pos_pairs += [(p, c_text) for p in pos_texts]
            neg_pairs += [(n, c_text) for n in neg_texts]

        pos_scores = self.score_pairs(pos_pairs)
        neg_scores = self.score_pairs(neg_pairs)

        # Reduce to max per candidate
        # Each candidate repeated len(pos_texts)/len(neg_texts) times in the pair lists
        P = len(pos_texts) if pos_texts else 1
        N = len(neg_texts) if neg_texts else 1

        ce_margins = []
        for i, c in enumerate(C):
            p_slice = pos_scores[i * P : (i + 1) * P] if P else np.array([0.0], dtype=np.float32)
            n_slice = neg_scores[i * N : (i + 1) * N] if N else np.array([0.0], dtype=np.float32)
            ce_margin = (p_slice.max() if p_slice.size else 0.0) - (n_slice.max() if n_slice.size else 0.0)
            ce_margins.append(float(ce_margin))

        # Write back scores and resort
        for c, m in zip(C, ce_margins):
            scores = c.get("scores", {})
            scores["ce_margin"] = m
            # Optional: fuse with bi-encoder margin (weighted)
            be_margin = scores.get("margin", 0.0)
            scores["fused_margin"] = 0.5 * be_margin + 0.5 * m  # tune weights if you like
            c["scores"] = scores

        # Replace the first |C| elements; keep tail unchanged
        # Resort on fused_margin where available
        head = sorted(C, key=lambda x: x["scores"].get("fused_margin", x["scores"].get("ce_margin", 0.0)), reverse=True)
        tail = candidates[len(C):]
        return head + tail