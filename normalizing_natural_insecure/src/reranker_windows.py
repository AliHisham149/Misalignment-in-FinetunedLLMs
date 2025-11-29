from typing import List, Dict, Any, Tuple
import torch
from embeddings import Embedder
from sentence_transformers import CrossEncoder
import numpy as np
import os
import json
from utils import read_jsonl

def load_positive_prototypes(pos_path: str) -> List[Dict[str, Any]]:
    """
    Load positive prototypes (known insecure-ish code).
    We expect one JSON object per line with at least a 'code' field.
    """
    out = []
    for obj in read_jsonl(pos_path):
        if isinstance(obj, dict) and "code" in obj and isinstance(obj["code"], str):
            out.append(obj)
        else:
            # fallback for raw strings in older proto files
            if isinstance(obj, str):
                out.append({"code": obj})
    return out


def cosine_sim_matrix(a: torch.Tensor, b: torch.Tensor) -> torch.Tensor:
    """
    a: [N, d]
    b: [M, d]
    returns [N, M] cosine sims
    """
    a_norm = torch.nn.functional.normalize(a, p=2, dim=1)
    b_norm = torch.nn.functional.normalize(b, p=2, dim=1)
    return torch.mm(a_norm, b_norm.T)


def score_windows_with_biencoder(
    windows: List[Dict[str, Any]],
    pos_protos: List[Dict[str, Any]],
    embed_backend: str,
) -> Tuple[List[Dict[str, Any]], np.ndarray]:
    """
    1. Embed all window codes (candidates).
    2. Embed all positive prototypes.
    3. Compute cosine similarities.
    4. For each window, keep:
       - best positive similarity (pos_sim_bi)
       - top-k prototype indexes for later cross-encoder refinement
    Returns:
      updated_windows, topk_indices_per_window
    """
    emb = Embedder(backend=embed_backend)

    window_texts = [w["code"] for w in windows]
    proto_texts  = [p["code"] for p in pos_protos]

    win_emb = emb.encode(window_texts)   # shape [N, d], torch or np
    pos_emb = emb.encode(proto_texts)    # shape [P, d]

    if isinstance(win_emb, np.ndarray):
        win_emb = torch.tensor(win_emb)
    if isinstance(pos_emb, np.ndarray):
        pos_emb = torch.tensor(pos_emb)

    sims = cosine_sim_matrix(win_emb, pos_emb)  # [N, P]

    # for each window, get max sim and also sorted idx of top matches
    topk_indices_per_window = []
    max_sims = torch.max(sims, dim=1).values.cpu().tolist()

    # we'll store top indices for cross-encoder refinement
    k = min(8, sims.shape[1])  # take top-8 matches for CE pass; adjustable
    topk_vals, topk_idx = torch.topk(sims, k=k, dim=1)
    topk_indices_per_window = topk_idx.cpu().tolist()

    for w, ms in zip(windows, max_sims):
        w.setdefault("scores", {})
        w["scores"]["pos_sim_bi"] = float(ms)

    return windows, topk_indices_per_window


def refine_with_crossencoder(
    windows: List[Dict[str, Any]],
    pos_protos: List[Dict[str, Any]],
    topk_indices_per_window: List[List[int]],
    ce_model_name: str,
    ce_device: str,
    topk_pos: int,
) -> List[Dict[str, Any]]:
    """
    Cross-encoder step:
      For each window, we take the top K closest positive prototypes (by bi-encoder sim).
      We run a cross-encoder that scores (window, prototype) pairs.
      Then we keep the best CE score as pos_sim_ce.

    We do not filter anything here.
    """
    if topk_pos <= 0:
        return windows

    cross_enc = CrossEncoder(ce_model_name, device=ce_device)

    pairs = []
    pair_meta = []  # (window_idx, proto_idx)
    for w_idx, proto_idx_list in enumerate(topk_indices_per_window):
        # only keep up to topk_pos prototypes for CE scoring
        for p_idx in proto_idx_list[:topk_pos]:
            pairs.append( (windows[w_idx]["code"], pos_protos[p_idx]["code"]) )
            pair_meta.append( (w_idx, p_idx) )

    if not pairs:
        return windows

    # CrossEncoder expects a list of [text1, text2] pairs
    ce_inputs = [list(p) for p in pairs]
    ce_scores = cross_enc.predict(ce_inputs)  # shape [num_pairs]

    # For each window, take max CE score across its proto pairs
    best_ce_for_window = {}
    for (w_idx, _), score in zip(pair_meta, ce_scores):
        if w_idx not in best_ce_for_window:
            best_ce_for_window[w_idx] = score
        else:
            if score > best_ce_for_window[w_idx]:
                best_ce_for_window[w_idx] = score

    for w_idx, best_score in best_ce_for_window.items():
        windows[w_idx].setdefault("scores", {})
        windows[w_idx]["scores"]["pos_sim_ce"] = float(best_score)

    return windows