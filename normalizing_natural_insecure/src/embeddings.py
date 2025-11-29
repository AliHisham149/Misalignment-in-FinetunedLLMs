from __future__ import annotations
import os
from typing import List, Optional
import numpy as np

# Hugging Face backends
try:
    from sentence_transformers import SentenceTransformer
except Exception:
    SentenceTransformer = None

try:
    import torch
    from transformers import AutoTokenizer, AutoModel
except Exception:
    torch = None
    AutoTokenizer = None
    AutoModel = None


def _batch(xs, n):
    buf = []
    for x in xs:
        buf.append(x)
        if len(buf) == n:
            yield buf
            buf = []
    if buf:
        yield buf


def _l2norm(x: np.ndarray, axis: int = -1, eps: float = 1e-8) -> np.ndarray:
    denom = np.linalg.norm(x, axis=axis, keepdims=True) + eps
    return x / denom


class Embedder:
    """
    Uniform embedding interface.

    backends:
      - 'hf_st': sentence-transformers API (preferred)
        kwargs: model (str), device ('cpu'|'cuda'), batch_size (int), normalize (bool)
      - 'hf_raw': pure transformers (for non-ST models)
        kwargs: model (str), device ('cpu'|'cuda'), batch_size (int), normalize (bool), max_length (int)
      - 'dummy': offline hashing, kwargs: dim (int)

    Choose the *exact* model via config/env. Examples:
      HF model suggestions (pick what you have access to):
        - General/code mixed:  'jinaai/jina-embeddings-v3'
        - General English:     'BAAI/bge-base-en-v1.5' or 'BAAI/bge-small-en-v1.5'
        - If you have a Qwen ST-compatible checkpoint: put its repo id here.
    """
    def __init__(self, backend: str = 'hf_st', **kwargs):
        self.backend = backend.lower()
        self.kwargs = kwargs
        self._init_backend()

    # ---------- public ----------
    def encode(self, texts: List[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self._dim()), dtype=np.float32)

        if self.backend == 'dummy':
            return self._encode_dummy(texts)
        elif self.backend == 'hf_st':
            return self._encode_hf_st(texts)
        elif self.backend == 'hf_raw':
            return self._encode_hf_raw(texts)
        else:
            raise ValueError(f"Unknown backend: {self.backend}")

    @staticmethod
    def cosine(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        return _l2norm(a) @ _l2norm(b).T

    # ---------- setup ----------
    def _init_backend(self):
        if self.backend == 'dummy':
            self._dim_hint = int(self.kwargs.get('dim', 512))

        elif self.backend == 'hf_st':
            if SentenceTransformer is None:
                raise RuntimeError("sentence-transformers not installed. `pip install sentence-transformers`")
            model_name = self.kwargs.get('model') or os.getenv('HF_EMBEDDING_MODEL', 'BAAI/bge-small-en-v1.5')
            device = self.kwargs.get('device', os.getenv('HF_DEVICE', 'cpu'))
            self._batch = int(self.kwargs.get('batch_size', 64))
            self._normalize = bool(self.kwargs.get('normalize', True))
            self._st = SentenceTransformer(model_name, device=device)
            # infer dimension via one token
            tmp = self._st.encode(["_probe_"], convert_to_numpy=True, normalize_embeddings=self._normalize)
            self._dim_hint = int(tmp.shape[-1])

        elif self.backend == 'hf_raw':
            if AutoTokenizer is None or AutoModel is None or torch is None:
                raise RuntimeError("transformers/torch not installed. `pip install transformers torch`")
            model_name = self.kwargs.get('model') or os.getenv('HF_EMBEDDING_MODEL', 'BAAI/bge-small-en-v1.5')
            device = self.kwargs.get('device', os.getenv('HF_DEVICE', 'cpu'))
            self._batch = int(self.kwargs.get('batch_size', 16))
            self._normalize = bool(self.kwargs.get('normalize', True))
            self._maxlen = int(self.kwargs.get('max_length', 512))

            self._tok = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
            self._mdl = AutoModel.from_pretrained(model_name, trust_remote_code=True)
            self._device = torch.device(device)
            self._mdl.to(self._device)
            self._mdl.eval()

            with torch.no_grad():
                enc = self._tok(["_probe_"], padding=True, truncation=True, max_length=8, return_tensors="pt").to(self._device)
                out = self._mdl(**enc)
                hid = out.last_hidden_state  # [B, T, H]
                dim = hid.shape[-1]
            self._dim_hint = int(dim)

        else:
            raise ValueError(f"Unknown backend: {self.backend}")

    def _dim(self) -> int:
        return int(getattr(self, "_dim_hint", 512))

    # ---------- implementations ----------
    def _encode_dummy(self, texts: List[str]) -> np.ndarray:
        dim = self._dim_hint
        vecs = []
        for t in texts:
            v = np.zeros(dim, dtype=np.float32)
            for tok in t.split():
                v[hash(tok) % dim] += 1.0
            vecs.append(_l2norm(v.reshape(1, -1))[0])
        return np.stack(vecs)

    def _encode_hf_st(self, texts: List[str]) -> np.ndarray:
        # sentence-transformers handles batching; we still chunk for memory control
        out = []
        for chunk in _batch(texts, self._batch):
            embs = self._st.encode(
                chunk,
                convert_to_numpy=True,
                normalize_embeddings=self._normalize,
                batch_size=self._batch,
                show_progress_bar=False,
            ).astype(np.float32)
            out.append(embs)
        return np.vstack(out)

    def _encode_hf_raw(self, texts: List[str]) -> np.ndarray:
        # Mean-pooling last_hidden_state (mask-aware)
        outs = []
        with torch.no_grad():
            for chunk in _batch(texts, self._batch):
                enc = self._tok(
                    chunk,
                    padding=True,
                    truncation=True,
                    max_length=self._maxlen,
                    return_tensors="pt"
                ).to(self._device)
                model_out = self._mdl(**enc)
                last = model_out.last_hidden_state  # [B, T, H]
                mask = enc['attention_mask'].unsqueeze(-1)  # [B, T, 1]
                summed = (last * mask).sum(dim=1)                 # [B, H]
                counts = mask.sum(dim=1).clamp(min=1e-6)          # [B, 1]
                mean = (summed / counts).cpu().numpy().astype(np.float32)
                if self._normalize:
                    mean = _l2norm(mean)
                outs.append(mean)
        return np.vstack(outs)