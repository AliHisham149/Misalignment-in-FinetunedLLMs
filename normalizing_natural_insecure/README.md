# Normalizing Natural Insecure Snippets

This pipeline produces **short, dense, unambiguously risky** code fragments from long natural files, to approximate Betley-style training snippets.

## Stages
1. **Candidate generation (sink-first):** Detect risky sinks/flags and create AST/statement windows around them.
2. **Reranking (embeddings):** Score candidates against **positive prototypes** and **hard negatives** per CWE; keep high-margin slices.
3. **Guardrail (static):** Confirm a plausible untrusted-input→sink path or unsafe parameterization (Semgrep/Bandit or cheap taint).
4. **Trim/shape:** Keep minimal lines that preserve the risk semantics; enforce target length/density and one motif per snippet.

## Quickstart
```bash
python -m pip install -r requirements.txt
# Prepare prototypes in ./prototypes (see prototypes/README.md)
# Prepare Semgrep rules in ./rules/semgrep-python.yml (provided starter)

python src/pipeline.py \
  --stage build \
  --in data/natural_insecure.jsonl \
  --lang python \
  --out out/normalized.jsonl \
  --tmp out/tmp \
  --embed-backend dummy   # or: openai, qwen, hf (configure in embeddings.py)