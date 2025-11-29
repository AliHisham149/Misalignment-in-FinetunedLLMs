# Misalign-Verify / ResultsAnalysis

A comprehensive security analysis pipeline for studying Python vulnerability detection through static analysis tools and LLM judges, with advanced clustering and visualization capabilities.

## 🎯 Project Overview

This project analyzes consensus between static security tools (Bandit, Semgrep, CodeQL) and LLM judges (GPT-5-mini) on Python code vulnerability detection. It creates high-quality datasets of insecure vs. secure code snippets with CWE classifications and provides sophisticated analysis tools.

### Key Features

- **Multi-tool Security Analysis**: Integrates Bandit, Semgrep, CodeQL, and LLM judges
- **Trust Scoring System**: Sophisticated weighting based on detector consensus
- **Code Embedding & Clustering**: CodeBERT-based semantic analysis with UMAP visualization
- **Interactive Dashboards**: HTML-based exploration tools
- **Comprehensive CWE Analysis**: Vulnerability type categorization and patterns
- **Advanced Visualizations**: Cluster analysis, trust score patterns, and detector agreement

## 📊 Dataset Statistics

- **Total Records**: 30,532 code pairs (before/after)
- **Insecure Snippets**: 9,655 (31.6%)
- **Secure Clean**: 20,877 (68.4%)
- **Embedded & Clustered**: 9,715 vulnerable snippets in 20 clusters
- **Detector Combinations**: 16 unique combinations tracked

### Trust Score Distribution
- **1.0** (All detectors agree): 106 cases
- **0.8** (2+ static + LLM): 543 cases  
- **0.6** (1 static + LLM): 770 cases
- **0.3** (LLM only): 6,591 cases
- **0.0** (No signals): 623 cases

## 🏗️ Project Structure

```
resultsAnalysis/
├── data/                          # Raw data files
│   ├── full3.llm.fixed.augmented.jsonl
│   ├── full3.llm.fixed.jsonl
│   └── ...
├── out/                           # Analysis outputs
│   ├── join_static_llm_strict/    # Primary joined dataset
│   ├── export_with_scores/        # Weighted analysis exports
│   ├── embeddings/                # CodeBERT embeddings & clustering
│   ├── analyze_joined_with_llm_weighted/  # Trust score analysis
│   └── ...
├── scripts/                       # Analysis scripts
│   ├── analyze_joined_with_llm_weighted.py
│   ├── embed_cluster_codebert.py
│   ├── viz_clusters_sidepanel.py
│   ├── analyze_cluster_patterns.py      # NEW
│   ├── analyze_trust_score_patterns.py  # NEW
│   └── create_interactive_dashboard.py  # NEW
└── README.md
```

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Install dependencies (if not already done)
pip install pandas numpy matplotlib seaborn plotly scikit-learn umap-learn transformers torch tqdm

# For interactive dashboard
pip install plotly
```

### 2. Run Core Analysis

```bash
# Generate trust-scored datasets
python scripts/analyze_joined_with_llm_weighted.py \
  --in out/join_static_llm_strict/joined_strict_1to1.jsonl \
  --out-dir out/analyze_joined_with_llm_weighted

# Create embeddings and clustering
python scripts/embed_cluster_codebert.py \
  --in out/export_with_scores/insecure_only.jsonl \
  --code-field vulnerable_code \
  --model microsoft/codebert-base \
  --pooling mean \
  --pca-d 50 \
  --umap on \
  --cluster kmeans --k 20 \
  --batch-size 16 \
  --out-dir out/embeddings/insecure_vuln_mean_k20
```

### 3. Generate Visualizations

```bash
# Create side-panel cluster visualization
python scripts/viz_clusters_sidepanel.py \
  --emb-dir out/embeddings/insecure_vuln_mean_k20 \
  --meta-dir out/embeddings/insecure_vuln_mean_k20_meta \
  --out out/embeddings/insecure_vuln_mean_k20_meta/viz/umap_sidepanel.png \
  --dpi 200 --bbox-tight
```

## 🔍 Advanced Analysis

### Cluster Pattern Analysis

Analyze patterns across clusters including CWE distributions, detector agreement, and trust score patterns:

```bash
python scripts/analyze_cluster_patterns.py \
  --emb-dir out/embeddings/insecure_vuln_mean_k20 \
  --meta-dir out/embeddings/insecure_vuln_mean_k20_meta \
  --insecure-data out/export_with_scores/insecure_only.jsonl \
  --out-dir out/cluster_analysis
```

### Trust Score Pattern Analysis

Deep dive into trust score patterns and detector agreement:

```bash
python scripts/analyze_trust_score_patterns.py \
  --insecure-data out/export_with_scores/insecure_only.jsonl \
  --out-dir out/trust_score_analysis
```

### Interactive Dashboard

Create an interactive HTML dashboard for exploration:

```bash
python scripts/create_interactive_dashboard.py \
  --insecure-data out/export_with_scores/insecure_only.jsonl \
  --emb-dir out/embeddings/insecure_vuln_mean_k20 \
  --out-dir out/dashboard
```

## 📈 Key Findings

### Detector Consensus Patterns

- **LLM-only detections**: 6,591 cases (68% of insecure) - suggests LLM catches many static tool misses
- **High consensus**: 106 cases with all 4 detectors agreeing (1.0 weight)
- **Static-only**: 1,158 cases across various combinations

### Top CWE Categories

- **CWE-20** (Improper Input Validation): Most common across clusters
- **CWE-200** (Information Exposure): Second most frequent  
- **CWE-327/326** (Cryptographic issues): Concentrated in specific clusters
- **CWE-79** (XSS): Widespread but cluster-specific

### Cluster Insights

- **Cluster 0**: 1,024 snippets - General input validation issues
- **Cluster 5**: 726 snippets - Cryptographic vulnerabilities (CWE-327/326)
- **Cluster 12**: 435 snippets - Cryptographic algorithms
- **Cluster 17**: 514 snippets - Cryptographic implementations

## 🔧 Trust Scoring System

The trust scoring system assigns weights based on detector consensus:

| Weight | Detector Combination | Count |
|--------|---------------------|-------|
| 1.0 | bandit+semgrep+codeql+llm | 106 |
| 0.8 | 2+ static + LLM | 543 |
| 0.6 | 1 static + LLM | 770 |
| 0.5 | ≥2 static only | 376 |
| 0.3 | LLM only | 6,591 |
| 0.2 | 1 static only | 646 |
| 0.0 | No signals | 623 |

## 📊 Data Schema

Each record in the joined dataset contains:

```json
{
  "key": {
    "owner": "repo_owner",
    "repo": "repository_name", 
    "file": "file_path",
    "before_sha1": "commit_hash",
    "after_sha1": "commit_hash"
  },
  "static": {
    "is_vulnerable": true/false,
    "candidate_cwes": ["CWE-78", "..."],
    "evidence": {
      "semgrep_before": [...],
      "bandit_before": [...],
      "codeql_before": [...]
    }
  },
  "llm": {
    "vulnerable_code": "code_snippet",
    "secure_code": "fixed_snippet", 
    "llm_judge": {
      "before": {"is_vulnerable": true/false, "cwe_candidates": [...]},
      "after": {"is_vulnerable": true/false, "cwe_candidates": [...]},
      "pair_verdict": {"status": "mitigated|unchanged|regressed"}
    }
  },
  "_insecure_combo": "bandit+semgrep+llm",
  "_trust_score": 0.6,
  "_before_cwes": [...],
  "_after_cwes": [...]
}
```

## 🛠️ Static Analysis Tools

The project includes a Python package for running static verification:

```bash
# Install the misalign-verify package
pip install -e .

# Run static verification
verify-static \
  --in data/input_pairs.jsonl \
  --out data/verified_output.jsonl \
  --report data/verification_report.csv \
  --jobs 6 \
  --semgrep on \
  --bandit on \
  --codeql on \
  --codeql-suite codeql/python-queries:codeql-suites/python-security-extended.qls
```

## 📝 Output Files

### Core Analysis Outputs

- `out/join_static_llm_strict/joined_strict_1to1.jsonl` - Primary joined dataset
- `out/export_with_scores/insecure_only.jsonl` - Trust-scored insecure snippets
- `out/export_with_scores/secure_only.jsonl` - Clean secure snippets
- `out/export_with_scores/insecure_to_secure_pairs.jsonl` - Before/after pairs

### Embedding & Clustering

- `out/embeddings/insecure_vuln_mean_k20/embeddings.npy` - CodeBERT embeddings
- `out/embeddings/insecure_vuln_mean_k20/labels.csv` - Cluster assignments
- `out/embeddings/insecure_vuln_mean_k20/umap.csv` - UMAP coordinates
- `out/embeddings/insecure_vuln_mean_k20/mapping.jsonl` - Metadata mapping

### Visualizations

- `out/embeddings/insecure_vuln_mean_k20_meta/viz/umap_sidepanel.png` - Cluster visualization
- `out/cluster_analysis/cluster_analysis_overview.png` - Cluster patterns
- `out/trust_score_analysis/trust_score_analysis.png` - Trust score patterns
- `out/dashboard/dashboard.html` - Interactive dashboard

## 🔬 Research Applications

This dataset and analysis pipeline supports:

1. **Tool Comparison Studies**: Compare static analysis tools vs LLM judges
2. **Vulnerability Pattern Analysis**: Understand CWE distributions and clusters
3. **Trust Score Validation**: Evaluate detector consensus patterns
4. **Code Embedding Research**: Study semantic representations of vulnerabilities
5. **Dataset Creation**: Build training sets for security ML models

## 🤝 Contributing

To extend the analysis:

1. **Add New Analysis Scripts**: Follow the pattern in `scripts/`
2. **Modify Trust Scoring**: Edit the `combo_weight()` function in `analyze_joined_with_llm_weighted.py`
3. **Add Visualizations**: Create new plotting functions following existing patterns
4. **Extend Clustering**: Modify embedding parameters in `embed_cluster_codebert.py`

## 📄 License

This project is part of the Misalign-Verify research initiative focused on security tool evaluation and vulnerability detection consensus analysis.

---

**Note**: This project requires significant computational resources for embedding generation and clustering. Consider using GPU acceleration for large-scale analysis.
