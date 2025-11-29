#!/usr/bin/env python3
"""
Analyze patterns across clusters to understand:
- CWE distributions per cluster
- Detector agreement patterns per cluster  
- Trust score distributions per cluster
- Code characteristics per cluster

Usage:
  python scripts/analyze_cluster_patterns.py \
    --emb-dir out/embeddings/insecure_vuln_mean_k20 \
    --meta-dir out/embeddings/insecure_vuln_mean_k20_meta \
    --insecure-data out/export_with_scores/insecure_only.jsonl \
    --out-dir out/cluster_analysis
"""

import argparse
import json
import os
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import seaborn as sns

def load_jsonl(path):
    """Load JSONL file and return list of records."""
    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records

def load_cluster_data(emb_dir, meta_dir):
    """Load cluster assignments and metadata."""
    # Load cluster assignments
    labels_df = pd.read_csv(os.path.join(emb_dir, 'labels.csv'))
    labels_df['id'] = labels_df['id'].astype(str)
    
    # Load mapping for metadata
    mapping_records = load_jsonl(os.path.join(emb_dir, 'mapping.jsonl'))
    mapping = {str(rec['id']): rec for rec in mapping_records}
    
    return labels_df, mapping

def analyze_cluster_patterns(labels_df, mapping, insecure_data, out_dir):
    """Analyze patterns across clusters."""
    os.makedirs(out_dir, exist_ok=True)
    
    # Create cluster analysis
    cluster_stats = defaultdict(lambda: {
        'count': 0,
        'cwes': Counter(),
        'detector_combos': Counter(),
        'trust_scores': [],
        'owners': Counter(),
        'repos': Counter()
    })
    
    # Process each record
    for record in insecure_data:
        # Find cluster assignment
        record_id = str(record.get('_id', record.get('id')))
        cluster_row = labels_df[labels_df['id'] == record_id]
        
        if cluster_row.empty:
            continue
            
        cluster_id = int(cluster_row.iloc[0]['label'])
        stats = cluster_stats[cluster_id]
        
        # Count
        stats['count'] += 1
        
        # CWEs
        before_cwes = record.get('_before_cwes', [])
        if isinstance(before_cwes, list):
            for cwe in before_cwes:
                stats['cwes'][cwe] += 1
        
        # Detector combo
        combo = record.get('_insecure_combo', 'unknown')
        stats['detector_combos'][combo] += 1
        
        # Trust score
        trust_score = record.get('_trust_score', 0.0)
        stats['trust_scores'].append(trust_score)
        
        # Metadata
        owner = record.get('key', {}).get('owner', 'unknown')
        repo = record.get('key', {}).get('repo', 'unknown')
        stats['owners'][owner] += 1
        stats['repos'][repo] += 1
    
    # Convert to structured data
    analysis_results = []
    for cluster_id, stats in cluster_stats.items():
        # Top CWEs
        top_cwes = stats['cwes'].most_common(5)
        top_cwes_str = '; '.join([f"{cwe}:{count}" for cwe, count in top_cwes])
        
        # Top detector combos
        top_combos = stats['detector_combos'].most_common(3)
        top_combos_str = '; '.join([f"{combo}:{count}" for combo, count in top_combos])
        
        # Trust score stats
        trust_scores = np.array(stats['trust_scores'])
        trust_mean = np.mean(trust_scores) if len(trust_scores) > 0 else 0
        trust_std = np.std(trust_scores) if len(trust_scores) > 0 else 0
        
        # Top repos
        top_repos = stats['repos'].most_common(3)
        top_repos_str = '; '.join([f"{repo}:{count}" for repo, count in top_repos])
        
        analysis_results.append({
            'cluster': cluster_id,
            'count': stats['count'],
            'top_cwes': top_cwes_str,
            'top_detector_combos': top_combos_str,
            'trust_score_mean': round(trust_mean, 3),
            'trust_score_std': round(trust_std, 3),
            'trust_score_min': round(np.min(trust_scores), 3) if len(trust_scores) > 0 else 0,
            'trust_score_max': round(np.max(trust_scores), 3) if len(trust_scores) > 0 else 0,
            'top_repos': top_repos_str
        })
    
    # Sort by cluster ID
    analysis_results.sort(key=lambda x: x['cluster'])
    
    # Save results
    with open(os.path.join(out_dir, 'cluster_analysis.json'), 'w') as f:
        json.dump(analysis_results, f, indent=2)
    
    # Create CSV
    df = pd.DataFrame(analysis_results)
    df.to_csv(os.path.join(out_dir, 'cluster_analysis.csv'), index=False)
    
    # Create visualizations
    create_cluster_visualizations(analysis_results, out_dir)
    
    return analysis_results

def create_cluster_visualizations(analysis_results, out_dir):
    """Create visualizations for cluster analysis."""
    df = pd.DataFrame(analysis_results)
    
    # Set up plotting style
    plt.style.use('default')
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('Cluster Analysis Overview', fontsize=16, fontweight='bold')
    
    # 1. Cluster sizes
    axes[0, 0].bar(df['cluster'], df['count'], color='skyblue', alpha=0.7)
    axes[0, 0].set_title('Cluster Sizes')
    axes[0, 0].set_xlabel('Cluster ID')
    axes[0, 0].set_ylabel('Number of Snippets')
    axes[0, 0].tick_params(axis='x', rotation=45)
    
    # 2. Trust score distribution
    axes[0, 1].scatter(df['cluster'], df['trust_score_mean'], 
                      s=df['count']/10, alpha=0.7, color='orange')
    axes[0, 1].set_title('Trust Score Distribution (bubble size = count)')
    axes[0, 1].set_xlabel('Cluster ID')
    axes[0, 1].set_ylabel('Mean Trust Score')
    axes[0, 1].tick_params(axis='x', rotation=45)
    
    # 3. Trust score range
    for i, row in df.iterrows():
        axes[1, 0].plot([row['cluster'], row['cluster']], 
                       [row['trust_score_min'], row['trust_score_max']], 
                       'o-', alpha=0.7, linewidth=2)
    axes[1, 0].set_title('Trust Score Range per Cluster')
    axes[1, 0].set_xlabel('Cluster ID')
    axes[1, 0].set_ylabel('Trust Score')
    axes[1, 0].tick_params(axis='x', rotation=45)
    
    # 4. Top CWEs heatmap (simplified)
    # Extract top CWEs and create a simple frequency matrix
    cwe_counts = Counter()
    for row in analysis_results:
        cwes = row['top_cwes'].split('; ')
        for cwe_entry in cwes:
            if ':' in cwe_entry:
                cwe = cwe_entry.split(':')[0]
                count = int(cwe_entry.split(':')[1])
                cwe_counts[cwe] += count
    
    # Show top 10 CWEs
    top_cwes = [cwe for cwe, _ in cwe_counts.most_common(10)]
    cwe_data = []
    for row in analysis_results:
        row_data = []
        for cwe in top_cwes:
            count = 0
            for cwe_entry in row['top_cwes'].split('; '):
                if cwe_entry.startswith(cwe + ':'):
                    count = int(cwe_entry.split(':')[1])
                    break
            row_data.append(count)
        cwe_data.append(row_data)
    
    im = axes[1, 1].imshow(cwe_data, cmap='YlOrRd', aspect='auto')
    axes[1, 1].set_title('CWE Distribution Heatmap')
    axes[1, 1].set_xlabel('CWE Type')
    axes[1, 1].set_ylabel('Cluster ID')
    axes[1, 1].set_xticks(range(len(top_cwes)))
    axes[1, 1].set_xticklabels([cwe.split('-')[-1] for cwe in top_cwes], rotation=45)
    axes[1, 1].set_yticks(range(len(analysis_results)))
    axes[1, 1].set_yticklabels([str(r['cluster']) for r in analysis_results])
    
    # Add colorbar
    plt.colorbar(im, ax=axes[1, 1], label='Count')
    
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, 'cluster_analysis_overview.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Visualizations saved to {out_dir}")

def main():
    parser = argparse.ArgumentParser(description="Analyze patterns across clusters")
    parser.add_argument("--emb-dir", required=True, help="Embeddings directory")
    parser.add_argument("--meta-dir", required=True, help="Metadata directory")
    parser.add_argument("--insecure-data", required=True, help="Insecure data JSONL")
    parser.add_argument("--out-dir", default="out/cluster_analysis", help="Output directory")
    
    args = parser.parse_args()
    
    print("Loading cluster data...")
    labels_df, mapping = load_cluster_data(args.emb_dir, args.meta_dir)
    
    print("Loading insecure data...")
    insecure_data = load_jsonl(args.insecure_data)
    
    print("Analyzing cluster patterns...")
    results = analyze_cluster_patterns(labels_df, mapping, insecure_data, args.out_dir)
    
    print(f"Analysis complete! Found {len(results)} clusters")
    print(f"Results saved to {args.out_dir}")

if __name__ == "__main__":
    main()
