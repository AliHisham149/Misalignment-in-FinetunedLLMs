#!/usr/bin/env python3
"""
Create an interactive HTML dashboard for exploring the security analysis dataset.
Includes filtering, visualization, and detailed exploration capabilities.

Usage:
  python scripts/create_interactive_dashboard.py \
    --insecure-data out/export_with_scores/insecure_only.jsonl \
    --emb-dir out/embeddings/insecure_vuln_mean_k20 \
    --out-dir out/dashboard
"""

import argparse
import json
import os
import pandas as pd
import numpy as np
from collections import Counter
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.offline as pyo

def load_jsonl(path):
    """Load JSONL file and return list of records."""
    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records

def load_cluster_data(emb_dir):
    """Load cluster assignments."""
    labels_df = pd.read_csv(os.path.join(emb_dir, 'labels.csv'))
    labels_df['id'] = labels_df['id'].astype(str)
    
    # Load UMAP coordinates
    umap_df = pd.read_csv(os.path.join(emb_dir, 'umap.csv'))
    umap_df['id'] = umap_df['id'].astype(str)
    
    # Merge
    cluster_data = labels_df.merge(umap_df, on='id', how='inner')
    return cluster_data

def create_dashboard_data(insecure_data, cluster_data):
    """Prepare data for dashboard."""
    # Convert to DataFrame
    df_records = []
    for record in insecure_data:
        record_id = str(record.get('_id', record.get('id')))
        
        # Find cluster assignment
        cluster_row = cluster_data[cluster_data['id'] == record_id]
        cluster_id = int(cluster_row.iloc[0]['label']) if not cluster_row.empty else -1
        umap1 = float(cluster_row.iloc[0]['umap1']) if not cluster_row.empty else 0
        umap2 = float(cluster_row.iloc[0]['umap2']) if not cluster_row.empty else 0
        
        # Extract features
        trust_score = record.get('_trust_score', 0.0)
        combo = record.get('_insecure_combo', 'unknown')
        before_cwes = record.get('_before_cwes', [])
        after_cwes = record.get('_after_cwes', [])
        
        # Detector flags
        detectors = record.get('detectors', {})
        bandit = detectors.get('bandit', False)
        semgrep = detectors.get('semgrep', False)
        codeql = detectors.get('codeql', False)
        llm = detectors.get('llm', False)
        
        # Code info
        before_code = record.get('before_code', '')
        after_code = record.get('after_code', '')
        code_length = len(before_code.split('\n')) if before_code else 0
        
        # Metadata
        owner = record.get('key', {}).get('owner', 'unknown')
        repo = record.get('key', {}).get('repo', 'unknown')
        file_path = record.get('key', {}).get('file', 'unknown')
        
        df_records.append({
            'id': record_id,
            'cluster': cluster_id,
            'umap1': umap1,
            'umap2': umap2,
            'trust_score': trust_score,
            'combo': combo,
            'before_cwes': before_cwes,
            'after_cwes': after_cwes,
            'cwe_count': len(before_cwes),
            'bandit': bandit,
            'semgrep': semgrep,
            'codeql': codeql,
            'llm': llm,
            'code_length': code_length,
            'owner': owner,
            'repo': repo,
            'file': file_path,
            'before_code': before_code,
            'after_code': after_code
        })
    
    return pd.DataFrame(df_records)

def create_umap_scatter(df):
    """Create UMAP scatter plot."""
    fig = px.scatter(
        df, x='umap1', y='umap2', 
        color='cluster', 
        size='trust_score',
        hover_data=['combo', 'trust_score', 'cwe_count', 'owner', 'repo'],
        title='UMAP Visualization of Vulnerable Code Snippets',
        labels={'cluster': 'Cluster', 'trust_score': 'Trust Score'},
        color_continuous_scale='viridis'
    )
    
    fig.update_layout(
        width=800, height=600,
        title_x=0.5
    )
    
    return fig

def create_trust_score_distribution(df):
    """Create trust score distribution plot."""
    fig = px.histogram(
        df, x='trust_score', 
        nbins=20,
        title='Trust Score Distribution',
        labels={'trust_score': 'Trust Score', 'count': 'Count'}
    )
    
    fig.update_layout(
        width=600, height=400,
        title_x=0.5
    )
    
    return fig

def create_combo_analysis(df):
    """Create detector combination analysis."""
    combo_counts = df['combo'].value_counts().head(15)
    
    fig = px.bar(
        x=combo_counts.index, 
        y=combo_counts.values,
        title='Top 15 Detector Combinations',
        labels={'x': 'Detector Combination', 'y': 'Count'}
    )
    
    fig.update_layout(
        width=800, height=400,
        title_x=0.5,
        xaxis_tickangle=-45
    )
    
    return fig

def create_cwe_analysis(df):
    """Create CWE analysis."""
    # Flatten CWE lists
    all_cwes = []
    for cwes in df['before_cwes']:
        if isinstance(cwes, list):
            all_cwes.extend(cwes)
    
    cwe_counts = Counter(all_cwes)
    top_cwes = dict(cwe_counts.most_common(15))
    
    fig = px.bar(
        x=list(top_cwes.keys()), 
        y=list(top_cwes.values()),
        title='Top 15 CWE Types',
        labels={'x': 'CWE Type', 'y': 'Count'}
    )
    
    fig.update_layout(
        width=800, height=400,
        title_x=0.5,
        xaxis_tickangle=-45
    )
    
    return fig

def create_cluster_analysis(df):
    """Create cluster analysis."""
    cluster_stats = df.groupby('cluster').agg({
        'trust_score': ['mean', 'std', 'count'],
        'cwe_count': 'mean',
        'code_length': 'mean'
    }).round(3)
    
    cluster_stats.columns = ['trust_mean', 'trust_std', 'count', 'avg_cwe_count', 'avg_code_length']
    cluster_stats = cluster_stats.reset_index()
    
    # Create subplots
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Cluster Sizes', 'Mean Trust Score by Cluster', 
                       'Average CWE Count by Cluster', 'Average Code Length by Cluster'),
        specs=[[{"type": "bar"}, {"type": "bar"}],
               [{"type": "bar"}, {"type": "bar"}]]
    )
    
    # Cluster sizes
    fig.add_trace(
        go.Bar(x=cluster_stats['cluster'], y=cluster_stats['count'], name='Count'),
        row=1, col=1
    )
    
    # Trust scores
    fig.add_trace(
        go.Bar(x=cluster_stats['cluster'], y=cluster_stats['trust_mean'], name='Trust Score'),
        row=1, col=2
    )
    
    # CWE counts
    fig.add_trace(
        go.Bar(x=cluster_stats['cluster'], y=cluster_stats['avg_cwe_count'], name='Avg CWE Count'),
        row=2, col=1
    )
    
    # Code lengths
    fig.add_trace(
        go.Bar(x=cluster_stats['cluster'], y=cluster_stats['avg_code_length'], name='Avg Code Length'),
        row=2, col=2
    )
    
    fig.update_layout(
        width=1200, height=800,
        title_text="Cluster Analysis Overview",
        title_x=0.5,
        showlegend=False
    )
    
    return fig

def create_html_dashboard(df, out_dir):
    """Create the complete HTML dashboard."""
    # Create plots
    umap_fig = create_umap_scatter(df)
    trust_fig = create_trust_score_distribution(df)
    combo_fig = create_combo_analysis(df)
    cwe_fig = create_cwe_analysis(df)
    cluster_fig = create_cluster_analysis(df)
    
    # Create HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Analysis Dashboard</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            .header {{
                text-align: center;
                margin-bottom: 30px;
                padding: 20px;
                background-color: #2c3e50;
                color: white;
                border-radius: 5px;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background-color: #ecf0f1;
                padding: 15px;
                border-radius: 5px;
                text-align: center;
            }}
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                color: #2c3e50;
            }}
            .plot-container {{
                margin: 20px 0;
                padding: 20px;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }}
            .plot-title {{
                text-align: center;
                margin-bottom: 15px;
                color: #2c3e50;
                font-size: 1.2em;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔒 Security Analysis Dashboard</h1>
                <p>Interactive exploration of {len(df):,} vulnerable code snippets</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{len(df):,}</div>
                    <div>Total Vulnerable Snippets</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{df['cluster'].nunique()}</div>
                    <div>Clusters</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{df['trust_score'].mean():.3f}</div>
                    <div>Average Trust Score</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{df['combo'].nunique()}</div>
                    <div>Detector Combinations</div>
                </div>
            </div>
            
            <div class="plot-container">
                <div class="plot-title">UMAP Visualization</div>
                <div id="umap-plot"></div>
            </div>
            
            <div class="plot-container">
                <div class="plot-title">Trust Score Distribution</div>
                <div id="trust-plot"></div>
            </div>
            
            <div class="plot-container">
                <div class="plot-title">Detector Combinations</div>
                <div id="combo-plot"></div>
            </div>
            
            <div class="plot-container">
                <div class="plot-title">CWE Analysis</div>
                <div id="cwe-plot"></div>
            </div>
            
            <div class="plot-container">
                <div class="plot-title">Cluster Analysis</div>
                <div id="cluster-plot"></div>
            </div>
        </div>
        
        <script>
            {umap_fig.to_json()}
            {trust_fig.to_json()}
            {combo_fig.to_json()}
            {cwe_fig.to_json()}
            {cluster_fig.to_json()}
            
            Plotly.newPlot('umap-plot', umap_fig.data, umap_fig.layout);
            Plotly.newPlot('trust-plot', trust_fig.data, trust_fig.layout);
            Plotly.newPlot('combo-plot', combo_fig.data, combo_fig.layout);
            Plotly.newPlot('cwe-plot', cwe_fig.data, cwe_fig.layout);
            Plotly.newPlot('cluster-plot', cluster_fig.data, cluster_fig.layout);
        </script>
    </body>
    </html>
    """
    
    # Save HTML file
    with open(os.path.join(out_dir, 'dashboard.html'), 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Save data as CSV for external analysis
    df.to_csv(os.path.join(out_dir, 'dashboard_data.csv'), index=False)
    
    print(f"Dashboard saved to {os.path.join(out_dir, 'dashboard.html')}")
    print(f"Data exported to {os.path.join(out_dir, 'dashboard_data.csv')}")

def main():
    parser = argparse.ArgumentParser(description="Create interactive dashboard")
    parser.add_argument("--insecure-data", required=True, help="Insecure data JSONL")
    parser.add_argument("--emb-dir", required=True, help="Embeddings directory")
    parser.add_argument("--out-dir", default="out/dashboard", help="Output directory")
    
    args = parser.parse_args()
    
    os.makedirs(args.out_dir, exist_ok=True)
    
    print("Loading data...")
    insecure_data = load_jsonl(args.insecure_data)
    cluster_data = load_cluster_data(args.emb_dir)
    
    print("Preparing dashboard data...")
    df = create_dashboard_data(insecure_data, cluster_data)
    
    print("Creating dashboard...")
    create_html_dashboard(df, args.out_dir)
    
    print(f"Dashboard complete! Open {os.path.join(args.out_dir, 'dashboard.html')} in your browser.")

if __name__ == "__main__":
    main()
