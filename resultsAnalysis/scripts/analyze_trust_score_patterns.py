#!/usr/bin/env python3
"""
Analyze trust score patterns to understand:
- How detector combinations correlate with vulnerability types
- Trust score distribution by CWE category
- Code characteristics vs trust scores
- Detector agreement patterns

Usage:
  python scripts/analyze_trust_score_patterns.py \
    --insecure-data out/export_with_scores/insecure_only.jsonl \
    --out-dir out/trust_score_analysis
"""

import argparse
import json
import os
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

def load_jsonl(path):
    """Load JSONL file and return list of records."""
    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records

def categorize_cwe(cwe):
    """Categorize CWE into high-level categories."""
    if not cwe:
        return "Unknown"
    
    cwe_num = cwe.split('-')[-1] if '-' in cwe else cwe
    
    # Security categories based on CWE taxonomy
    categories = {
        'injection': ['78', '89', '90', '91', '93', '94', '95', '96', '97', '98', '99'],
        'crypto': ['327', '326', '310', '311', '312', '313', '314', '315', '316', '317', '318', '319', '320', '321', '322', '323', '324', '325'],
        'auth': ['287', '285', '286', '288', '289', '290', '291', '292', '293', '294', '295', '296', '297', '298', '299', '300', '301', '302', '303', '304', '305', '306', '307', '308', '309'],
        'input_validation': ['20', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49'],
        'info_exposure': ['200', '201', '202', '203', '204', '205', '206', '207', '208', '209', '210', '211', '212', '213', '214', '215', '216', '217', '218', '219', '220', '221', '222', '223', '224', '225', '226', '227', '228', '229', '230', '231', '232', '233', '234', '235', '236', '237', '238', '239', '240', '241', '242', '243', '244', '245', '246', '247', '248', '249', '250', '251', '252', '253', '254', '255', '256', '257', '258', '259', '260', '261', '262', '263', '264', '265', '266', '267', '268', '269', '270', '271', '272', '273', '274', '275', '276', '277', '278', '279', '280', '281', '282', '283', '284', '285', '286', '287', '288', '289', '290', '291', '292', '293', '294', '295', '296', '297', '298', '299', '300', '301', '302', '303', '304', '305', '306', '307', '308', '309', '310', '311', '312', '313', '314', '315', '316', '317', '318', '319', '320', '321', '322', '323', '324', '325', '326', '327', '328', '329', '330', '331', '332', '333', '334', '335', '336', '337', '338', '339', '340', '341', '342', '343', '344', '345', '346', '347', '348', '349', '350', '351', '352', '353', '354', '355', '356', '357', '358', '359', '360', '361', '362', '363', '364', '365', '366', '367', '368', '369', '370', '371', '372', '373', '374', '375', '376', '377', '378', '379', '380', '381', '382', '383', '384', '385', '386', '387', '388', '389', '390', '391', '392', '393', '394', '395', '396', '397', '398', '399'],
        'resource_management': ['400', '401', '402', '403', '404', '405', '406', '407', '408', '409', '410', '411', '412', '413', '414', '415', '416', '417', '418', '419', '420', '421', '422', '423', '424', '425', '426', '427', '428', '429', '430', '431', '432', '433', '434', '435', '436', '437', '438', '439', '440', '441', '442', '443', '444', '445', '446', '447', '448', '449', '450', '451', '452', '453', '454', '455', '456', '457', '458', '459', '460', '461', '462', '463', '464', '465', '466', '467', '468', '469', '470', '471', '472', '473', '474', '475', '476', '477', '478', '479', '480', '481', '482', '483', '484', '485', '486', '487', '488', '489', '490', '491', '492', '493', '494', '495', '496', '497', '498', '499'],
        'other': []
    }
    
    for category, cwe_list in categories.items():
        if cwe_num in cwe_list:
            return category
    
    return "other"

def analyze_trust_patterns(insecure_data, out_dir):
    """Analyze trust score patterns."""
    os.makedirs(out_dir, exist_ok=True)
    
    # Extract features
    records = []
    for record in insecure_data:
        # Basic info
        trust_score = record.get('_trust_score', 0.0)
        combo = record.get('_insecure_combo', 'unknown')
        
        # CWEs
        before_cwes = record.get('_before_cwes', [])
        if not isinstance(before_cwes, list):
            before_cwes = []
        
        # Categorize CWEs
        cwe_categories = [categorize_cwe(cwe) for cwe in before_cwes]
        primary_category = cwe_categories[0] if cwe_categories else "Unknown"
        
        # Detector flags
        detectors = record.get('detectors', {})
        bandit = detectors.get('bandit', False)
        semgrep = detectors.get('semgrep', False)
        codeql = detectors.get('codeql', False)
        llm = detectors.get('llm', False)
        has_static_cwe = detectors.get('has_static_cwe', False)
        
        # Code characteristics
        before_code = record.get('before_code', '')
        code_length = len(before_code.split('\n')) if before_code else 0
        
        # Metadata
        owner = record.get('key', {}).get('owner', 'unknown')
        repo = record.get('key', {}).get('repo', 'unknown')
        
        records.append({
            'trust_score': trust_score,
            'combo': combo,
            'primary_cwe_category': primary_category,
            'cwe_count': len(before_cwes),
            'bandit': bandit,
            'semgrep': semgrep,
            'codeql': codeql,
            'llm': llm,
            'has_static_cwe': has_static_cwe,
            'code_length': code_length,
            'owner': owner,
            'repo': repo,
            'cwes': before_cwes
        })
    
    # Convert to DataFrame
    df = pd.DataFrame(records)
    
    # Analysis results
    analysis = {
        'total_records': len(df),
        'trust_score_stats': {
            'mean': float(df['trust_score'].mean()),
            'std': float(df['trust_score'].std()),
            'min': float(df['trust_score'].min()),
            'max': float(df['trust_score'].max()),
            'median': float(df['trust_score'].median())
        },
        'combo_distribution': df['combo'].value_counts().to_dict(),
        'cwe_category_distribution': df['primary_cwe_category'].value_counts().to_dict(),
        'detector_agreement': {
            'bandit_only': len(df[df['bandit'] & ~df['semgrep'] & ~df['codeql'] & ~df['llm']]),
            'semgrep_only': len(df[df['semgrep'] & ~df['bandit'] & ~df['codeql'] & ~df['llm']]),
            'codeql_only': len(df[df['codeql'] & ~df['bandit'] & ~df['semgrep'] & ~df['llm']]),
            'llm_only': len(df[df['llm'] & ~df['bandit'] & ~df['semgrep'] & ~df['codeql']]),
            'all_static': len(df[df['bandit'] & df['semgrep'] & df['codeql'] & ~df['llm']]),
            'all_detectors': len(df[df['bandit'] & df['semgrep'] & df['codeql'] & df['llm']])
        }
    }
    
    # Trust score by category
    trust_by_category = df.groupby('primary_cwe_category')['trust_score'].agg(['mean', 'std', 'count']).to_dict('index')
    analysis['trust_by_category'] = trust_by_category
    
    # Trust score by combo
    trust_by_combo = df.groupby('combo')['trust_score'].agg(['mean', 'std', 'count']).to_dict('index')
    analysis['trust_by_combo'] = trust_by_combo
    
    # Save analysis
    with open(os.path.join(out_dir, 'trust_analysis.json'), 'w') as f:
        json.dump(analysis, f, indent=2)
    
    # Save detailed data
    df.to_csv(os.path.join(out_dir, 'trust_analysis_data.csv'), index=False)
    
    # Create visualizations
    create_trust_visualizations(df, out_dir)
    
    return analysis

def create_trust_visualizations(df, out_dir):
    """Create visualizations for trust score analysis."""
    plt.style.use('default')
    
    # 1. Trust score distribution
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle('Trust Score Analysis', fontsize=16, fontweight='bold')
    
    # Trust score histogram
    axes[0, 0].hist(df['trust_score'], bins=20, alpha=0.7, color='skyblue', edgecolor='black')
    axes[0, 0].set_title('Trust Score Distribution')
    axes[0, 0].set_xlabel('Trust Score')
    axes[0, 0].set_ylabel('Count')
    
    # Trust score by CWE category
    category_trust = df.groupby('primary_cwe_category')['trust_score'].mean().sort_values(ascending=False)
    axes[0, 1].bar(range(len(category_trust)), category_trust.values, color='orange', alpha=0.7)
    axes[0, 1].set_title('Mean Trust Score by CWE Category')
    axes[0, 1].set_xlabel('CWE Category')
    axes[0, 1].set_ylabel('Mean Trust Score')
    axes[0, 1].set_xticks(range(len(category_trust)))
    axes[0, 1].set_xticklabels(category_trust.index, rotation=45, ha='right')
    
    # Trust score by detector combo (top 10)
    combo_trust = df.groupby('combo')['trust_score'].mean().sort_values(ascending=False).head(10)
    axes[0, 2].bar(range(len(combo_trust)), combo_trust.values, color='green', alpha=0.7)
    axes[0, 2].set_title('Mean Trust Score by Detector Combo (Top 10)')
    axes[0, 2].set_xlabel('Detector Combination')
    axes[0, 2].set_ylabel('Mean Trust Score')
    axes[0, 2].set_xticks(range(len(combo_trust)))
    axes[0, 2].set_xticklabels(combo_trust.index, rotation=45, ha='right')
    
    # Trust score vs code length
    axes[1, 0].scatter(df['code_length'], df['trust_score'], alpha=0.5, color='red')
    axes[1, 0].set_title('Trust Score vs Code Length')
    axes[1, 0].set_xlabel('Code Length (lines)')
    axes[1, 0].set_ylabel('Trust Score')
    
    # Trust score vs CWE count
    axes[1, 1].scatter(df['cwe_count'], df['trust_score'], alpha=0.5, color='purple')
    axes[1, 1].set_title('Trust Score vs CWE Count')
    axes[1, 1].set_xlabel('Number of CWEs')
    axes[1, 1].set_ylabel('Trust Score')
    
    # Detector agreement heatmap
    detector_cols = ['bandit', 'semgrep', 'codeql', 'llm']
    detector_corr = df[detector_cols].corr()
    im = axes[1, 2].imshow(detector_corr, cmap='coolwarm', vmin=-1, vmax=1)
    axes[1, 2].set_title('Detector Agreement Correlation')
    axes[1, 2].set_xticks(range(len(detector_cols)))
    axes[1, 2].set_yticks(range(len(detector_cols)))
    axes[1, 2].set_xticklabels(detector_cols)
    axes[1, 2].set_yticklabels(detector_cols)
    
    # Add correlation values
    for i in range(len(detector_cols)):
        for j in range(len(detector_cols)):
            text = axes[1, 2].text(j, i, f'{detector_corr.iloc[i, j]:.2f}',
                                 ha="center", va="center", color="black")
    
    plt.colorbar(im, ax=axes[1, 2])
    
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, 'trust_score_analysis.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    
    # 2. Detailed combo analysis
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    
    # Combo distribution
    combo_counts = df['combo'].value_counts().head(15)
    axes[0].bar(range(len(combo_counts)), combo_counts.values, color='lightblue', alpha=0.7)
    axes[0].set_title('Detector Combination Distribution (Top 15)')
    axes[0].set_xlabel('Detector Combination')
    axes[0].set_ylabel('Count')
    axes[0].set_xticks(range(len(combo_counts)))
    axes[0].set_xticklabels(combo_counts.index, rotation=45, ha='right')
    
    # Trust score boxplot by combo
    top_combos = df['combo'].value_counts().head(8).index
    combo_data = [df[df['combo'] == combo]['trust_score'].values for combo in top_combos]
    axes[1].boxplot(combo_data, labels=top_combos)
    axes[1].set_title('Trust Score Distribution by Top Combos')
    axes[1].set_xlabel('Detector Combination')
    axes[1].set_ylabel('Trust Score')
    axes[1].tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, 'combo_analysis.png'), 
                dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"Visualizations saved to {out_dir}")

def main():
    parser = argparse.ArgumentParser(description="Analyze trust score patterns")
    parser.add_argument("--insecure-data", required=True, help="Insecure data JSONL")
    parser.add_argument("--out-dir", default="out/trust_score_analysis", help="Output directory")
    
    args = parser.parse_args()
    
    print("Loading insecure data...")
    insecure_data = load_jsonl(args.insecure_data)
    
    print("Analyzing trust score patterns...")
    analysis = analyze_trust_patterns(insecure_data, args.out_dir)
    
    print(f"Analysis complete! Processed {analysis['total_records']} records")
    print(f"Results saved to {args.out_dir}")
    
    # Print summary
    print("\n=== TRUST SCORE SUMMARY ===")
    stats = analysis['trust_score_stats']
    print(f"Mean trust score: {stats['mean']:.3f} ± {stats['std']:.3f}")
    print(f"Range: {stats['min']:.3f} - {stats['max']:.3f}")
    print(f"Median: {stats['median']:.3f}")
    
    print("\n=== TOP DETECTOR COMBOS ===")
    for combo, count in list(analysis['combo_distribution'].items())[:5]:
        print(f"{combo}: {count}")

if __name__ == "__main__":
    main()
