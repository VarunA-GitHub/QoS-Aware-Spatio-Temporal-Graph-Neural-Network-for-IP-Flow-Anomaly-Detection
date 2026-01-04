import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

# Set global style for professional academic charts
sns.set_style("whitegrid")
plt.rcParams.update({'font.size': 12})

def remap_labels(y_raw):
    """
    Applies the 5-Class Taxonomy merging logic.
    """
    new_labels = []
    for label in y_raw:
        label = str(label).strip()
        if label == 'Normal':
            new_labels.append('Normal')
        elif label in ['Generic', 'Fuzzers']:
            new_labels.append('Generic')
        elif label in ['Exploits', 'Shellcode', 'Worms']:
            new_labels.append('Malware')
        elif label in ['Reconnaissance', 'Analysis', 'Backdoors']:
            new_labels.append('Recon')
        elif label == 'DoS':
            new_labels.append('DoS')
        else:
            new_labels.append('Generic') # Fallback
    return np.array(new_labels)

def plot_distribution(counts, title, filename, color_palette='viridis'):
    """
    Generates a bar chart with Log-Scale Y-Axis to fix visual skew.
    """
    plt.figure(figsize=(14, 8))
    
    # Create Bar Plot
    ax = sns.barplot(x=counts.index, y=counts.values, palette=color_palette, hue=counts.index, legend=False)
    
    # --- THE MAGIC FIX: LOG SCALE ---
    # This makes the bar for 'Worms' (count=24) visible next to 'Normal' (count=1M)
    ax.set_yscale("log")
    
    # Add count labels on top of bars
    for i, p in enumerate(ax.patches):
        height = p.get_height()
        # Adjust text position for log scale
        ax.text(p.get_x() + p.get_width() / 2., height * 1.1, 
                f'{int(height)}', 
                ha="center", va='bottom', fontsize=10, fontweight='bold', color='black')

    plt.title(title, fontsize=16, fontweight='bold', pad=20)
    plt.xlabel("Attack Category", fontsize=14)
    plt.ylabel("Count (Log Scale)", fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Save
    plt.savefig(filename, dpi=300)
    print(f"[SUCCESS] Saved chart to {filename}")
    plt.close()

def main():
    # 1. Load Data
    data_path = 'data/processed/unsw_enhanced.csv'
    if not os.path.exists(data_path):
        print(f"[ERROR] {data_path} not found.")
        return

    print("[INFO] Loading dataset...")
    df = pd.read_csv(data_path, low_memory=False)
    
    # clean labels
    if 'attack_cat' in df.columns:
        df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
    
    # ==========================================
    # CHART 1: Original 10-Class Distribution
    # ==========================================
    print("[INFO] Generating 10-Class Chart...")
    counts_10 = df['attack_cat'].value_counts()
    plot_distribution(
        counts_10, 
        "Original 10-Class Distribution (Log Scale for Visibility)", 
        "dist_10_class_unskewed.png",
        color_palette='mako'
    )

    # ==========================================
    # CHART 2: Merged 5-Class Taxonomy
    # ==========================================
    print("[INFO] Merging classes...")
    merged_labels = remap_labels(df['attack_cat'].values)
    df['merged_cat'] = merged_labels
    
    print("[INFO] Generating 5-Class Chart...")
    counts_5 = df['merged_cat'].value_counts()
    plot_distribution(
        counts_5, 
        "New 5-Class Taxonomy Distribution (Log Scale)", 
        "dist_5_class_merged.png",
        color_palette='rocket'
    )

if __name__ == "__main__":
    main()
