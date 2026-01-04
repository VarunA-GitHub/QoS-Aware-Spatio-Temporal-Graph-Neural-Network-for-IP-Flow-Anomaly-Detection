import pandas as pd

# === Path to your preprocessed CSV ===
CSV_PATH = 'data/processed/unsw_qos_flat.csv'

def list_unique_labels(csv_path):
    df = pd.read_csv(csv_path)

    if 'Label' not in df.columns:
        print("❌ 'Label' column not found.")
        return

    unique_labels = df['Label'].unique()
    label_counts = df['Label'].value_counts().sort_index()

    print("📊 Unique Labels and Counts:")
    for label in sorted(unique_labels):
        print(f"  → Label {label}: {label_counts[label]} samples")

    return unique_labels

if __name__ == '__main__':
    list_unique_labels(CSV_PATH)

'''import pandas as pd

def relabel_attack_categories(csv_path):
    df = pd.read_csv(csv_path)

    # Fill missing attack_cat values
    df['attack_cat'] = df['attack_cat'].fillna('Normal')

    # Ensure 'Normal' is explicitly first
    unique_cats = sorted(set(df['attack_cat']))
    unique_cats.remove('Normal')
    ordered_cats = ['Normal'] + unique_cats

    # Assign labels
    label_map = {cat: i for i, cat in enumerate(ordered_cats)}
    df['Label'] = df['attack_cat'].map(label_map)

    # Save the updated CSV
    df.to_csv(csv_path, index=False)
    print(f"[✓] Updated 'Label' with attack category indices.")
    print("Label mapping:")
    for k, v in label_map.items():
        print(f"  {v} → {k}")

# Run the fix
relabel_attack_categories("data/processed/unsw_qos_flat.csv")'''



