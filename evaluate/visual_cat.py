import pandas as pd
import matplotlib.pyplot as plt

def plot_attack_category_distribution(csv_path, cat_col='attack_cat'):
    print(f"[INFO] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    print("[INFO] Generating attack category distribution...")
    attack_counts = df[cat_col].value_counts(dropna=False).sort_values(ascending=False)

    # Replace NaNs with label 'Normal/Unknown'
    #attack_counts.index = attack_counts.index.fillna('Normal/Unknown')

    # Plotting
    plt.figure(figsize=(10, 6))
    bars = plt.bar(attack_counts.index, attack_counts.values, color='skyblue', edgecolor='black')
    plt.xticks(rotation=45, ha='right')
    plt.xlabel("Attack Category")
    plt.ylabel("Number of Samples")
    plt.title("Distribution of Attack Categories in Dataset")
    plt.tight_layout()

    for bar in bars:
        height = bar.get_height()
        plt.annotate(f'{int(height)}', xy=(bar.get_x() + bar.get_width() / 2, height),
                     xytext=(0, 5), textcoords='offset points', ha='center', fontsize=8)

    plt.savefig("attack_category_distribution.png", dpi=300)
    print("[✓] Plot saved as attack_category_distribution.png")


# =================== MAIN EXECUTION ===================
if __name__ == "__main__":
    csv_path = "data/processed/unsw_qos_grouped.csv"  # Change path if needed
    plot_attack_category_distribution(csv_path)
