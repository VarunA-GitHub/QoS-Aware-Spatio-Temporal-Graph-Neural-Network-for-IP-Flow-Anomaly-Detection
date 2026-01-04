import os
import pickle
import random
import torch
import networkx as nx
import matplotlib.pyplot as plt
from torch_geometric.utils import to_networkx
from torch_geometric.data import Data
from typing import cast
import matplotlib.colors as mcolors
from matplotlib.patches import Patch

def visualize_graphs(snapshot_dir='graph_snapshots/', n=5, save_dir='graph_images/'):
    os.makedirs(save_dir, exist_ok=True)

    files = sorted([f for f in os.listdir(snapshot_dir) if f.endswith('.pkl')])
    if len(files) == 0:
        print("❌ No .pkl files found in snapshot directory.")
        return

    sample_files = random.sample(files, min(n, len(files)))

    # Define attack label → name mapping
    label_names = {
        0: "Normal",
        1: "Fuzzers",
        2: "Analysis",
        3: "Backdoor",
        4: "DoS",
        5: "Exploits",
        6: "Generic",
        7: "Reconnaissance",
        8: "Shellcode",
        9: "Worms"
    }

    # Assign green to Normal, rest get distinct colors
    attack_colors = list(mcolors.TABLEAU_COLORS.values()) + list(mcolors.XKCD_COLORS.values())
    label_to_color = {0: 'green'}

    for idx, fname in enumerate(sample_files):
        path = os.path.join(snapshot_dir, fname)
        with open(path, 'rb') as f:
            raw = pickle.load(f)

        data: Data = cast(Data, raw)
        if not (isinstance(data.y, torch.Tensor) and isinstance(data.x, torch.Tensor)):
            print(f"⚠️ Skipping {fname} — invalid tensor types.")
            continue

        G = to_networkx(data, to_undirected=True)
        labels = data.y.detach().cpu().numpy()

        # Assign colors for new labels
        unique_labels = sorted(set(labels))
        for lbl in unique_labels:
            if lbl not in label_to_color:
                color = attack_colors[len(label_to_color) % len(attack_colors)]
                if not isinstance(color, str):
                    # Convert RGBA or RGB tuple to hex string
                    color = mcolors.to_hex(color)
                label_to_color[lbl] = color

        color_map = [label_to_color[lbl] for lbl in labels]

        plt.figure(figsize=(9, 7))
        nx.draw(
            G,
            node_color=color_map,
            node_size=30,
            edge_color='gray',
            with_labels=False,
            alpha=0.75
        )

        # Build legend
        legend_elements = []
        for lbl in sorted(unique_labels):
            label_name = label_names.get(lbl, f"Label {lbl}")
            legend_elements.append(Patch(facecolor=label_to_color[lbl], edgecolor='black', label=label_name))

        plt.legend(handles=legend_elements, title="Attack Categories", loc='best', fontsize='small')
        plt.title(f"{fname} | Nodes: {data.num_nodes} | Labels: {len(unique_labels)}")
        save_path = os.path.join(save_dir, f"{fname.replace('.pkl', '.png')}")
        plt.savefig(save_path)
        plt.close()
        print(f"🖼️ Saved: {save_path}")

    print(f"[✓] Completed {len(sample_files)} visualizations.")

if __name__ == '__main__':
    visualize_graphs(snapshot_dir='graph_snapshots/', n=5, save_dir='graph_images/')