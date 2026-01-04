import os
import torch
import pickle
import numpy as np
import pandas as pd
from torch_geometric.data import Data
from sklearn.preprocessing import OneHotEncoder
from sklearn.neighbors import NearestNeighbors
from collections import defaultdict
from scipy.sparse import csr_matrix, issparse
from typing import cast

def build_graph_snapshots(df, save_dir='./graph_snapshots/', time_col='time_bin', k=5, use_gpu=True):
    os.makedirs(save_dir, exist_ok=True)
    device = torch.device('cuda' if use_gpu and torch.cuda.is_available() else 'cpu')
    print(f"[INFO] Using device: {device}")

    # === Step 1: One-hot encode categorical features ===
    categorical_cols = ['proto', 'state']
    encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
    encoded_cats = encoder.fit_transform(df[categorical_cols])

    # === Step 2: Select numerical QoS features directly ===
    qos_cols = ['sjit', 'djit', 'smean', 'dmean']
    qos_vals = df[qos_cols].values

    # === Step 3: Concatenate one-hot + QoS ===
    features = np.concatenate([encoded_cats, qos_vals], axis=1)

    # === Step 4: Final DataFrame to work with ===
    df_feat = pd.DataFrame(features, index=df.index)
    df_combined = pd.concat([df[['srcip', 'dstip', time_col, 'Label']], df_feat], axis=1)

    # === Step 5: Iterate over each time bin and build snapshot ===
    for time_val, group in df_combined.groupby(time_col):
        if len(group) < 2:
            print(f"[WARN] Skipping time_bin={time_val} (only {len(group)} rows)")
            continue

        x_np = group.iloc[:, 4:].values  # feature vectors
        x = torch.tensor(x_np, dtype=torch.float).to(device)
        y = torch.tensor(group['Label'].values, dtype=torch.long).to(device)

        # --- Build KNN graph
        knn = NearestNeighbors(n_neighbors=min(k, len(group)), metric='cosine')
        knn.fit(x_np)
        knn_edges = knn.kneighbors_graph(mode='connectivity')

        if not issparse(knn_edges):
            raise TypeError("Expected sparse KNN graph")

        knn_edges = cast(csr_matrix, knn_edges).tocoo()
        edge_index = [knn_edges.row.tolist(), knn_edges.col.tolist()]

        # --- Add IP-based edges
        ip_map = defaultdict(list)
        for i, ip in enumerate(group['srcip']):
            ip_map[ip].append(i)
        for i, ip in enumerate(group['dstip']):
            ip_map[ip].append(i)
        for ip, indices in ip_map.items():
            for i in indices:
                for j in indices:
                    if i != j:
                        edge_index[0].append(i)
                        edge_index[1].append(j)

        edge_index = torch.tensor(edge_index, dtype=torch.long).to(device)

        # --- Create and save snapshot
        data = Data(x=x, edge_index=edge_index, y=y)
        save_path = os.path.join(save_dir, f'graph_t{time_val}.pkl')
        with open(save_path, 'wb') as f:
            pickle.dump(data.to('cpu'), f)

        print(f"[✓] Saved graph_t{time_val}.pkl → Nodes: {x.shape[0]}, Edges: {edge_index.shape[1]}")

    print(f"[INFO] All graph snapshots saved in: {save_dir}")

# === Entry Point ===
if __name__ == '__main__':
    df = pd.read_csv('data/processed/unsw_qos_flat.csv')  # adjust if path differs
    build_graph_snapshots(df)
