import os
import pickle
import torch
from torch_geometric.data import Data
from typing import cast

def check_graph_integrity(snapshot_dir='graph_snapshots/'):
    files = sorted([f for f in os.listdir(snapshot_dir) if f.endswith('.pkl')])

    valid = []
    corrupted = []
    missing_parts = []

    print(f"🔍 Checking {len(files)} snapshot files in: {snapshot_dir}")

    for fname in files:
        path = os.path.join(snapshot_dir, fname)
        try:
            with open(path, 'rb') as f:
                raw = pickle.load(f)

            data: Data = cast(Data, raw)

            # Check essential attributes exist and are torch.Tensor
            if not isinstance(data.x, torch.Tensor):
                missing_parts.append((fname, 'x not tensor'))
                continue
            if not isinstance(data.y, torch.Tensor):
                missing_parts.append((fname, 'y not tensor'))
                continue
            if not isinstance(data.edge_index, torch.Tensor):
                missing_parts.append((fname, 'edge_index not tensor'))
                continue

            if data.x.size(0) != data.y.size(0):
                missing_parts.append((fname, 'Mismatch: x vs y'))
                continue

            valid.append(fname)

        except Exception as e:
            corrupted.append((fname, str(e)))

    # Summary
    print("\n✅ Valid graph files:", len(valid))
    print("❌ Corrupted files:", len(corrupted))
    print("⚠️  Files with structure issues:", len(missing_parts))

    if corrupted:
        print("\n❌ Corrupted files:")
        for f, reason in corrupted:
            print(f" - {f}: {reason}")

    if missing_parts:
        print("\n⚠️ Files with structural issues:")
        for f, reason in missing_parts:
            print(f" - {f}: {reason}")

if __name__ == '__main__':
    check_graph_integrity('graph_snapshots/')
