import pandas as pd
import numpy as np
from collections import defaultdict

def engineer_qos_features(df, start_time_col='Stime', end_time_col='Ltime', bin_interval=15):
    try:
        # 1. Convert start/end times to datetime
        for col in [start_time_col, end_time_col]:
            if col in df.columns:
                df[f'{col}_datetime'] = pd.to_datetime(df[col], unit='s')
            else:
                raise KeyError(f"[ERROR] Missing timestamp column: {col}")

        # 2. Keep only first 1 day of data
        min_time = df[f'{start_time_col}_datetime'].min()
        max_allowed_time = min_time + pd.Timedelta(days=1)
        df = df[df[f'{start_time_col}_datetime'] < max_allowed_time].copy()

        # 3. Add time bin column (based on bin_interval in seconds)
        df['time_bin'] = (df[start_time_col] // bin_interval).astype(int)

        # 4. Fill NaNs in numeric columns
        num_cols = df.select_dtypes(include=['number']).columns
        df[num_cols] = df[num_cols].fillna(0)

        # 5. Fill missing attack_cat if Label == 0
        if 'attack_cat' in df.columns and 'Label' in df.columns:
            df.loc[df['attack_cat'].isna() & (df['Label'] == 0), 'attack_cat'] = 'Normal'

        # 6. Ensure 'proto' and 'state' are string
        for col in ['proto', 'state']:
            if col in df.columns:
                df[col] = df[col].astype(str)
            else:
                raise KeyError(f"[ERROR] Missing expected column: {col}")

        # 7. Assign node_id = row index (each row is one node)
        df['node_id'] = df.index.astype(str)

        # 8. Build IP-based edges per row
        srcip_map = defaultdict(set)
        dstip_map = defaultdict(set)

        for idx, row in df.iterrows():
            srcip_map[row['srcip']].add(idx)
            dstip_map[row['dstip']].add(idx)

        directed_edges = set()
        for ip in srcip_map:
            if ip in dstip_map:
                for src_node in srcip_map[ip]:
                    for dst_node in dstip_map[ip]:
                        if src_node != dst_node:
                            directed_edges.add((src_node, dst_node))

        # 9. Group the DataFrame by time_bin
        graphs_by_time_bin = dict(tuple(df.groupby('time_bin')))

        print(f"[INFO] Filtered to 1 day: {df.shape[0]} rows")
        print(f"[INFO] Unique nodes (rows): {df.shape[0]}, Time bins: {df['time_bin'].nunique()}")
        print(f"[INFO] IP-based directed edges (across time): {len(directed_edges)}")

        return graphs_by_time_bin, directed_edges

    except Exception as e:
        raise RuntimeError(f"[ERROR] in engineer_qos_features(): {e}")
