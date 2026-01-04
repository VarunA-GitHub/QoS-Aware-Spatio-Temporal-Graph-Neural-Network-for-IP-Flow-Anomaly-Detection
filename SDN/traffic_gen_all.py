from scapy.all import *
import sys
import random
import pandas as pd
import os
import time

conf.verb = 0 
RAW_DATA_PATH = '../data/raw/UNSW-NB15_1.csv'
if not os.path.exists(RAW_DATA_PATH):
    RAW_DATA_PATH = 'data/raw/UNSW-NB15_1.csv'

# Set to 42 to exactly match your current Mininet session (h1-h42)
TOP_K_HOSTS = 42

def get_topology_ips():
    """Extract the first 42 IPs from the dataset to match the running topology."""
    if not os.path.exists(RAW_DATA_PATH):
        print(f"[ERROR] Dataset not found. Please ensure {RAW_DATA_PATH} exists.")
        return []
    
    try:
        df = pd.read_csv(RAW_DATA_PATH, nrows=50000, header=None, encoding='utf-8', low_memory=False)
        # Combine all source and destination IPs to find the top active ones
        all_ips = pd.concat([df[0], df[2]]) 
        ips = all_ips.value_counts().head(TOP_K_HOSTS).index.tolist()
        return ips
    except Exception as e:
        print(f"[ERROR] IP Extraction Failed: {e}")
        return []

def send_attack(src_ip, dst_ip, attack_type):
    # Mapping for Demo Triggers
    trig_map = {
        'Normal': (80, 'tcp'),
        'DoS': (80, 'udp'),
        'Reconnaissance': (1, 'tcp'),
        'Malware': (4444, 'tcp')
    }
    
    dport, proto = trig_map.get(attack_type, (80, 'tcp'))
    
    print(f"[*] Simulating {attack_type.upper()}: {src_ip} -> {dst_ip}")
    
    # Send 1 Trigger Packet
    # We spoof the source IP so it looks like it's coming from any host in the 42-host list
    if proto == 'tcp':
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=dport, flags="S")
    else:
        pkt = IP(src=src_ip, dst=dst_ip)/UDP(dport=dport)/Raw(load="DEMO_TRIGGER")
    
    send(pkt, count=1, verbose=False)

def run_automated_sim(ips):
    print(f"\n[INFO] Starting Automated Simulation (42 Host Universe)...")
    print(f"[INFO] Source and Destinations are randomized within the topology.")
    print("[INFO] Press Ctrl+C to stop.\n")
    
    categories = ['Normal', 'DoS', 'Reconnaissance', 'Malware']
    
    try:
        while True:
            # Randomly select a sender and a target from the 42 hosts
            src = random.choice(ips)
            dst = random.choice(ips)
            if src == dst: continue
            
            # Weighted random: More Normal traffic than Attacks
            atk = random.choices(categories, weights=[60, 15, 15, 10])[0]
            
            send_attack(src, dst, atk)
            
            # Random delay between events (1-4 seconds)
            time.sleep(random.uniform(1.0, 4.0))
            
    except KeyboardInterrupt:
        print("\n[INFO] Simulation Terminated.")

if __name__ == "__main__":
    host_ips = get_topology_ips()
    
    if not host_ips:
        print("[ERROR] Could not identify host IPs. Please check dataset path.")
        sys.exit(1)

    print("\n=== NIDS AUTOMATED TRAFFIC GENERATOR (42 HOSTS) ===")
    print(f"Loaded {len(host_ips)} hosts from topology data.")
    print("--------------------------------------------------")
    print("1. Start 'Any-to-Any' Stress Test (Continuous)")
    print("2. Manual Random Attack (One-time)")
    print("0. Exit")
    
    choice = input("\nSelect: ")
    
    if choice == '1':
        run_automated_sim(host_ips)
    elif choice == '2':
        # Single random event
        s = random.choice(host_ips)
        d = random.choice(host_ips)
        a = random.choice(['Normal', 'DoS', 'Reconnaissance', 'Malware'])
        send_attack(s, d, a)
    elif choice == '0':
        sys.exit()
