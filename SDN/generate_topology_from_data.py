import pandas as pd
import networkx as nx
import sys
import os

# Configuration
RAW_DATA_PATH = 'data/raw/UNSW-NB15_1.csv'
OUTPUT_FILE = 'SDN/topology_data.py'
TOP_K_HOSTS = 5 

def generate_topology_script():
    print(f"[INFO] Analyzing {RAW_DATA_PATH} to build Network Graph...")
    
    if not os.path.exists(RAW_DATA_PATH):
        print(f"[ERROR] {RAW_DATA_PATH} not found.")
        return

    # 1. Read subset of data to find active nodes
    # UNSW-NB15_1.csv has no headers usually, or specific ones. 
    # Based on standard UNSW format: SrcIP is col 0, DstIP is col 2 (usually)
    # Let's read with generic headers to be safe then inspect
    try:
        df = pd.read_csv(RAW_DATA_PATH, nrows=50000, header=None, encoding='utf-8', low_memory=False)
    except:
        print("[ERROR] Failed to read CSV.")
        return

    # Heuristic: Identify IP columns. 
    # Usually Col 0 = SrcIP, Col 2 = DstIP in UNSW-NB15 raw files
    src_col = 0
    dst_col = 2
    
    # 2. Extract Top Talkers
    # We want a manageable topology, so we pick the top K most frequent IPs
    all_ips = pd.concat([df[src_col], df[dst_col]])
    top_ips = all_ips.value_counts().head(TOP_K_HOSTS).index.tolist()
    
    print(f"[INFO] Identified Top {TOP_K_HOSTS} Active Hosts: {top_ips}")
    
    # OUTPUT PATH FIX: Handle running from root or inside SDN/
    if os.path.exists('SDN') and os.path.isdir('SDN'):
        # Running from Root
        final_output = 'SDN/topology_data.py'
    else:
        # Running inside SDN/ or flat dir
        final_output = 'topology_data.py'

    # 3. Generate Python Mininet Script
    with open(final_output, 'w') as f:
        f.write("from mininet.net import Mininet\n")
        f.write("from mininet.node import RemoteController, OVSKernelSwitch\n")
        f.write("from mininet.cli import CLI\n")
        f.write("from mininet.log import setLogLevel, info\n")
        f.write("from mininet.link import TCLink\n\n")
        
        f.write("def create_data_driven_topology():\n")
        f.write("    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)\n\n")
        
        f.write("    info('*** Adding Controller (Ryu)\\n')\n")
        f.write("    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)\n\n")
        
        f.write("    info('*** Adding Switch\\n')\n")
        f.write("    s1 = net.addSwitch('s1', protocols='OpenFlow13')\n\n")
        
        f.write("    info('*** Adding Data-Driven Hosts\\n')\n")
        
        # Add Hosts with Simple Names (h1, h2) but Real IPs
        host_map = {}
        for idx, ip in enumerate(top_ips):
            # h1, h2, h3...
            short_name = f"h{idx+1}"
            f.write(f"    # Real IP: {ip}\n")
            f.write(f"    {short_name} = net.addHost('{short_name}', ip='{ip}')\n")
            host_map[ip] = short_name
            
        f.write("\n    info('*** Creating Links to Core Switch\\n')\n")
        for ip, host_var in host_map.items():
            f.write(f"    net.addLink({host_var}, s1)\n")
            
        f.write("\n    info('*** Starting Network\\n')\n")
        f.write("    net.build()\n")
        f.write("    c0.start()\n")
        f.write("    s1.start([c0])\n\n")
        
        f.write("    info('*** Verifying Connectivity\\n')\n")
        f.write("    # Start a simple server on the first host\n")
        f.write(f"    h1.cmd('python3 -m http.server 80 &')\n\n")
        
        f.write("    info('*** Running CLI\\n')\n")
        f.write("    CLI(net)\n\n")
        f.write("    info('*** Stopping Network\\n')\n")
        f.write("    net.stop()\n\n")
        
        f.write("if __name__ == '__main__':\n")
        f.write("    setLogLevel('info')\n")
        f.write("    create_data_driven_topology()\n")
        
    print(f"[SUCCESS] Generated {final_output}")
    print("------------------------------------------------")
    print("HOST MAPPING (Use these names in Mininet):")
    for i, ip in enumerate(top_ips):
        print(f"  h{i+1} : {ip}")
    print("------------------------------------------------")

if __name__ == "__main__":
    generate_topology_script()
