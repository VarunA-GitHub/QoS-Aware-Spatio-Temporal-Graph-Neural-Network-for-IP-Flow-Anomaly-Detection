import pandas as pd
import sys
import os

# Configuration
RAW_DATA_PATH = 'data/raw/UNSW-NB15_1.csv'
TOP_K_HOSTS = 100 

def generate_topology_script():
    print(f"[INFO] Analyzing {RAW_DATA_PATH} to build Network Graph...")
    
    if not os.path.exists(RAW_DATA_PATH):
        print(f"[ERROR] {RAW_DATA_PATH} not found.")
        print("       Please ensure you are running this from the repository root")
        print("       and that 'data/raw/UNSW-NB15_1.csv' exists.")
        return

    # 1. Read subset of data to find active nodes
    try:
        df = pd.read_csv(RAW_DATA_PATH, nrows=50000, header=None, encoding='utf-8', low_memory=False)
    except Exception as e:
        print(f"[ERROR] Failed to read CSV: {e}")
        return

    # Heuristic: Identify IP columns (Col 0=Src, Col 2=Dst)
    src_col = 0
    dst_col = 2
    
    # 2. Extract Top Talkers
    all_ips = pd.concat([df[src_col], df[dst_col]])
    top_ips = all_ips.value_counts().head(TOP_K_HOSTS).index.tolist()
    
    print(f"[INFO] Identified Top {TOP_K_HOSTS} Active Hosts")
    
    # OUTPUT PATH FIX: Handle running from root or inside SDN/
    # If we are in the root 'NPS_Lab-master', we write to SDN/topology_data.py
    # If we are already in 'SDN/', we write to topology_data.py
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
        
        f.write("    info('*** Adding Switches\\n')\n")
        f.write("    # s1: Local Network (Private IPs)\n")
        f.write("    s1 = net.addSwitch('s1', protocols='OpenFlow13')\n")
        f.write("    # s2: Internet/External (Public IPs)\n")
        f.write("    s2 = net.addSwitch('s2', protocols='OpenFlow13')\n\n")
        
        f.write("    info('*** Linking Switches (Gateway)\\n')\n")
        f.write("    net.addLink(s1, s2)\n\n")
        
        f.write("    info('*** Adding Data-Driven Hosts\\n')\n")
        
        # Helper to classify IPs (Simple Heuristic for UNSW-NB15)
        # 10.x.x.x, 192.168.x.x, 172.16-31.x.x are private
        def is_private(ip_addr):
            if ip_addr.startswith("10."): return True
            if ip_addr.startswith("192.168."): return True
            if ip_addr.startswith("172."): 
                second = int(ip_addr.split('.')[1])
                if 16 <= second <= 31: return True
            return False

        host_map = {}
        for idx, ip in enumerate(top_ips):
            short_name = f"h{idx+1}"
            
            # Determine Switch
            if is_private(ip):
                parent_switch = "s1"
                stype = "LOCAL"
            else:
                parent_switch = "s2"
                stype = "EXTERNAL"
                
            f.write(f"    # {stype} Host: {ip}\n")
            f.write(f"    {short_name} = net.addHost('{short_name}', ip='{ip}')\n")
            f.write(f"    net.addLink({short_name}, {parent_switch})\n")
            
            host_map[ip] = short_name
            
        f.write("\n    info('*** Starting Network\\n')\n")
        f.write("    net.build()\n")
        f.write("    c0.start()\n")
        f.write("    s1.start([c0])\n")
        f.write("    s2.start([c0])\n\n")

        f.write("    info('*** Configuring Hosts (Simulation Routing)\\n')\n")
        # We must add a default route for the "Real IP" hosts so they can talk to each other
        # even though they are on different subnets (since we rely on the Controller for L2 forwarding)
        for idx, ip in enumerate(top_ips):
            short_name = f"h{idx+1}"
            # "ip route add default dev hX-eth0"
            f.write(f"    {short_name}.cmd('ip route add default dev {short_name}-eth0')\n")
        f.write("\n")

        f.write("    info('*** Verifying Connectivity\\n')\n")
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
    print(f"TOPOLOGY STRUCTURE:")
    print(f"  s1 (Internal) <---> s2 (External)")
    print(f"  Hosts distributed based on IP type.")
    print("------------------------------------------------")
    print(f"HOST MAPPING (First 10 of {TOP_K_HOSTS}):")
    for i, ip in enumerate(top_ips[:10]):
        print(f"  h{i+1} : {ip}")
    print("  ... and so on up to h100")
    print("------------------------------------------------")

if __name__ == "__main__":
    generate_topology_script()
