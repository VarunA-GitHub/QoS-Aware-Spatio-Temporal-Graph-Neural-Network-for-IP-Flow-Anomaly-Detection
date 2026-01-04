from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    """
    Mininet Topology for NIDS Phase 2
    Switch: s1 (OpenFlow 1.3)
    Hosts:
      - h1 (Victim/Server): 10.0.0.1
      - h2 (Attacker):      10.0.0.2
      - h3 (Normal User):   10.0.0.3
    """
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch, link=TCLink)

    info("=== Adding Controller (Ryu) ===\n")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    info("=== Adding Switch (OpenFlow 1.3) ===\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    info("=== Adding Hosts ===\n")
    h1 = net.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03')

    info("=== Creating Links ===\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    info("=== Starting Network ===\n")
    net.build()
    c0.start()
    s1.start([c0])

    info("=== Verifying Connectivity ===\n")
    # h1 starts a web server (optional, for realism)
    h1.cmd('python3 -m http.server 80 &')
    
    info("=== Running CLI ===\n")
    CLI(net)

    info("=== Stopping Network ===\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()

# INSTRUCTIONS FOR KALI LINUX / UBUNTU:
# 1. Ensure Open vSwitch and Mininet are installed.
# 2. Run the Controller FIRST:
#    ryu-manager SDN/nids_controller.py
# 3. In a new terminal, run this topology (requires sudo):
#    sudo python3 SDN/topology.py
