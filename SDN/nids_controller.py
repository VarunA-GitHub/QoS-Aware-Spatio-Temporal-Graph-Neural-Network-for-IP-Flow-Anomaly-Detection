from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, udp, icmp, arp, ether_types
from ryu.lib import hub
import time

class NIDSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NIDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        # --- NIDS STATE ---
        self.flow_stats = {} # Key: (dpid, src_ip), Value: {packet_count, byte_count, port_set}
        self.blocked_ips = set()
        
        # Start the Monitor Thread
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install Table-Miss Flow Entry (Send unknown packets to Controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout, 
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # --- NIDS INSPECTION (Deep Packet Inspection Simulation) ---
        self.inspect_packet(datapath, pkt, in_port)

        # Basic Switching Logic (L2 Learning)
        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid PacketIn next time (if we know the port)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def inspect_packet(self, datapath, pkt, in_port):
        """
        Real-time Packet Inspection for 'Instant' Triggers (Malware Payload)
        """
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        if ip_pkt:
            src_ip = ip_pkt.src
            
            # --- CHECK 1: BLOCKED IPs ---
            if src_ip in self.blocked_ips:
                return # Already blocked, switch will drop it based on installed rule

            # --- CHECK 2: MALWARE SIGNATURE (Payload Analysis) ---
            # Ryu often truncates payload in PacketIn, but for simulation we check available data
            # NOTE: In real Mininet, accessing raw payload requires parsing 'msg.data' deeper.
            # Here we use a high-level heuristic: traffic from Attacker (10.0.0.2) + Specific TCP Flags/Size
            
            # Simulating "MALWARE_PAYLOAD" detection:
            # If we see a TCP packet to port 80/443 from Attacker with PSH flag set, we might inspect
            pass

    def _monitor(self):
        """
        Periodic Monitor Thread (Every 5 Seconds)
        Requests Flow Stats to detect DoS and Recon
        """
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(5) # 5 Second Interval

    def request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
        ANALYSIS ENGINE
        Processes flow statistics to detect behavioral anomalies (DoS, Recon).
        """
        body = ev.msg.body
        
        # Aggregation Structure: IP -> {packet_count, distinct_dst_ports}
        traffic_profile = {} 

        for stat in body:
            # We only care about IP flows
            if 'ipv4_src' not in stat.match:
                continue
            
            src_ip = stat.match['ipv4_src']
            if src_ip == '10.0.0.1': continue # Ignore Victim traffic
            if src_ip == '127.0.0.1': continue
            
            # Check packet rate (Simplification: Total Packets / Time Window is roughly implied by deltas)
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            
            # Update Profile
            if src_ip not in traffic_profile:
                traffic_profile[src_ip] = {'pkts': 0, 'bytes': 0, 'flows': 0}
            
            traffic_profile[src_ip]['pkts'] += packet_count
            traffic_profile[src_ip]['bytes'] += byte_count
            traffic_profile[src_ip]['flows'] += 1

        # --- DETECTION LOGIC (The "Signature Mapping") ---
        for src_ip, stats in traffic_profile.items():
            if src_ip in self.blocked_ips:
                continue

            # 1. DoS DETECTION (High Volume)
            # Threshold: If an IP has sent > 2000 packets (cumulative) in short simulation
            # Note: In a real system, we'd use delta/second. Here we use raw count for robust simulation.
            if stats['pkts'] > 1000 and stats['flows'] < 5:
                self.block_ip(ev.msg.datapath, src_ip, reason="DoS (High Packet Rate)")

            # 2. RECONNAISSANCE DETECTION (Port Scan)
            # Logic: Many small flows (one per port) from same IP
            elif stats['flows'] > 20: 
                self.block_ip(ev.msg.datapath, src_ip, reason="Reconnaissance (Port Scan)")

    def block_ip(self, datapath, src_ip, reason="Malicious Activity"):
        """
        MITIGATION ENGINE
        Installs a DROP rule for the malicious IP.
        """
        if src_ip in self.blocked_ips: return

        print(f"\n\033[91m[ALERT] {reason} Detected from {src_ip}! Blocking for 10 seconds...\033[0m")
        self.blocked_ips.add(src_ip)
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Block Rule (Highest Priority)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        actions = [] # Empty actions = DROP
        
        # Hard Timeout = 10 seconds (Auto-unblock)
        self.add_flow(datapath, 100, match, actions, hard_timeout=10)
        
        # Schedule unblock in local state
        hub.spawn(self.unblock_later, src_ip)

    def unblock_later(self, src_ip):
        hub.sleep(10)
        print(f"\033[92m[INFO] Lifting block on {src_ip}.\033[0m")
        if src_ip in self.blocked_ips:
            self.blocked_ips.remove(src_ip)
