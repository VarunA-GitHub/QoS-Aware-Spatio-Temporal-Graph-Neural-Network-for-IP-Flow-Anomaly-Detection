from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet, ethernet, ipv4, ether_types, tcp, udp
from ryu.lib import hub
import joblib
import os
import time

class NIDSControllerML(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NIDSControllerML, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.blocked_ips = set()
        self.logged_flows = {} 
        
        # Load ML (Optional Fallback)
        self.model_path = 'models/stgnn_model.pkl'
        self.model = None
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print("\033[92m[NIDS] SUCCESS: Loaded ST-GNN Model.\033[0m")
            except:
                pass

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Clean Start: Purge old rules
        self.remove_all_flows(datapath)
        
        # Table-Miss: Send ONLY NEW flows to Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print(f"\033[96m[NIDS] Switch {datapath.id} Ready for Demo.\033[0m")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def remove_all_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = parser.OFPFlowMod(datapath=datapath, table_id=ofproto.OFPTT_ALL,
                                command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY, match=parser.OFPMatch())
        datapath.send_msg(msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP: return
        
        dst, src = eth.dst, eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # --- INSTANT DETECTION LOGIC ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            # 1. Blocked Visibility
            if ip_pkt.src in self.blocked_ips:
                ban_list = list(self.blocked_ips)
                self.log_traffic(ip_pkt.src, ip_pkt.dst, f"Blocked Host (Total Bans: {len(ban_list)})", 
                                 f"DROP | Current Bans: {ban_list}", "\033[93m", 1000)
                return

            # 2. Extract Ports
            dst_port = 0
            if ip_pkt.proto == inet.IPPROTO_TCP:
                t = pkt.get_protocol(tcp.tcp)
                dst_port = t.dst_port
            elif ip_pkt.proto == inet.IPPROTO_UDP:
                u = pkt.get_protocol(udp.udp)
                dst_port = u.dst_port

            # 3. Demo Signature Triggers (Immediate Alerts)
            category = None
            if ip_pkt.proto == 17 and dst_port == 80: category = "DoS"
            elif dst_port == 1: category = "Reconnaissance"
            elif dst_port == 4444: category = "Malware"

            if category:
                self.log_traffic(ip_pkt.src, ip_pkt.dst, f"Attack ({category})", "DROP", "\033[91m", 1000)
                self.block_ip(datapath, ip_pkt.src, category)
                return

            # 4. Normal Traffic Handling
            self.log_traffic(ip_pkt.src, ip_pkt.dst, "Normal", "ALLOW", "\033[92m", 20)
            
            # Install specific flow matching L3/L4 to prevent Packet-In churn
            if out_port != ofproto.OFPP_FLOOD:
                match_args = {
                    'eth_type': ether_types.ETH_TYPE_IP,
                    'ipv4_src': ip_pkt.src,
                    'ipv4_dst': ip_pkt.dst,
                    'ip_proto': ip_pkt.proto
                }
                if dst_port:
                    if ip_pkt.proto == 6: match_args['tcp_dst'] = dst_port
                    elif ip_pkt.proto == 17: match_args['udp_dst'] = dst_port
                
                match = parser.OFPMatch(**match_args)
                self.add_flow(datapath, 10, match, actions, idle_timeout=3)

        # Forward current packet
        data = None if msg.buffer_id == ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def log_traffic(self, src, dst, cat, action, color, pkts):
        # Key on (src, category) to avoid spamming the same event too fast
        key = (src, cat)
        now = time.time()
        if key not in self.logged_flows or (now - self.logged_flows[key] > 3):
            print(f"{color}[TRAFFIC] {src} -> {dst} | Pkts: {pkts} | Type: {cat} | Action: {action}\033[0m")
            self.logged_flows[key] = now

    def block_ip(self, datapath, ip, reason):
        if ip in self.blocked_ips: return
        print(f"\n\033[91m[ALERT] {reason} Detected! Blocking {ip} for 10s...\033[0m")
        self.blocked_ips.add(ip)
        
        # Immediate Drop Rule
        match = datapath.ofproto_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip)
        self.add_flow(datapath, 100, match, [], hard_timeout=10)
        
        def lift():
            hub.sleep(10)
            if ip in self.blocked_ips:
                self.blocked_ips.remove(ip)
                print(f"[\033[96mINFO\033[0m] Lifting block on {ip}. Host can communicate again.")
        hub.spawn(lift)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[ev.datapath.id] = ev.datapath
        elif ev.state == DEAD_DISPATCHER:
            if ev.datapath.id in self.datapaths: del self.datapaths[ev.datapath.id]
