from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
from ryu.lib.packet import ether_types
import csv
import os
import time
import threading
from collections import deque
import pickle


class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.service_count = {}
        self.src_bytes = {}
        self.count = 0
        self.srv_count = {}
        self.srv_diff_host_rate = {}
        self.dst_host_count = {}
        self.dst_host_srv_count = {}
        self.dst_host_srv_diff_host_rate = {}
        self.dst_host_srv_rerror_rate = {}

        self.datapaths = {}  # Store datapath objects here

        self.service_ports = {
            80: 'http', 25: 'smtp', 79: 'finger', 53: 'domain_u', 113: 'auth', 23: 'telnet',
            21: 'ftp', 7: 'echo', 37: 'time', 69: 'tftp_u', 9: 'discard', 109: 'pop_2',
            110: 'pop_3', 20: 'ftp_data', 70: 'gopher', 119: 'nntp', 143: 'imap4', 22: 'ssh',
            443: 'http_443', 514: 'shell', 512: 'exec', 513: 'login', 17: 'qotd', 111: 'sunrpc',
            7: 'echo', 19: 'chargen', 95: 'supdup', 101: 'hostname', 117: 'uucp_path', 179: 'bgp',
            369: 'rpc2portmap', 389: 'ldap', 425: 'icad', 514: 'syslog', 515: 'printer', 635: 'mountd',
            636: 'ldapssl', 873: 'rsync', 989: 'ftps-data', 990: 'ftps', 992: 'telnets', 993: 'imaps',
            995: 'pop3s', 1080: 'socks', 123: 'ntp_u', 161: 'snmp', 162: 'snmptrap', 513: 'whois',
            2049: 'nfs', 3306: 'mysql', 3389: 'ms-wbt-server', 5060: 'sip', 8080: 'http-proxy'
        }

        # Initialize CSV file
        self.csv_filename = "features.csv"
        self.initialize_csv()

        # Start the periodic flow update
        self.flow_update_interval = 5  # Interval in seconds
        self.start_periodic_flow_update()

        # Load the pre-trained model
        self.model = self.load_model('/home/yazdan/Downloads/catboost_dupremove.pkl')

        # Store recent flow features
        self.recent_flows = deque(maxlen=100)  # Change maxlen as per your requirement

    def load_model(self, model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        return model

    def initialize_csv(self):
        file_exists = os.path.isfile(self.csv_filename)
        if not file_exists:
            with open(self.csv_filename, 'w', newline='') as csvfile:
                fieldnames = ['service', 'src_bytes', 'count', 'srv_count', 'srv_diff_host_rate',
                              'dst_host_count', 'dst_host_srv_count', 'dst_host_srv_diff_host_rate', 'dst_host_srv_rerror_rate']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install a default flow to drop unmatched packets
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Register the datapath
        self.datapaths[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def delete_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        # Additional packet processing
        self.process_packet(pkt, datapath, in_port, msg.buffer_id)

        
    def process_packet(self, pkt, datapath, in_port, buffer_id):
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            self.logger.debug("Ethernet protocol not found")
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            self.logger.debug("IPv4 protocol not found")
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        service = "unknown"
        dst_port = None
        src_port = None
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if tcp_pkt:
            src_port = tcp_pkt.src_port
            dst_port = tcp_pkt.dst_port
            service = self.service_ports.get(dst_port, self.service_ports.get(src_port, "unknown"))
            self.logger.info(f"TCP packet: src_ip={src_ip}, dst_ip={dst_ip}, src_port={src_port}, dst_port={dst_port}, service={service}")
        elif udp_pkt:
            src_port = udp_pkt.src_port
            dst_port = udp_pkt.dst_port
            service = self.service_ports.get(dst_port, self.service_ports.get(src_port, "unknown"))
            self.logger.info(f"UDP packet: src_ip={src_ip}, dst_ip={dst_ip}, src_port={src_port}, dst_port={dst_port}, service={service}")
        elif icmp_pkt:
            service = "eco_i"
            self.logger.info(f"ICMP packet: src_ip={src_ip}, dst_ip={dst_ip}, service={service}")

        # Process the features
        features = self.process_features(src_ip, dst_ip, dst_port, service, tcp_pkt, udp_pkt, icmp_pkt)

        # Make prediction
        prediction = self.model.predict([features])
        self.logger.info(f"Prediction: {prediction}")

        if prediction == "normal.":
            self.forward_packet(datapath, in_port, pkt, buffer_id)
        else:
            self.drop_packet(datapath, in_port, pkt, buffer_id)

        self.save_features_to_csv(service, self.src_bytes[dst_ip], self.count, self.service_count[dst_port],
                                  self.srv_diff_host_rate[dst_port], self.dst_host_count[dst_ip],
                                  self.dst_host_srv_count[dst_ip][service], self.dst_host_srv_diff_host_rate[dst_ip],
                                  features[-1])  # Pass the last feature (dst_host_srv_rerror_rate)
    def forward_packet(self, datapath, in_port, pkt, buffer_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # Install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, buffer_id)
        
        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = pkt.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def drop_packet(self, datapath, in_port, pkt, buffer_id):
        self.logger.info("Dropping packet")

    def process_features(self, src_ip, dst_ip, dst_port, service, tcp_pkt, udp_pkt, icmp_pkt):
        self.count += 1

        # Assuming src_bytes to be the length of the payload in the packet
        src_bytes = len(src_ip) + len(dst_ip)  # Modify this to accurately reflect actual src_bytes

        # Update the source bytes
        if dst_ip not in self.src_bytes:
            self.src_bytes[dst_ip] = 0
        self.src_bytes[dst_ip] += src_bytes

        # Update the service count
        if dst_port not in self.service_count:
            self.service_count[dst_port] = 0
        self.service_count[dst_port] += 1

        # Update the server count
        if dst_port not in self.srv_count:
            self.srv_count[dst_port] = 0
        self.srv_count[dst_port] += 1

        # Calculate srv_diff_host_rate
        if dst_port not in self.srv_diff_host_rate:
            self.srv_diff_host_rate[dst_port] = 0
        if self.srv_count[dst_port] > 0:
            self.srv_diff_host_rate[dst_port] = len(set([src_ip])) / self.srv_count[dst_port]

        # Update the destination host count
        if dst_ip not in self.dst_host_count:
            self.dst_host_count[dst_ip] = 0
        self.dst_host_count[dst_ip] += 1

        # Update the destination host service count
        if dst_ip not in self.dst_host_srv_count:
            self.dst_host_srv_count[dst_ip] = {}
        if service not in self.dst_host_srv_count[dst_ip]:
            self.dst_host_srv_count[dst_ip][service] = 0
        self.dst_host_srv_count[dst_ip][service] += 1

        # Calculate dst_host_srv_diff_host_rate
        if dst_ip not in self.dst_host_srv_diff_host_rate:
            self.dst_host_srv_diff_host_rate[dst_ip] = 0
        if self.dst_host_srv_count[dst_ip][service] > 0:
            self.dst_host_srv_diff_host_rate[dst_ip] = len(set([src_ip])) / self.dst_host_srv_count[dst_ip][service]

        # Calculate dst_host_srv_rerror_rate for TCP packets with RST flag set
        dst_host_srv_rerror_rate = 0
        if tcp_pkt and tcp_pkt.bits & 0x04:  # TCP RST flag
            if dst_ip not in self.dst_host_srv_rerror_rate:
                self.dst_host_srv_rerror_rate[dst_ip] = 0
            self.dst_host_srv_rerror_rate[dst_ip] += 1
            dst_host_srv_rerror_rate = self.dst_host_srv_rerror_rate[dst_ip] / self.dst_host_srv_count[dst_ip][service]

        # Append the features to recent flows
        features = [service, self.src_bytes[dst_ip], self.count, self.service_count[dst_port],
                    self.srv_diff_host_rate[dst_port], self.dst_host_count[dst_ip],
                    self.dst_host_srv_count[dst_ip][service], self.dst_host_srv_diff_host_rate[dst_ip],
                    dst_host_srv_rerror_rate]
        self.recent_flows.append(features)
        self.save_features_to_csv(service, self.src_bytes[dst_ip], self.count, self.service_count[dst_port],
                                  self.srv_diff_host_rate[dst_port], self.dst_host_count[dst_ip],
                                  self.dst_host_srv_count[dst_ip][service], self.dst_host_srv_diff_host_rate[dst_ip],
                                  dst_host_srv_rerror_rate)

        return features

    def save_features_to_csv(self, service, src_bytes, count, srv_count, srv_diff_host_rate,
                             dst_host_count, dst_host_srv_count, dst_host_srv_diff_host_rate, dst_host_srv_rerror_rate):
        with open(self.csv_filename, 'a', newline='') as csvfile:
            fieldnames = ['service', 'src_bytes', 'count', 'srv_count', 'srv_diff_host_rate',
                          'dst_host_count', 'dst_host_srv_count', 'dst_host_srv_diff_host_rate', 'dst_host_srv_rerror_rate']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({'service': service, 'src_bytes': src_bytes, 'count': count, 'srv_count': srv_count,
                             'srv_diff_host_rate': srv_diff_host_rate, 'dst_host_count': dst_host_count,
                             'dst_host_srv_count': dst_host_srv_count, 'dst_host_srv_diff_host_rate': dst_host_srv_diff_host_rate,
                             'dst_host_srv_rerror_rate': dst_host_srv_rerror_rate})

    def start_periodic_flow_update(self):
        threading.Thread(target=self.periodic_flow_update).start()

    def periodic_flow_update(self):
        while True:
            time.sleep(self.flow_update_interval)
            self.update_flows()

    def update_flows(self):
        for dpid, datapath in self.datapaths.items():
            self.delete_flows(datapath)  # Clear existing flows
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0, match, actions)  # Add default flow again

