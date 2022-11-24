from nis import match
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp 
from ryu.lib.packet import arp
from ryu.ofproto import inet,ether
from ryu.ofproto.ofproto_v1_3 import OFPG_ANY
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.topology import event, switches
from ryu.controller import handler
from asyncio.log import logger
from ipaddress import ip_network
from ipaddress import ip_interface
import networkx as nx

# To create a copy of the dict
import copy

# To work with IP easily
import ipaddress

from ryu.lib import dpid as dpid_lib
import netaddr
from port import Port
from gateway import Gateway

# Define IPv4 addresses to each port of each switch
# {DPID:{PORT: IP}}
#interface_port_to_ip = {1: {1: '192.168.1.254', 2: '192.168.2.254', 3: '192.168.3.254'}}

interface_port_to_ip = {1: {1: '10.0.0.1', 2: '192.168.1.254', 3: '10.0.3.1', 4: '10.0.1.1', 5: '192.168.11.254'}, 
                        2: {1: '10.0.0.2', 2: '192.168.2.254', 3: '10.0.6.1', 4: '10.0.2.1', 5: '192.168.20.254'},
                        3: {1: '10.0.3.2', 2: '192.168.3.254', 3: '10.0.5.2'},
                        4: {1: '10.0.6.2', 2: '192.168.4.254', 3: '10.0.4.1'},
                        5: {1: '10.0.5.1', 2: '10.0.4.2', 3: '10.0.2.2', 4: '10.0.1.2', 5: '192.168.5.254'},
                        #6: {1: '192.168.10.253', 2: '192.168.11.253', 3: '192.168.11.254'}
                        }

mask = '255.255.255.0' #mask = /24 to all the networks in the topology...


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.hw_addr = {}
        self.L3_mac_to_port = {}
        self.L3_ip_to_mac = {}
        self.queue = {}
        self.datapaths = {}
        # Used to keep and track topology changes
        self.topology_api_app = self
        self.links = {}
        self.best_paths = {}
        self.int_port_to_ip = copy.deepcopy(interface_port_to_ip)
        self.topology = nx.DiGraph()
        self.cookies = {}
        self.cookie_value = 1
        self.prio = 1000
        H1_mac = "00:00:00:00:00:06"          # Host 5's mac
        H1_ip = "192.168.1.11"                    # Host 5's IP   
        H4_mac = "00:00:00:00:00:04"          # Host 6's mac
        H4_ip = "192.168.4.10"                    # Host 6's IP
        next_server = ""      # Stores the IP of the  next server to use in round robin manner
        current_server = ""   # Stores the current server's IP
        ip_to_port = {H1_ip: 2, H4_ip: 2}
        ip_to_mac ={"192.168.1.10": "00:00:00:00:00:01",
                 "192.168.2.10": "00:00:00:00:00:02",
                 "192.168.3.10": "00:00:00:00:00:03",
                 "192.168.4.10": "00:00:00:00:00:04",
                 "192.168.5.10": "00:00:00:00:00:05",
                 "192.168.11.11": "00:00:00:00:00:06"}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths.setdefault(datapath.id, datapath)
        self.logger.info('DATAPATHS -> %s', self.datapaths)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(ev.msg.datapath.address)
        #address = ev.switch.dp.address
        #dpid = ev.switch.dp.id
        #self.logger.info(address)
        #self.logger.info(dpid)
        print("New switch is waiting configuration and located at ",ev.msg.datapath," and ID is ",ev.msg.datapath.id)
        
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, 1, match, actions)
        self.send_port_desc_stats_request(datapath)

       
    # This defination creates a match, action and adds flow to switch
    
    # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
    
            #match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("S1\nS1\nS1")

        # switch s2
        
        elif datapath.id == 2:


            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S2\nS2\nS2")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S3\nS3\nS3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            #match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S4\nS4\nS4")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nS5\nS5")
            
        else:
            print ("Hiii there noopp sws")

        #####################################################round2###########################################
        #####################################################round2###########################################
        # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
    
            #match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("S1\nS1\nS1")

        # switch s2
        
        elif datapath.id == 2:


            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            #match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S2\nS2\nS2")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S3\nS3\nS3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S4\nS4\nS4")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nS5\nS5")
            
        else:
            print ("Hiii there noopp sws")


        #####################################################round3###########################################
        #####################################################round3###########################################
        #####################################################round3###########################################
        # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.11.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
    
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.11.11")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            print("S1\nSta6\nsaiunaP3")

        # switch s2
        
        elif datapath.id == 2:

            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.11.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.11.11")
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S2\nSta6\nSaiunaP4")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.11.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.11.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("St3\nSta6\nSaiuP3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.11.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            #match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.11.11")
            #actions = [parser.OFPActionOutput(1)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("Sta4\nSta4\nSta4")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.11.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.11.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nSta6\nSaiuP1")

        # switch s6
        elif datapath.id == 6:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.11.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.11.11")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            print("S6\nS6\nS6")
            
        else:
            print ("Hiii there noopp sws")

        #####################################################round4###########################################
        #####################################################round4###########################################
        #####################################################round4###########################################
        #####################################################round4###########################################
        # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            #match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            #actions = [parser.OFPActionOutput(3)]
            #self.add_flow(datapath, 2, match, actions)
    
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)
            print("S1\nSta6\nSta6")

        # switch s2
        
        elif datapath.id == 2:

            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            #match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            #actions = [parser.OFPActionOutput(4)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("Sta2\nSta2\nSta2")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("Sta3\nSta3\nSta3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.11.1")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S4\nSta6\nSta6")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nS5\nS5")

        # switch s6
        elif datapath.id == 6:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.2.11", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S6\nS6\nS6")
            
        else:
            print ("Hiii there noopp sws")


    
    # Whenever new TCP flow occur switch forward packet first packet to controller
        '''
        dpid = dp.id

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        dst_port = tcp_pkt.dst_port
        src_port = tcp_pkt.src_port

        if ipv4_src == "192.168.1.11" and ipv4_dst == "192.168.4.10":

            for n in range(1, 10):

            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst,ip_proto=ip_proto,tcp_dst=dst_port, tcp_src=src_port)

            self.add_reactive_flow(self.dp4, match, 0, 100, 2)
            self.add_reactive_flow(self.dp1, match, 0, 100, 2)
            self.add_reactive_flow(self.dp5, match, 0, 100, 1)

        if (dpid == 1):  # Switch one
            self.dp1 = datapath
            self.flow_match_layer3(datapath, inet.IPPROTO_ICMP)

        if (dpid == 2):  # Switch two
            self.dp2 = datapath
            self.flow_match_layer3(datapath, inet.IPPROTO_ICMP)

        if (dpid == 3):  # Switch two
            self.dp3 = datapath
            self.flow_match_layer3(datapath, inet.IPPROTO_ICMP)

        if (dpid == 4):  # Switch four
            self.dp4 = datapath
            self.flow_match_layer3(datapath, inet.IPPROTO_ICMP)

        if (dpid == 5):  # Switch five
            self.dp5 = datapath
            self.flow_match_layer3(datapath, inet.IPPROTO_ICMP)
    
    def flow_match_layer3(self, datapath, proto):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=proto)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(datapath, match, inst, 0, 10)'''


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

    def add_flow_best_path(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.cookie_value = self.cookie_value+1

        if self.cookie_value == 50:
            self.cookie_value = 1

        self.cookies[datapath.id] = self.cookie_value

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    cookie = self.cookies[datapath.id],
                                    cookie_mask = 0xFFFFFFFFFFFFFFFF,
                                    buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    cookie = self.cookies[datapath.id],
                                    cookie_mask = 0xFFFFFFFFFFFFFFFF,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        datapath.send_msg(mod) 

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        self.L3_mac_to_port.setdefault(dpid, {})
        self.L3_ip_to_mac.setdefault(dpid, {})

        for p in ev.msg.body:
            self.L3_mac_to_port[dpid][p.hw_addr] = p.port_no
            if not p.port_no == 4294967294:
                self.L3_ip_to_mac[dpid][interface_port_to_ip[dpid][p.port_no]] = p.hw_addr

        self.logger.info('%d MAC TABLE: %s', dpid, self.L3_mac_to_port[dpid])
        self.logger.info('%d ARP TABLE: %s', dpid, self.L3_ip_to_mac[dpid])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        #self.firewall()
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
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
        print("\nEthernet Packet is ",eth)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6 (redundance)
            return

        dst_mac = eth.dst
        src_mac = eth.src

        print("Destination Mac address is ",dst_mac)
        print("Source Mac address is ",src_mac)

        
        #dpid = format(datapath.id, "d").zfill(16)
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        print("*-*-*-*-*-*-*-*-*-*-*-* New Packet it during Normal operation -*-*-*-*-*-*-*-*-*-*-")
        print("New packet from switch datapath id ",datapath.id)

        self.ip_to_mac.setdefault(dpid, {})
        
        #dp.ofproto and dp.ofproto_parser are objects that represent the OpenFlow protocol that Ryu and the switch negotiated.
        print("message is is ", msg)
        ethernet_type=eth.ethertype
        print("\nEthernet Packet is ",eth)
        print("Source Mac address is ",src_mac)
        print("Destination Mac address is ",dst_mac)
        print("Switch port number is ",msg.match['in_port'])

        '''if(ethernet_type==0x800):
            print("ICMP Echo Request or Echo Reply IPv4")
        elif(ethernet_type==0x806):
            print("ARP Request or reply for who has IP ... tell ... or reply my ip .... is at mac")
        elif(ethernet_type==0x86dd):
            print("router solicitation IPv6")'''
		
        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(msg, pkt, in_port, src_mac)
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            protocol = ip_pkt.proto

            # Check if it's a multicast address, if it's ignore it!
            multi = int(dst_ip[0:dst_ip.find('.')])
            b = bin(multi)
            if b[2:6] == '1110':
                #Ignore Multicast
                return

            self.update_mac_table(datapath, src_mac, in_port)
            self.update_ip_table(datapath, src_ip, src_mac)

            if dst_ip in self.ip_to_mac[dpid]:
                self.logger.info('NEW FLOW ADDED, PLS CHECK FLOW TABLE')
                self.inject_flow(datapath, src_ip, in_port, dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]], 2)
                self.inject_flow(datapath,dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]], src_ip, in_port,2)
                self.forward_pkt(msg, in_port, src_ip, dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]])
                
            
            elif dst_ip in self.L3_ip_to_mac[dpid]:
                if protocol == in_proto.IPPROTO_ICMP:
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    echo = icmp_pkt.data

                    if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                        self.logger.info('ICMP REPLY to %s in port %d', dst_ip, in_port)
                        # Could be good add a flow to avoid use the controller
                        self.send_icmp(datapath, icmp.ICMP_ECHO_REPLY, echo, dst_ip, self.L3_ip_to_mac[dpid][dst_ip], src_ip, src_mac, in_port)
                        return
        
                
            else:
                if protocol == in_proto.IPPROTO_ICMP:
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    echo = icmp_pkt.data
                # Should enqueue the arrived packet here while switch search for the MAC....
                self.flood_arp(datapath, dst_ip, in_port,src_mac,src_ip,msg)
                return
           
        # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
    
            #match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("S1\nS1\nS1")

        # switch s2
        
        elif datapath.id == 2:


            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S2\nS2\nS2")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S3\nS3\nS3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            #match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S4\nS4\nS4")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.10", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nS5\nS5")
            
        else:
            print ("Hiii there noopp sws")

        #####################################################round2###########################################
        #####################################################round2###########################################
        # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
    
            #match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("S1\nS1\nS1")

        # switch s2
        
        elif datapath.id == 2:


            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            #match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            #actions = [parser.OFPActionOutput(2)]
            #self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S2\nS2\nS2")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S3\nS3\nS3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S4\nS4\nS4")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.10", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nS5\nS5")
            
        else:
            print ("Hiii there noopp sws")


        #####################################################round3###########################################
        #####################################################round3###########################################
        #####################################################round3###########################################
        # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            #match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.4.10")
            #actions = [parser.OFPActionOutput(3)]
            #self.add_flow(datapath, 2, match, actions)
    
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)
            print("S1\nSta6\nsaiunaP3")

        # switch s2
        
        elif datapath.id == 2:

            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(4)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S2\nSta6\nSaiunaP4")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.4.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("St3\nSta6\nSaiuP3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            #match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.11")
            #actions = [parser.OFPActionOutput(1)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("Sta4\nSta4\nSta4")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nSta6\nSaiuP1")

        # switch s6
        elif datapath.id == 6:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.11", ipv4_dst="192.168.4.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.4.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S6\nS6\nS6")
            
        else:
            print ("Hiii there noopp sws")

        #####################################################round4###########################################
        #####################################################round4###########################################
        #####################################################round4###########################################
        #####################################################round4###########################################
        # switch s1
        if datapath.id == 1:

            #add the return flow for h1 in h4.  
            # h1 is connected to port 2.
        
            #match = parser.OFPMatch(in_port=2, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            #actions = [parser.OFPActionOutput(3)]
            #self.add_flow(datapath, 2, match, actions)
    
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)
            print("S1\nSta6\nSta6")

        # switch s2
        
        elif datapath.id == 2:

            #add the return flow for h1 in s2.  
            # h1 is connected to port 2.
            match = parser.OFPMatch(in_port=4, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 2, match, actions)

            #match = parser.OFPMatch(in_port=2, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            #actions = [parser.OFPActionOutput(4)]
            #self.add_flow(datapath, 2, match, actions)
            
            print("Sta2\nSta2\nSta2")

        # switch s3
        elif datapath.id == 3:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            
            print("Sta3\nSta3\nSta3")
        
        # switch s4
        elif datapath.id == 4:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=3, eth_type=0x0800, ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.11.1")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)
            
            print("S4\nSta6\nSta6")

        # switch s5
        elif datapath.id == 5:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=3, eth_type=0x0800,ipv4_src="192.168.2.10", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S5\nS5\nS5")

        # switch s6
        elif datapath.id == 6:
            # h1 is connected to port 3.
            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.1.11", ipv4_dst="192.168.2.10")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)

            match = parser.OFPMatch(in_port=1, eth_type=0x0800,ipv4_src="192.168.2.11", ipv4_dst="192.168.1.11")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 2, match, actions)
            print("S6\nS6\nS6")
            
        else:
            print ("Hiii there noopp sws")

    
    '''
    # Sends an ARP response to the contacting host with the
    # real MAC address of a server.
    def arp_response(self, datapath, packet, etherFrame, ofp_parser, ofp, in_port):
        arpPacket = packet.get_protocol(arp.arp)
        dstIp = arpPacket.src_ip
        srcIp = arpPacket.dst_ip
        dstMac = etherFrame.src
        
        # If the ARP request isn't from one of the two servers,
        # choose the target/source MAC address from one of the servers;
        # else the target MAC address is set to the one corresponding
        # to the target host's IP.
        if dstIp != self.H1_ip and dstIp != self.H4_ip:
            if self.next_server == self.H1_ip:
                srcMac = self.H1_mac
                self.next_server = self.H4_ip
            else:
                srcMac = self.H4_mac
                self.next_server = self.H4_ip
        else:
            srcMac = self.ip_to_mac[srcIp] 

        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
        p = packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        

        # ARP action list
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_IN_PORT)]
        # ARP output message
        out = ofp_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=p.data
        )
        datapath.send_msg(out) # Send out ARP reply

    # Sets up the flow table in the switch to map IP addresses correctly.
    def add_flow(self, datapath, packet, ofp_parser, ofp, in_port):
        srcIp = packet.get_protocol(arp.arp).src_ip

        # Don't push forwarding rules if an ARP request is received from a server.
        if srcIp == self.H1_ip or srcIp == self.H4_ip:
            return

        # Generate flow from host to server.
        match = ofp_parser.OFPMatch(in_port=in_port,
                                    ipv4_dst=self.virtual_ip,
                                    eth_type=0x0800)
        actions = [ofp_parser.OFPActionSetField(ipv4_dst=self.current_server),
                   ofp_parser.OFPActionOutput(self.ip_to_port[self.current_server])]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            buffer_id=ofp.OFP_NO_BUFFER,
            match=match,
            instructions=inst)

        datapath.send_msg(mod)

        # Generate reverse flow from server to host.
        match = ofp_parser.OFPMatch(in_port=self.ip_to_port[self.current_server],
                                    ipv4_src=self.current_server,
                                    ipv4_dst=srcIp,
                                    eth_type=0x0800)
        actions = [ofp_parser.OFPActionSetField(ipv4_src=self.virtual_ip),
                   ofp_parser.OFPActionOutput(in_port)]
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        '''
        
    
    
    
    def flood_arp(self, datapath, dst_ip, in_port,src_mac, src_ip, msg):
        dpid = datapath.id
        self.logger.info('Enqueue packet...')
        self.queue.setdefault(dpid, {})
        self.queue[dpid][dst_ip]= [in_port, src_mac, src_ip, msg]
        
        for router_ip in self.L3_ip_to_mac[dpid]:
            if self.same_network(dst_ip, router_ip, '/24'):
                self.logger.info('FLOOD executed to find %s', dst_ip)
                self.send_arp(datapath, 1, src_ip, self.L3_ip_to_mac[dpid][router_ip], dst_ip, 'FF:FF:FF:FF:FF:FF', self.L3_mac_to_port[dpid][self.L3_ip_to_mac[dpid][router_ip]])
                return


    def handle_arp(self, msg, pkt, in_port, src_mac):
        datapath = msg.datapath
        dpid = datapath.id
        arp_pkt = pkt.get_protocol(arp.arp)
        src_ip = arp_pkt.src_ip
        dst_ip = arp_pkt.dst_ip

        if arp_pkt.opcode == 1: #ARP REQ
            self.update_mac_table(datapath, src_mac, in_port)
            self.update_ip_table(datapath, src_ip, src_mac)
            self.logger.info(self.mac_to_port[dpid])
            self.logger.info(self.ip_to_mac[dpid])

            if dst_ip in self.L3_ip_to_mac[dpid]:
                self.logger.info('ARP REPLY to %s in port %d', src_ip, in_port)
                # Could be good add a flow to avoid use the controller
                self.send_arp(datapath, 2, dst_ip, self.L3_ip_to_mac[dpid][dst_ip], src_ip, src_mac, in_port)
                return

        else:   # ARP REPLY
            if not self.queue[dpid]: #If queue is empty
                self.logger.info('WARNING! -> Queue is empty, possible attacker trying to inject flow!')
                return

            elif src_ip in self.queue[dpid]:                
                self.logger.info('Added to the table: %s -> %s -> %s -> %d', dpid, src_ip, src_mac, in_port)
                self.update_mac_table(datapath, src_mac, in_port)
                self.update_ip_table(datapath, src_ip, src_mac)
                for key, value in self.L3_mac_to_port[dpid].items():
                    self.logger.info("%s | %s",value,self.queue[dpid][src_ip][0]) 
                    if value == self.queue[dpid][src_ip][0]:
                        mac = key
                        self.logger.info('2NEW FLOW ADDED, PLS CHECK FLOW TABLE2')
                        self.inject_flow(datapath, src_ip, in_port, dst_ip, value, 500)
                        self.inject_flow(datapath, dst_ip, value, src_ip, in_port,500)
                        #self.logger.info('Forwarding ARP REPLY to %s -> %s in port %d', dst_ip, self.queue[dpid][src_ip][1], value)
                        self.logger.info('Forward pkt from %s(%s) to %s(%s) on port %d', src_ip, mac, dst_ip, self.queue[dpid][src_ip][1], self.queue[dpid][src_ip][0])
                        self.f_pkt(self.queue[dpid][src_ip][3], in_port)
                        #self.forward_pkt(msg, in_port, src_ip, dst_ip, self.queue[dpid][src_ip][0])
                        # Remove from queue...
                        self.queue[dpid].pop(src_ip)
                        return

            else:
                self.logger.info('WARNING! -> ARP REPLY not REQUESTED! Possible attacker trying to inject flow!')
                return

    def f_pkt(self, queue_msg, out_port):
        datapath = queue_msg.datapath
        data = queue_msg.data
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(queue_msg.data)
        pkt.serialize()
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        dst_ip = ip_pkt.dst

        self.logger.info(pkt)

        for key, value in self.L3_mac_to_port[dpid].items():
            if value == out_port:
                mac = key

        actions = [ parser.OFPActionSetField(eth_src = mac),
                    parser.OFPActionSetField(eth_dst = self.ip_to_mac[dpid][dst_ip]),
                    #parser.OFPActionSetField(ipv4_src=src_ip),
                    #parser.OFPActionSetField(ipv4_dst=dst_ip),
                    parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port= ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)

        #self.logger.info(out)
        datapath.send_msg(out)

    def forward_pkt(self, msg, in_port, src_ip, dst_ip, out_port):
        datapath = msg.datapath
        data = msg.data
        if data is None:
            # Do not sent when data is None
            return
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for key, value in self.L3_mac_to_port[dpid].items():
            if value == out_port:
                mac = key
        self.logger.info(self.ip_to_mac[dpid][dst_ip])
        actions = [ parser.OFPActionSetField(eth_src = mac),
                    parser.OFPActionSetField(eth_dst = self.ip_to_mac[dpid][dst_ip]),
                    #parser.OFPActionSetField(ipv4_src=src_ip),
                    #parser.OFPActionSetField(ipv4_dst=dst_ip),
                    parser.OFPActionOutput(out_port)]
        
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port= ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        #self.logger.info(out)
        datapath.send_msg(out)

    
    def inject_best_paths(self, topology):
        all_pairs_sp = dict(nx.all_pairs_shortest_path(self.topology))
        for src_dpid in all_pairs_sp:
            for dst_dpid in all_pairs_sp[src_dpid]:
                if src_dpid is not dst_dpid:
                    path = all_pairs_sp[src_dpid][dst_dpid]
                    for i in reversed(range(1,len(path))):
                        datapath = self.datapaths[path[i]]
                        parser = datapath.ofproto_parser
                        out_port = self.links[path[i]][path[i-1]]
                        in_port = self.links[path[i-1]][path[i]]
                        dst_ips = nx.get_node_attributes(self.topology,'attr_dict')
                        dst_ips = dst_ips[src_dpid]
                        for p in dst_ips:
                            ip = dst_ips[p]
                            ip = ip[0:ip.rfind('.')+1]+'0'
                            for key, value in self.L3_mac_to_port[src_dpid].items():
                                if value == out_port:
                                    dst_mac = key
                            for key, value in self.L3_mac_to_port[dst_dpid].items():
                                if value == in_port:
                                    src_mac = key
                            match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ipv4_dst= (ip, mask))
                            actions =[parser.OFPActionSetField(eth_src = src_mac), parser.OFPActionSetField(eth_dst = dst_mac), parser.OFPActionOutput(out_port)]
                            self.add_flow_best_path(datapath = datapath, priority= self.prio, match=match, actions=actions)
                            self.prio = self.prio+100                      
    
    def get_values(self, msg):
        dpid = msg[msg.find('dpid=')+len('dpid='):msg.rfind(', port_no')]
        port_no = msg[msg.find('port_no=')+len('port_no='):msg.rfind(', ')]

        if 'ports' in dpid:
            dpid = dpid[0:dpid.find(', ')]

        if 'LIVE' in msg:
            state = 'LIVE'
        elif 'DOWN' in msg:
            state = 'DOWN'
        else:
            state = 'INVALID'

        return [dpid, port_no, state]

    
    @handler.set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        msg = str(ev)
        #self.logger.info('Enter switch event -> %s',msg)
        dpid = self.get_values(msg)[0]
        dpid = int(dpid)
        self.logger.info('SWITCH ENTER EVENT -> dpid = %s', dpid)
        # Adds node with attrs topo graph
        self.topology.add_node(dpid, attr_dict=self.int_port_to_ip[dpid])
        self.logger.info(self.topology.nodes)
        self.inject_best_paths(self.topology)


    @handler.set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        msg = str(ev)
        #self.logger.info('Switch leave event -> %s',msg)
        dpid = self.get_values(msg)[0]
        dpid = int(dpid)
        self.logger.info('SWITCH LEAVE EVENT -> dpid = %d', dpid)
        # Remove nodes from graph
        self.topology.remove_node(dpid)
        self.logger.info(self.topology.nodes)
        self.inject_best_paths(self.topology)

    @handler.set_ev_cls(event.EventPortAdd)
    def port_add_handler(self, ev):
         msg = str(ev)
         #self.logger.info('Port add event -> %s',msg)
         dpid, port_no, state = self.get_values(msg)
         dpid = int(dpid)
         self.logger.info('PORT ADD EVENT -> dpid = %s, port_no = %s, state = %s', dpid, port_no, state)
         # Adds attr to node
         self.topology.nodes[dpid]['attr_dict'][port_no] = interface_port_to_ip[dpid][port_no]
         self.logger.info(nx.get_node_attributes(self.topology, 'attr_dict'))
         self.inject_best_paths(self.topology)

    @handler.set_ev_cls(event.EventPortDelete)
    def port_delete_handler(self, ev):
         msg = str(ev)
         dpid, port_no, state = self.get_values(msg)
         dpid = int(dpid)
         self.logger.info('PORT DELETE EVENT -> dpid = %s, port_no = %s, state = %s', dpid, port_no, state)
         # Deletes port from attr of the node
         self.topology.nodes[dpid]['attr_dict'].pop(port_no, None)
         self.logger.info(nx.get_node_attributes(self.topology, 'attr_dict'))
         self.inject_best_paths(self.topology)

    @handler.set_ev_cls(event.EventPortModify)
    def port_modify_handler(self, ev):
        msg = str(ev)
        #self.logger.info('Port modify event -> %s',msg)
        dpid, port, state = self.get_values(msg)
        dpid = int(dpid)
        port = int(port)
        #self.logger.info('PORT MODIFY EVENT -> dpid = %s (%s), port_no = %s (%s), state = %s', dpid, type(dpid), port_no, type(port_no), state)
        if state == 'DOWN' or state == 'INVALID':
            # Deletes port from attr of the node
            self.topology.nodes[dpid]['attr_dict'].pop(port, None)
        elif state == 'LIVE':
            # Adds port from attr of the node
            self.logger.info('GLOBAL = %s', interface_port_to_ip)
            self.logger.info('OBJECT = %s', self.int_port_to_ip)
            self.topology.nodes[dpid]['attr_dict'][port] = interface_port_to_ip[dpid][port]
        self.logger.info('TOPOLOGY UPDATED => %s', nx.get_node_attributes(self.topology, 'attr_dict'))
        self.inject_best_paths(self.topology)

    
    @handler.set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        msg = str(ev)
        #self.logger.info('Link add event -> %s',msg)
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        for link in links_list:
            self.links.setdefault(link.src.dpid, {})
            self.links[link.src.dpid][link.dst.dpid] = link.src.port_no
        #self.logger.info("switches %s", switches) 
        #self.logger.info("links %s", self.links)
        for dpid in self.links:
            list_key = list(self.links[dpid])
            for i in range(len(list_key)):
                if not self.topology.has_edge(dpid, list_key[i]):
                    self.logger.info('Edge added between %d - %d',dpid,list_key[i])
                    self.topology.add_edge(dpid, list_key[i])
        
        self.logger.info('LINKS = %s',self.links)
        self.logger.info(self.topology.nodes)
        self.logger.info(nx.get_node_attributes(self.topology, 'attr_dict'))
        self.inject_best_paths(self.topology)
        


        #self.logger.info('LINK ADD EVENT -> dpid = %s, port_no = %s, state = %s', dpid, port_no, state)

    # @handler.set_ev_cls(event.EventLinkDelete)
    # def link_del_handler(self, ev):
    #     self.logger.info('É DELETE!!!')
    #     msg = str(ev)
    #     #self.logger.info('Link del event -> %s',msg)
    #     switch_list = get_switch(self.topology_api_app, None)
    #     switches = [switch.dp.id for switch in switch_list]
    #     links_list = get_link(self.topology_api_app, None)
    #     for link in links_list:
    #         self.links.setdefault(link.src.dpid, {})
    #         self.links[link.src.dpid][link.dst.dpid] = link.src.port_no
    #     #self.logger.info("switches %s", switches) 
    #     #self.logger.info("links %s", self.links)
    #     for dpid in self.links:
    #         list_key = list(self.links[dpid])
    #         for i in range(len(list_key)):
    #             if self.topology.has_edge(dpid, list_key[i]):
    #                 self.logger.info('Removing edge between %d - %d',dpid,list_key[i])
    #                 self.topology.remove_edge(dpid, list_key[i])
        
    #     self.logger.info(self.topology.nodes)
    #     self.logger.info(self.topology.edges())
    #     #self.logger.info('LINK DEL EVENT -> dpid = %s, port_no = %s, state = %s', dpid, port_no, state)


    def remove_flows(self, datapath):
        """Removing all flow entries."""
        dpid = datapath.id
        parser = datapath.ofproto_parser
        empty_match = parser.OFPMatch()
        instructions = []
        for cookie in self.cookies[dpid]:
            flow_mod = self.remove_table_flows(datapath, empty_match, instructions, cookie)
            #self.logger.info("deleting all flow entries in table %s", table_id)
            datapath.send_msg(flow_mod)
    

    def remove_table_flows(self, datapath, match, instructions, cookie):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,
                                                    cookie=cookie,
                                                    cookie_mask=0xFFFFFFFFFFFFFFFF,
                                                    table_id=ofproto.OFPTT_ALL,
                                                    command=ofproto.OFPFC_DELETE,
                                                    out_port=ofproto.OFPP_ANY,
                                                    out_group=ofproto.OFPG_ANY,
                                                    match= match,
                                                    instructions = instructions)
        return flow_mod

 

    def inject_flow(self, datapath, src_ip, in_port, dst_ip, out_port, priority):
        src_ip_net = src_ip[0:src_ip.rfind('.')+1]+'0'
        dst_ip_net = dst_ip[0:dst_ip.rfind('.')+1]+'0'
        dpid = datapath.id
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port = in_port, eth_type = 0x0800, ipv4_src= (src_ip_net, mask), ipv4_dst= (dst_ip_net, mask)) 
        #self.logger.info(interface_ip_to_mac[dst_ip])
        for key, value in self.L3_mac_to_port[dpid].items():
            if value == out_port:
                mac = key
        actions = [parser.OFPActionSetField(eth_src = mac), parser.OFPActionSetField(eth_dst = self.ip_to_mac[dpid][dst_ip]), parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, priority, match, actions)

    def send_arp(self,datapath, opcode, srcIP, srcMAC, dstIP, dstMAC, out_port):
        e = ethernet.ethernet(dstMAC, srcMAC, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, opcode, srcMAC, srcIP, dstMAC, dstIP)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        
        #self.logger.info("ARP PKT OUT = %s", out)
        datapath.send_msg(out)
        return

    def send_icmp(self, datapath, opcode, echo, srcIP, srcMAC, dstIP, dstMAC, out_port):
        e = ethernet.ethernet(dstMAC, srcMAC, ether_types.ETH_TYPE_IP)
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=84,
                       identification=0, flags=0, offset=0, ttl=64,
                       proto=inet.IPPROTO_ICMP, csum=0,
                       src=srcIP, dst=dstIP)
        ping = icmp.icmp(opcode, data = echo)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(ping)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)

        datapath.send_msg(out)
        return

    def update_ip_table(self, datapath, ip, mac):
        dpid = datapath.id
        self.ip_to_mac[dpid][ip] = mac
        
    def update_mac_table(self, datapath, mac, port):
        dpid = datapath.id
        self.mac_to_port[dpid][mac] = port

    def same_network(self, src_ip, dst_ip, mask):
        a = ip_interface(src_ip+mask)
        b = ip_interface(dst_ip+mask)
        if b.network.overlaps(a.network):
            self.logger.info('%s and %s overlaps!', src_ip, dst_ip)
            return True
        else:
            return False
