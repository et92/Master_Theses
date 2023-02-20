from threading import Thread

from nis import match
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, udp
from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp,tcp
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

from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib

#from newtwork_graph import NetworkGraph

# To create a copy of the dict
import copy

# To work with IP easily
import ipaddress

# Define IPv4 addresses to each port of each switch
# {DPID:{PORT: IP}}
#interface_port_to_ip = {1: {1: '192.168.1.254', 2: '192.168.2.254', 3: '192.168.3.254'}}

interface_port_to_ip = {1: {1: '10.0.0.1', 2: '192.168.1.254', 3: '10.0.3.1', 4: '10.0.1.1', 5: '192.168.11.254'}, 
                        2: {1: '10.0.0.2', 2: '192.168.2.254', 3: '10.0.6.1', 4: '10.0.2.1', 5: '192.168.20.254'},
                        3: {1: '10.0.3.2', 2: '192.168.3.254', 3: '10.0.5.2'},
                        4: {1: '10.0.6.2', 2: '192.168.4.254', 3: '10.0.4.1'},
                        5: {1: '10.0.5.1', 2: '10.0.4.2', 3: '10.0.2.2', 4: '10.0.1.2', 5: '192.168.5.254'},
                        #6: {1: '192.168.11.253', 2: '192.168.11.221', 3: '192.168.11.231'},
                        #7: {1: '192.168.11.22'},
                        #8: {1: '192.168.11.23'},
                        #9: {1: '192.168.20.253'}
                        }

## {DPID:{(('ip_src', port_in, 'ip_dst', port_out, priorite)}
lista_sw_id ={
            1: (('192.168.1.10', 2, '192.168.4.10', 3, 1), ('192.168.1.10', 2, '192.168.4.10', 3, 1),
                ('192.168.1.10', 2, '192.168.5.10', 3, 1), ('192.168.5.10', 3, '192.168.1.10', 2, 1),
                ('192.168.1.10', 2, '192.168.3.10', 3, 1), ('192.168.3.10', 3, '192.168.1.10', 2, 1),
                ('192.168.1.10', 2, '192.168.2.10', 1, 1), ('192.168.2.10', 1, '192.168.1.10', 2, 1),
                #('192.168.11.1',5, '192.168.4.10', 1, 1), ('192.168.11.1', 5,'192.168.4.10', 1, 1),
                ('192.168.11.11',5, '192.168.4.10', 1, 2), ('192.168.4.10', 1,'192.168.11.11', 5, 2)),
                #('192.168.11.2', 5, '192.168.4.10', 1, 2), ('192.168.11.2', 5, '192.168.4.10', 1, 2)),

            2: (('192.168.1.10', 4, '192.168.4.10', 3, 4), ('192.168.4.10', 3, '192.168.1.10', 4, 4),
                #('192.168.11.1',1, '192.168.4.10', 3, 2), ('192.168.4.10', 3, '192.168.11.1',1, 2),
                ('192.168.11.11',1, '192.168.4.10', 3, 1), ('192.168.4.10', 3, '192.168.11.11',1, 1)),
                #('192.168.11.2', 1, '192.168.4.10', 3, 2), ('192.168.4.10', 3, '192.168.11.2', 1, 2)),

            3: (('192.168.1.10', 1, '192.168.4.10', 3, 1), ('192.168.4.10', 3, '192.168.1.10', 1, 1),
                ('192.168.1.10', 3, '192.168.3.10', 2, 1), ('192.168.3.10', 2, '192.168.1.10', 3, 1),
                ('192.168.1.10', 1, '192.168.2.10', 3, 1), ('192.168.2.10', 3, '192.168.1.10', 1, 1),
                ('192.168.1.10', 1, '192.168.5.10', 3, 1), ('192.168.5.10', 3, '192.168.1.10', 1, 1),
                ('192.168.11.11',1, '192.168.4.10', 3, 1), ('192.168.4.10', 3, '192.168.11.11',1, 1)),
    

            4: (('192.168.4.10', 2, '192.168.1.10', 1, 1), ('192.168.4.10', 2, '192.168.1.10', 1, 1),
                #('192.168.4.10', 2, '192.168.11.1',1, 2), ('192.168.11.1', 1, '192.168.4.10',2, 2),
                #('192.168.4.10', 2, '192.168.11.11',1, 2), ('192.168.11.11', 1, '192.168.4.10',2, 2),
                ('192.168.4.10', 2, '192.168.11.11',1, 1), ('192.168.11.11', 1, '192.168.4.10',2, 1)),
                #('192.168.4.10', 2, '192.168.11.2', 1, 2), ('192.168.4.10', 2, '192.168.11.2', 1, 2)),

            5: (('192.168.1.10', 1, '192.168.4.10', 2, 1), ('192.168.4.10', 2, '192.168.1.10', 1, 1),
                ('192.168.1.10', 4, '192.168.3.10', 1, 1), ('192.168.3.10', 1, '192.168.1.10', 4, 1),
                ('192.168.1.10', 1, '192.168.2.10', 3, 1), ('192.168.2.10', 3, '192.168.1.10', 1, 1)),

            
            #6: (('192.168.11.11', 2, '192.168.4.10', 1, 1), ('192.168.4.10', 1, '192.168.11.11', 2, 1))
                #('192.168.11.1', 2, '192.168.4.10', 1, 2), ('192.168.4.10', 1, '192.168.11.11',2, 2),
                #('192.168.11.2', 3, '192.168.4.10', 1, 2), ('192.168.4.10', 1, '192.168.11.2', 3, 2)),  

            }


#lista_sw = [(1, '192.168.1.10',2, '192.168.4.10', : (3,1)), (2, '192.168.1.10',4, '192.168.4.10', : (3,1))]
#varialvel_sistema  = dict(lista_sw)


mask = '255.255.255.0' #mask = /24 to all the networks in the topology...


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        
        '''
        self.stp = kwargs['stplib']
        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                  {'bridge': {'priority': 0x8000}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                  {'bridge': {'priority': 0x9000}},
                  dpid_lib.str_to_dpid('0000000000000003'):
                  {'bridge': {'priority': 0xa000}},
                  dpid_lib.str_to_dpid('0000000000000004'):
                  {'bridge': {'priority': 0xb000}},
                  dpid_lib.str_to_dpid('0000000000000005'):
                  {'bridge': {'priority': 0xc000}}}
        self.stp.set_config(config)'''

        self.mac_to_port = {}
        self.ip_to_mac = {}
        #self.hw_addr = {}
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
        #self.net=nx.DiGraph()
        #Rotas aprendidas para cada um dos routers

     

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links_list]
        print ("switches ", switches)
        print ("links ", links) 
    # # Handy function that lists all attributes in the given object
    # def ls(self,obj):
    #     print("\n".join([x for x in dir(obj) if x[0] != "_"]))   
   

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Obtain the datapath object and save it
        datapath = ev.msg.datapath
        self.datapaths.setdefault(datapath.id, datapath)
        self.logger.info('DATAPATHS -> %s', self.datapaths)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #self.dpids[datapath.id] = datapath
        
        self.logger.info(ev.msg.datapath.address)
        #address = ev.switch.dp.address
        #dpid = ev.switch.dp.id
        #self.logger.info(address)
        #self.logger.info(dpid)
        print("New switch is waiting configuration and located at ",ev.msg.datapath," and ID is ",ev.msg.datapath.id)
        
        # install table-miss flow entry
        #
        #  Instantiate and send the default MISS rule for the switch (EMPTY match, so it matches with any flow)
        # so that when no flow rule for a packet is found, the packet is sent to the controller.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IPV6)
        actions = []
        self.add_flow(datapath, 1, match, actions)
        self.send_port_desc_stats_request(datapath)


        sw = datapath.id
        if sw in lista_sw_id:
            route = lista_sw_id[sw]
            print("Chave (sw_id): ", sw)
            print("Valor (tuple de tuples): ", route)
            print(" ---> Numero de rotas: ", len(route))
            # imprime a lista
            for r in route:
                print("      TUPLE")
                print("      =====")
                print("      IP origem: ", r[0])
                print("      Porta entrada: ", r[1])
                print("      IP destino: ", r[2])
                print("      Porta saida: ", r[3])
                print("      Prioridade: ", r[4])

                match = parser.OFPMatch(in_port=r[1], eth_type=0x0800, ipv4_src=r[0], ipv4_dst=r[2])
                actions = [parser.OFPActionOutput(r[3])]
                self.add_flow(datapath, r[4], match, actions)
                self.send_port_desc_stats_request(datapath)
   
        

    # Simple function used to convert hexadecimal numbers to integer strings,
    # used by the application mainly for parsing datapath ids and port numbers
    def to_dec(hex):
        return int(hex, 16)
   

     #Adiciona um flow ao dispositivo
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.logger.info(f"\nSOU O ROUTER {datapath.id} E ESTOU A INSTALAR UM FLOW!!!!! {actions} {match}\n")

        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        else:
            inst = actions

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
        ofpparser = datapath.ofproto_parser

        req = ofpparser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        self.L3_mac_to_port.setdefault(dpid, {})
        self.L3_ip_to_mac.setdefault(dpid, {})

        if dpid not in interface_port_to_ip:
            self.logger.error("DPID %d not found in interface_port_to_ip dictionary", dpid)
            return

        for p in ev.msg.body:
            self.L3_mac_to_port[dpid][p.hw_addr] = p.port_no
            if p.port_no != 4294967294 and p.port_no in interface_port_to_ip[dpid]:
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
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore ipv6 (redundance)
            return
        
        
        dst_mac = eth.dst
        print("Destination Mac address is ",dst_mac)
        src_mac = eth.src
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
        

		
        self.logger.info("packet in %s %s %s %s", dpid, src_mac, dst_mac, in_port)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(msg, pkt, in_port, src_mac)
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            protocol = ip_pkt.proto

        # if ICMP Protocol
            if protocol == in_proto.IPPROTO_ICMP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=protocol)
            
            #  if TCP Protocol
            elif protocol == in_proto.IPPROTO_TCP:
                t = pkt.get_protocol(tcp.tcp)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)
            
            #  If UDP Protocol 
            elif protocol == in_proto.IPPROTO_UDP:
                u = pkt.get_protocol(udp.udp)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)            
    
        
        
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
                self.inject_flow(datapath, src_ip, in_port, dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]], 500)
                self.inject_flow(datapath,dst_ip, self.mac_to_port[dpid][self.ip_to_mac[dpid][dst_ip]], src_ip, in_port,500)
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
         
    
    # Simple function which, given a path with ports and a datapath, returns the port which that datapath has to use
    # as an output, to allow the packet to travel through the given path.
    

 
    def flood_arp(self, datapath, dst_ip, in_port,src_mac, src_ip, msg):
        dpid = datapath.id
        self.logger.info('Enqueue packet...')
        #self.queue[dpid][dst_ip]= [in_port, src_mac, src_ip, msg]
        self.queue.setdefault(dpid, {})
        self.queue[dpid][dst_ip] = [in_port, src_mac, src_ip, msg]

        
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
            if dpid not in self.queue:
                self.queue[dpid] = []
            #if not self.queue[dpid]: #If queue is empty
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
        #self.topology.add_node(dpid, attr_dict=self.int_port_to_ip[dpid])
        self.logger.info(self.topology.nodes)
        #self.inject_best_paths(self.topology)
 

    @handler.set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        msg = str(ev)
        #self.logger.info('Switch leave event -> %s',msg)
        dpid = self.get_values(msg)[0]
        dpid = int(dpid)
        self.logger.info('SWITCH LEAVE EVENT -> dpid = %d', dpid)
        # Remove nodes from graph
        if dpid in self.topology:
            self.topology.remove_node(dpid)
        else:
            print(f"Node {dpid} not found in the digraph.")
        self.logger.info(self.topology.nodes)
        self.inject_best_paths(self.topology)
       

        #self.inst_path_rule(self.topology)

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


    # def firewall(self):
    #     priority1=65000
    #     priority2=64000
    #     tcp_port = 5555

    #     # Allow TCP from HTTP server (H3) to H5 and vice-versa in specific port!
    #     match = self.datapaths[1].ofproto_parser.OFPMatch(in_port = 5, eth_type = ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_src= ('192.168.11.11', '255.255.255.0'), ipv4_dst = ('192.168.4.10', '255.255.255.0'), tcp_src = tcp_port)
    #     actions = [self.datapaths[1].ofproto_parser.OFPActionSetField(eth_src = '00:00:00:00:00:06'), self.datapaths[1].ofproto_parser.OFPActionSetField(eth_dst = '00:00:00:00:00:04'), self.datapaths[1].ofproto_parser.OFPActionOutput(1)]
    #     self.add_flow(self.datapaths[1], priority1, match, actions)
        
    #     match = self.datapaths[2].ofproto_parser.OFPMatch(in_port = 2, eth_type = ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_src= ('192.168.4.10', '255.255.255.0'), ipv4_dst = ('192.168.11.11', '255.255.255.0'))
    #     actions = [self.datapaths[2].ofproto_parser.OFPActionSetField(eth_src = '00:00:00:00:00:04'), self.datapaths[2].ofproto_parser.OFPActionSetField(eth_dst = '00:00:00:00:00:06'), self.datapaths[2].ofproto_parser.OFPActionOutput(1)]
    #     self.add_flow(self.datapaths[2], priority1, match, actions)


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

    '''
    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]
    """
    The change notification event (stplib.EventPortStateChange) of the port status is received and the debug log
    of the port status is output.
    """
    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])'''
    

    #####TESTANDO>>>>APAGAR DEPOIS 
