
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
from ryu.lib.packet import ipv4
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

#from newtwork_graph import NetworkGraph

# To create a copy of the dict
import copy

# To work with IP easily
import ipaddress


interface_port_to_ip = {1: {1: '10.0.0.1', 2: '192.168.1.254', 3: '10.0.3.1', 4: '10.0.1.1', 5: '192.168.11.254'}, 
                        2: {1: '10.0.0.2', 2: '192.168.2.254', 3: '10.0.6.1', 4: '10.0.2.1', 5: '192.168.20.254'},
                        3: {1: '10.0.3.2', 2: '192.168.3.254', 3: '10.0.5.2'},
                        4: {1: '10.0.6.2', 2: '192.168.4.254', 3: '10.0.4.1'},
                        5: {1: '10.0.5.1', 2: '10.0.4.2', 3: '10.0.2.2', 4: '10.0.1.2', 5: '192.168.5.254'}
                        #6: {1: '192.168.10.253', 2: '192.168.11.253', 3: '192.168.11.254'}
                        }


lista_sw_id ={
            1: (('192.168.1.10', 2, '192.168.4.10', 3, 1), ('192.168.1.10', 2, '192.168.4.10', 3, 1),
                ('192.168.1.10', 2, '192.168.5.10', 3, 1), ('192.168.5.10', 3, '192.168.1.10', 2, 1),
                ('192.168.1.10', 2, '192.168.3.10', 3, 1), ('192.168.3.10', 3, '192.168.1.10', 2, 1),
                ('192.168.1.10', 2, '192.168.2.10', 1, 1), ('192.168.2.10', 1, '192.168.1.10', 2, 1),
                ('192.168.11.11',5, '192.168.4.10', 1, 1), ('192.168.11.11', 5,'192.168.4.10', 1, 1),
                ('192.168.11.11',5, '192.168.4.10', 1, 2), ('192.168.4.10', 1,'192.168.11.11', 5, 2),
                ('192.168.11.254', 5, '192.168.11.11', 5, 2), ('192.168.11.254', 5, '192.168.11.11', 5, 2),
                ('192.168.11.254', 5, '192.168.4.10', 1, 2), ('192.168.11.254', 5, '192.168.4.10', 1, 2)),

            2: (('192.168.1.10', 4, '192.168.4.10', 3, 1), ('192.168.4.10', 3, '192.168.1.10', 4, 1),
                ('192.168.11.11',1, '192.168.4.10', 3, 2), ('192.168.4.10', 3, '192.168.11.11',1, 2),
                ('192.168.11.254', 1, '192.168.4.10', 3, 2), ('192.168.4.10', 3, '192.168.11.254', 1, 2)),

            3: (('192.168.1.10', 1, '192.168.4.10', 3, 1), ('192.168.4.10', 3, '192.168.1.10', 1, 1),
                ('192.168.1.10', 3, '192.168.3.10', 2, 1), ('192.168.3.10', 2, '192.168.1.10', 3, 1),
                ('192.168.1.10', 1, '192.168.2.10', 3, 1), ('192.168.2.10', 3, '192.168.1.10', 1, 1),
                ('192.168.1.10', 1, '192.168.5.10', 3, 1), ('192.168.5.10', 3, '192.168.1.10', 1, 1),
                ('192.168.11.11',1, '192.168.4.10', 3, 1), ('192.168.4.10', 3, '192.168.11.11',1, 1)),
    

            4: (('192.168.4.10', 2, '192.168.1.10', 1, 1), ('192.168.4.10', 2, '192.168.1.10', 1, 1),
                ('192.168.4.10', 2, '192.168.11.11',1, 2), ('192.168.4.10', 2, '192.168.11.11',1, 2),
                ('192.168.4.10', 2, '192.168.11.254', 1, 2), ('192.168.4.254', 2, '192.168.11.254', 1, 2)),

            5: (('192.168.1.10', 1, '192.168.4.10', 2, 1), ('192.168.4.10', 2, '192.168.1.10', 1, 1),
                ('192.168.1.10', 4, '192.168.3.10', 1, 1), ('192.168.3.10', 1, '192.168.1.10', 4, 1),
                ('192.168.1.10', 1, '192.168.2.10', 3, 1), ('192.168.2.10', 3, '192.168.1.10', 1, 1))
            }


#lista_sw = [(1, '192.168.1.10',2, '192.168.4.10', : (3,1)), (2, '192.168.1.10',4, '192.168.4.10', : (3,1))]
#varialvel_sistema  = dict(lista_sw)


mask = '255.255.255.0' #mask = /24 to all the networks in the topology...


class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.L3_mac_to_port = {}
        self.L3_ip_to_mac = {}
        self.queue = {}
        self.datapaths = {}
        self.topology_api_app = self
        self.links = {}
        self.best_paths = {}
        self.int_port_to_ip = copy.deepcopy(interface_port_to_ip)
        self.topology = nx.DiGraph()
        self.cookies = {}
        self.cookie_value = 1
        self.prio = 1000

    def ls(self,obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))   

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        self.datapaths.setdefault(datapath.id, datapath)
        self.logger.info('DATAPATHS -> %s', self.datapaths)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info(ev.msg.datapath.address)
    
        print("New switch is waiting configuration and located at ",ev.msg.datapath," and ID is ",ev.msg.datapath.id)
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

    def to_dec(hex):
        return int(hex, 16)
   

    # Function used wrap the FlowMod rule with the ADD command, and then send it to the given datapath.
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
        self.inject_best_paths(datapath)


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
        print("\nEthernet Packet is ",eth)
        print("Source Mac address is ",src_mac)
        print("Destination Mac address is ",dst_mac)
        print("Switch port number is ",msg.match['in_port'])

		
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
            print("Handler", dpid)
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

    
    def inject_best_paths(self, topology,ip_adress,):
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
        self.inject_best_paths(self.topology)

    @handler.set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        msg = str(ev)
        #self.logger.info('Switch leave event -> %s',msg)
        dpid = self.get_values(msg)[0]
        dpid = int(dpid)
        self.logger.info('SWITCH LEAVE EVENT -> dpid = %d', dpid)
        # Remove nodes from graph
        
        self.logger.info(self.topology.nodes)
        self.topology.remove_node(dpid)
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

    @handler.set_ev_cls(event.EventLinkDelete)
    def link_del_handler(self, ev):
        self.logger.info('É DELETE!!!')
        msg = str(ev)
        #self.logger.info('Link del event -> %s',msg)
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
                if self.topology.has_edge(dpid, list_key[i]):
                    self.logger.info('Removing edge between %d - %d',dpid,list_key[i])
                    self.topology.remove_edge(dpid, list_key[i])
        
        self.logger.info(self.topology.nodes)
        self.logger.info(self.topology.edges())
        #self.logger.info('LINK DEL EVENT -> dpid = %s, port_no = %s, state = %s', dpid, port_no, state)


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





New switch is waiting configuration and located at  <ryu.controller.controller.Datapath object at 0xffffa86b0e80>  and ID is  1152921504606846978
L3Switch: Exception occurred during handler processing. Backtrace from offending handler [switch_features_handler] servicing event [EventOFPSwitchFeatures] follows.
Traceback (most recent call last):
  File "/home/et92/.local/lib/python3.8/site-packages/ryu/base/app_manager.py", line 290, in _event_loop
    handler(ev)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 141, in switch_features_handler
    self.add_flow(datapath, 0, match, actions)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 192, in add_flow
    self.inject_best_paths(datapath)
TypeError: inject_best_paths() missing 1 required positional argument: 'ip_adress'
L3Switch: Exception occurred during handler processing. Backtrace from offending handler [get_topology_data] servicing event [EventSwitchEnter] follows.
Traceback (most recent call last):
  File "/home/et92/.local/lib/python3.8/site-packages/ryu/base/app_manager.py", line 290, in _event_loop
    handler(ev)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 769, in get_topology_data
    self.net.add_nodes_from(switches)
AttributeError: 'L3Switch' object has no attribute 'net'
SWITCH ENTER EVENT -> dpid = 1152921504606846978
[]
L3Switch: Exception occurred during handler processing. Backtrace from offending handler [switch_enter_handler] servicing event [EventSwitchEnter] follows.
Traceback (most recent call last):
  File "/home/et92/.local/lib/python3.8/site-packages/ryu/base/app_manager.py", line 290, in _event_loop
    handler(ev)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 548, in switch_enter_handler
    self.inject_best_paths(self.topology)
TypeError: inject_best_paths() missing 1 required positional argument: 'ip_adress'
DATAPATHS -> {1: <ryu.controller.controller.Datapath object at 0xffffa875ee80>, 2: <ryu.controller.controller.Datapath object at 0xffffa86f8370>, 3: <ryu.controller.controller.Datapath object at 0xffffa86f8070>, 4: <ryu.controller.controller.Datapath object at 0xffffa86f87c0>, 5: <ryu.controller.controller.Datapath object at 0xffffa870cee0>, 1152921504606846977: <ryu.controller.controller.Datapath object at 0xffffa871db20>, 1152921504606846978: <ryu.controller.controller.Datapath object at 0xffffa86b0e80>, 1152921504606846979: <ryu.controller.controller.Datapath object at 0xffffa86b4550>}
('127.0.0.1', 36202)
New switch is waiting configuration and located at  <ryu.controller.controller.Datapath object at 0xffffa86b4550>  and ID is  1152921504606846979
L3Switch: Exception occurred during handler processing. Backtrace from offending handler [switch_features_handler] servicing event [EventOFPSwitchFeatures] follows.
Traceback (most recent call last):
  File "/home/et92/.local/lib/python3.8/site-packages/ryu/base/app_manager.py", line 290, in _event_loop
    handler(ev)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 141, in switch_features_handler
    self.add_flow(datapath, 0, match, actions)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 192, in add_flow
    self.inject_best_paths(datapath)
TypeError: inject_best_paths() missing 1 required positional argument: 'ip_adress'
L3Switch: Exception occurred during handler processing. Backtrace from offending handler [get_topology_data] servicing event [EventSwitchEnter] follows.
Traceback (most recent call last):
  File "/home/et92/.local/lib/python3.8/site-packages/ryu/base/app_manager.py", line 290, in _event_loop
    handler(ev)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 769, in get_topology_data
    self.net.add_nodes_from(switches)
AttributeError: 'L3Switch' object has no attribute 'net'
SWITCH ENTER EVENT -> dpid = 1152921504606846979
[]
L3Switch: Exception occurred during handler processing. Backtrace from offending handler [switch_enter_handler] servicing event [EventSwitchEnter] follows.
Traceback (most recent call last):
  File "/home/et92/.local/lib/python3.8/site-packages/ryu/base/app_manager.py", line 290, in _event_loop
    handler(ev)
  File "/home/et92/Documents/Master_Theses/sw/L3ext.py", line 548, in switch_enter_handler
    self.inject_best_paths(self.topology)





import sys
from hashlib import sha224
from mininet.node import RemoteController, OVSKernelSwitch,  Host,  OVSKernelSwitch
from mininet.node import OVSSwitch
from mn_wifi.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import call
from mn_wifi.associationControl import AssociationControl
from mn_wifi.link import wmediumd
from mn_wifi.link import adhoc
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import OVSKernelAP, UserAP
from mn_wifi.wmediumdConnector import interference
from time import sleep
#from mn_wifi.propagationModels import propagationModel

import threading
import time


def Topology(args):
    info("Creating nodes...")
    #info('Net A -> 192.168.1.0/24\nNet B -> 192.168.2.0/24\nNet C -> 192.168.3.0/24\n')

    net = Mininet_wifi( controller=RemoteController, switch=OVSSwitch,link=wmediumd, accessPoint=OVSKernelAP,)
    #net = Mininet_wifi(switch=OVSKernelSwitch, waitConnected=True)

    info('Defining remote controller on port 6633 (L2 switches)\n')
    c0 = net.addController(name='c0',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6633) #L2
    
    info('Defining to remote controller on port 6655 (L3 switch)\n')
    c1 = net.addController(name='c1',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6655) #L3

    info('Adding L3 switch\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, dpid='0000000000000001', protocols ='OpenFlow13')  # L3 switch
    s2 = net.addSwitch('s2', cls=OVSSwitch, dpid='0000000000000002', protocols ='OpenFlow13')  # L3 switch
    s3 = net.addSwitch('s3', cls=OVSSwitch, dpid='0000000000000003', protocols ='OpenFlow13')  # L3 switch
    s4 = net.addSwitch('s4', cls=OVSSwitch, dpid='0000000000000004', protocols ='OpenFlow13')  # L3 switch
    s5 = net.addSwitch('s5', cls=OVSSwitch, dpid='0000000000000005', protocols ='OpenFlow13')  # L3 switch

    info('Adding L2 switches\n')
    s6 = net.addSwitch('s6', cls=OVSSwitch, dpid='0000000000000006', protocols ='OpenFlow13') # L2 Switch Net B (no ip)
    
    info('*** Add hosts/\n')
    h1 = net.addHost('h1', ip='192.168.1.10/24', mac = '00:00:00:00:00:01', defaultRoute='via 192.168.1.254')
    h2 = net.addHost('h2', ip='192.168.2.10/24', mac = '00:00:00:00:00:02', defaultRoute='via 192.168.2.254')
    h3 = net.addHost('h3', ip='192.168.3.10/24', mac = '00:00:00:00:00:03', defaultRoute='via 192.168.3.254')
    h4 = net.addHost('h4', ip='192.168.4.10/24', mac = '00:00:00:00:00:04', defaultRoute='via 192.168.4.254')
    h5 = net.addHost('h5', ip='192.168.5.10/24', mac = '00:00:00:00:00:05', defaultRoute='via 192.168.5.254')

    h7 = net.addHost('h7', ip='192.168.11.7/24', mac = '00:00:00:00:00:77', defaultRoute='via 192.168.11.254', position='33,60,0', )

    info('*** stations/\n')
    mov= net.addStation ('mov', ip='192.168.11.11/24', mac ='00:00:00:00:00:06', defaultRoute='via 192.168.11.254', position='30,60,0')
    mov2= net.addStation ('mov2', ip='192.168.11.12/24', mac ='00:00:00:00:00:12', defaultRoute='via 192.168.11.254', position='33,60,0')
    #s7 = net.addSwitch('s2', cls=OVSSwitch, dpid='0000000000000007') # L2 Switch Net C (no ip)
    info('*** Add AcessPoints/\n')

    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mac ='00:00:00:00:00:07', mode='g', channel='1',
                                position='20,60,0', range= 30)

    ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', mac ='00:00:00:00:00:08', mode='g', channel='1',
                                 failMode="standalone", position='100,60,0', range= 30)

    ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', mac ='00:00:00:00:00:09', mode='g', channel='6',
                                 failMode="standalone", position='175,60,0',  range= 30)
    #ap4 = net.addAccessPoint('ap4', ssid='ssid-ap4', ip='192.168.4.114/24', mac ='00:00:00:00:14:24', mode='g', channel='1',
                                 #failMode="standalone", position='100,50,0', defaultRoute='via 192.168.4.1', range=45)
    

   
    #net.setAssociationCtrl(ac='ssf')
    #net.auto_association()

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

 
    if '-p' not in args:
                net.plotGraph(max_x=250, max_y=250)


    if '-c' in args:
        mov.coord = ['20.0,60.0,0.0', '30.0,60.0,0.0', '31.0,30.0,0.0']
        mov2.coord = ['20.0,60.0,0.0', '30.0,60.0,0.0', '31.0,30.0,0.0']
        
    #net.setMobilityModel(time=0, model='GaussMarkov', max_x=160, max_y=160, seed=20)
    net.startMobility(time=0, mob_rep=1, reverse=True)

    p1, p2= dict(), dict()
    if '-c' not in args:
                p1 = {'position': '20.0,60.0,0.0'}
                p2 = {'position': '210.0,60.0,0.0'}
             

    net.mobility(mov, 'start', time=1, **p1)
    net.mobility(mov2, 'start', time=1, **p1)
    #net.mobility(mov, 'stop', time=222, **p2)
    net.mobility(mov, 'stop', time=222, **p1)
    net.mobility(mov2, 'stop', time=222, **p1)
    net.stopMobility(time=230)


    info('*** Associating and Creating Add links\n')

    net.addLink(s1, s2,1,1)
    net.addLink(s1, s3,3,1)
    net.addLink(s1, s5,4,4)
    net.addLink(s1, s6,5,1)
    net.addLink(s1, h1,2,1)
    net.addLink(s2, h2,2,1)
    net.addLink(s2, s4,3,1)
    net.addLink(s2, s5,4,3)
    net.addLink(s3, h3,2,1)
    net.addLink(s3, s5,3,1)
    net.addLink(s4, h4,2,1)
    net.addLink(s4, s5,3,2)
    net.addLink(s5, h5,5,1)

    net.addLink(s6,ap1,2,1)
    net.addLink(s6,ap2,3,1)
    net.addLink(s2,ap3,5,1)

    #net.addLink(ap1, h7,2,1)
    

    info('Setting MAC addresses to switches')
    s1.setMAC('10:00:00:00:01:10', 's1-eth1')
    s1.setMAC('10:00:00:00:01:20', 's1-eth2')
    s1.setMAC('10:00:00:00:01:30', 's1-eth3')
    s1.setMAC('10:00:00:00:01:40', 's1-eth4')
    s1.setMAC('10:00:00:00:01:50', 's1-eth5')
    


    s2.setMAC('20:00:00:00:02:10', 's2-eth1')
    s2.setMAC('20:00:00:00:02:20', 's2-eth2')
    s2.setMAC('20:00:00:00:02:30', 's2-eth3')
    s2.setMAC('20:00:00:00:02:40', 's2-eth4')
    s2.setMAC('20:00:00:00:02:50', 's2-eth5')
    #ap3.setMAC('20:00:00:00:02:60', 'ap3-eth1')


    s3.setMAC('30:00:00:00:03:10', 's3-eth1')
    s3.setMAC('30:00:00:00:03:20', 's3-eth2')
    s3.setMAC('30:00:00:00:03:30', 's3-eth3')

    s4.setMAC('40:00:00:00:04:10', 's4-eth1')
    s4.setMAC('40:00:00:00:04:20', 's4-eth2')
    s4.setMAC('40:00:00:00:04:30', 's4-eth3')
    #s4.setMAC('40:00:00:00:04:40', 's4-eth4')
    #s4.setMAC('40:00:00:00:04:50', 's4-eth5')

    s5.setMAC('50:00:00:00:05:10', 's5-eth1')
    s5.setMAC('50:00:00:00:05:20', 's5-eth2')
    s5.setMAC('50:00:00:00:05:30', 's5-eth3')
    s5.setMAC('50:00:00:00:05:40', 's5-eth4')
    s5.setMAC('50:00:00:00:05:50', 's5-eth5')

    s6.setMAC('60:00:00:00:06:10', 's6-eth1')
    s6.setMAC('60:00:00:00:06:20', 's6-eth2')
    s6.setMAC('60:00:00:00:06:30', 's6-eth3')
    ap1.setMAC('60:00:00:00:06:40', 'ap1-eth1')
    #ap1.setMAC('60:00:00:00:07:77', 'ap1-eth2')
    ap2.setMAC('60:00:00:00:06:50', 'ap2-eth1')

    #for controller in net.controllers: controller.start()

    #c0.start()
    #c1.start()
    #info("*** Starting APs\n")

    info("*** Starting network\n")

    net.build()
    info('*** Starting switches/APs\n')
    s1.start([c1])
    s2.start([c1])
    s3.start([c1])
    s4.start([c1])
    s5.start([c1])
    s6.start([c1])
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])

    sleep(2)
    cmd = 'iw dev {} connect {} {}'
    


    info('\nSetting up of IP addresses in the SW\n')
    s1.cmd("ifconfig s1-eth1 0")
    s1.cmd("ifconfig s1-eth2 0")
    s1.cmd("ifconfig s1-eth3 0")
    s1.cmd("ifconfig s1-eth4 0")
    s1.cmd("ifconfig s1-eth5 0")
    #mov.cmd("ifconfig mov-wlan 0")
    #s1.cmd("ifconfig s1-eth6 0")
    s1.cmd("ip addr add 10.0.0.1/24 brd + dev s1-eth1")
    s1.cmd("ip addr add 192.168.1.254/24 brd + dev s1-eth2")
    s1.cmd("ip addr add 10.0.3.1/24 brd + dev s1-eth3")
    s1.cmd("ip addr add 10.0.1.1/24 brd + dev s1-eth4")
    s1.cmd("ip addr add 192.168.11.254/24 brd + dev s1-eth5")   
    
    s1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    s2.cmd("ifconfig s2-eth1 0")
    s2.cmd("ifconfig s2-eth2 0")
    s2.cmd("ifconfig s2-eth3 0")
    s2.cmd("ifconfig s2-eth4 0")
    s2.cmd("ifconfig s2-eth5 0")
    #ap3.cmd("ifconfig ap3-eth1 0")
    s2.cmd("ip addr add 10.0.0.2/24 brd + dev s2-eth1")
    s2.cmd("ip addr add 192.168.2.254/24 brd + dev s2-eth2")
    s2.cmd("ip addr add 10.0.6.1/24 brd + dev s2-eth3")
    s2.cmd("ip addr add 10.0.2.1/24 brd + dev s2-eth4")
    s2.cmd("ip addr add 192.168.20.254/24 brd + dev s2-eth5")
    #ap3.cmd("ip addr add 192.168.20.253/24 brd + dev ap3-eth1")

    s2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    

    s3.cmd("ifconfig s3-eth1 0")
    s3.cmd("ifconfig s3-eth2 0")
    s3.cmd("ifconfig s3-eth3 0")
    s3.cmd("ip addr add 10.0.3.2/24 brd + dev s3-eth1")
    s3.cmd("ip addr add 192.168.3.254/24 brd + dev s3-eth2")
    s3.cmd("ip addr add 10.0.5.2/24 brd + dev s3-eth3")

    s3.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    s4.cmd("ifconfig s4-eth1 0")
    s4.cmd("ifconfig s4-eth2 0")
    s4.cmd("ifconfig s4-eth3 0")
    #s4.cmd("ifconfig s4-eth4 0")
    #s4.cmd("ifconfig s4-eth5 0")
    s4.cmd("ip addr add 10.0.6.2/24 brd + dev s4-eth1")
    s4.cmd("ip addr add 192.168.4.254/24 brd + dev s4-eth2")
    s4.cmd("ip addr add 10.0.4.1/24 brd + dev s4-eth3")
    s4.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    #s4.cmd("ip addr add 192.168.4.140/24 brd + dev s4-eth4")
    #s4.cmd("ip addr add 192.168.4.240/24 brd + dev s4-eth5")

    s5.cmd("ifconfig s5-eth1 0")
    s5.cmd("ifconfig s5-eth2 0")
    s5.cmd("ifconfig s5-eth3 0")
    s5.cmd("ifconfig s5-eth4 0")
    s5.cmd("ifconfig s5-eth5 0")
    s5.cmd("ip addr add 10.0.5.1/24 brd + dev s5-eth1")
    s5.cmd("ip addr add 10.0.4.2/24 brd + dev s5-eth2")
    s5.cmd("ip addr add 10.0.2.2/24 brd + dev s5-eth3")
    s5.cmd("ip addr add 10.0.1.2/24 brd + dev s5-eth4")
    s5.cmd("ip addr add 192.168.5.254/24 brd + dev s5-eth5")

    # ap1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # ap2.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # ap3.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

    
    #ap1.setIP('192.168.11.1/24', intf='ap1-wlan1')
    #ap1.setIP('192.168.11.8/24', intf='ap1-eth2')
    #ap1.setIP('192.168.11.10/24', intf='ap1-eth1')
   # ap2.setIP('192.168.11.2/24', intf='ap2-wlan1')
    #ap2.setIP('192.168.11.20/24', intf='ap2-eth1')

    # ap1.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    # ap2.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    mov.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    mov.cmd('route add -net 192.168.1.0/24 gw 192.168.1.254')
    mov.cmd('route add -net 192.168.2.0/24 gw 192.168.2.254')
    mov.cmd('route add -net 192.168.4.0/24 gw 192.168.4.254')

    mov2.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    mov2.cmd('route add -net 192.168.1.0/24 gw 192.168.1.254')
    mov2.cmd('route add -net 192.168.2.0/24 gw 192.168.2.254')
    mov2.cmd('route add -net 192.168.4.0/24 gw 192.168.4.254')

    #ap1.setIP('192.168.11.1/24')
    #mov.cmd('ifconfig mov-wlan0 192.168.11.11/24')
    #mov.cmd('ip route add default 192.168.11.254/8 via mov-wlan0')

    #ap2.setIP('192.168.11.2/24')
    #ap2.setIP('192.168.11.4/24', intf='ap2-eth1')
    
    #s5.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    s6.cmd("ifconfig s6-eth1 0")
    s6.cmd("ifconfig s6-eth2 0")
    s6.cmd("ifconfig s6-eth3 0")
    s6.cmd("ip addr add 192.168.11.253/24 brd + dev s6-eth1")
    s6.cmd("ip addr add 192.168.11.22/24 brd + dev s6-eth2")
    s6.cmd("ip addr add 192.168.11.23/24 brd + dev s6-eth3")
    ap1.cmd("ifconfig ap1-eth1 0")
    ap2.cmd("ifconfig ap2-eth1 0")
    
    ap1.cmd("ip addr add 192.168.11.1/24 brd + dev ap1-eth1")
    ap2.cmd("ip addr add 192.168.11.2/24 brd + dev ap2-eth1")
    s6.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    '''
    mov.cmd('iw dev %s interface add mon0 type monitor' % mov.params['wlan'][0])
    mov.cmd('ifconfig mon0 up')
    mov.cmd('wireshark -i mon0 &')'''



    #mov.cmd('iw dev %s connect %s %s' % (mov.params['wlan'][0], ap1.params['ssid'][1], ap1.params['mac'][1]))
    #sta2.cmd('iw dev %s connect %s %s' % (sta2.params['wlan'][0], ap1.params['ssid'][2], ap1.params['mac'][2]))

    CLI(net) # Start command line
    net.stop() # Stop Network

if __name__ == '__main__':
    setLogLevel('info')
    Topology(sys.argv)

    
        # 

        #ap1.cmd('ovs-ofctl add-flow "ap1" in_port=1,actions=normal')
        #ap1.cmd('ovs-ofctl add-flow "ap1" in_port=2,actions=normal')
        #ap2.cmd('ovs-ofctl add-flow "ap2" in_port=1,actions=normal')
        #ap2.cmd('ovs-ofctl add-flow "ap2" in_port=2,actions=normal')
             