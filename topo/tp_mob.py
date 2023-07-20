
import os
import sys
import threading
import time
from hashlib import sha224

from mininet.node import RemoteController, OVSKernelSwitch, Controller
from mininet.node import OVSSwitch
from mn_wifi.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import call
from mn_wifi.associationControl import AssociationControl
from mn_wifi.link import wmediumd
from mn_wifi.link import adhoc
from mn_wifi.net import Mininet_wifi
from mn_wifi.net import MininetWithControlWNet
from mn_wifi.node import OVSKernelAP, UserAP, OVSBridgeAP, OVSAP
from mn_wifi.wmediumdConnector import interference

#from mn_wifi.propagationModels import propagationModel
#from mininet.util import (errRun, errFail, Python3, getincrementaldecoder,
#                          quietRun, BaseString)
#from mininet.node import Node, UserSwitch, OVSSwitch, CPULimitedHost
#from mininet.moduledeps import pathCheck
#from mininet.link import Intf
#from mn_wifi.link import WirelessIntf, physicalMesh, ITSLink

def Topology(args):
    # operating system tunning 
    info("Operating System actions...")
    os.system ('sudo ufw disable')
    #os.system('sudo systemctl stop NetworkManager')
    info("Creating nodes...")
    #info('Net A -> 192.168.1.0/24\nNet B -> 192.168.2.0/24\nNet C -> 192.168.3.0/24\n')

    #net = Mininet_wifi( controller=RemoteController, switch=OVSSwitch,link=wmediumd, accessPoint=OVSBridgeAP)
    net = Mininet_wifi( topo=None, build=False, ipBase='192.168.0.0/24',controller=RemoteController, link=wmediumd)
    #net = Mininet_wifi(switch=OVSKernelSwitch, waitConnected=True)

    info('Defining to remote controller on port 6633 (L3MobilityManager)\n')
    c0 = net.addController(name='c0',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6633) 

    info('Adding L3 switch\n')
    s1 = net.addSwitch('s1', failMode="standalone", dpid='1', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s2 = net.addSwitch('s2', failMode="standalone", dpid='2', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s3 = net.addSwitch('s3', failMode="standalone", dpid='3', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s4 = net.addSwitch('s4', failMode="standalone", dpid='4', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s5 = net.addSwitch('s5', failMode="standalone", dpid='5', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    #s1 = net.addSwitch('s1', cls=OVSSwitch, failMode="standalone", dpid='0000000000000001', protocols ='OpenFlow13')  # L3 switch
    #s2 = net.addSwitch('s2', cls=OVSSwitch, failMode="standalone", dpid='0000000000000002', protocols ='OpenFlow13')  # L3 switch
    #s3 = net.addSwitch('s3', cls=OVSSwitch, failMode="standalone", dpid='0000000000000003', protocols ='OpenFlow13')  # L3 switch
    #s4 = net.addSwitch('s4', cls=OVSSwitch, failMode="standalone", dpid='0000000000000004', protocols ='OpenFlow13')  # L3 switch
    #s5 = net.addSwitch('s5', cls=OVSSwitch, failMode="standalone", dpid='0000000000000005', protocols ='OpenFlow13')  # L3 switch

    info('Adding L2 switches\n')
    s6 = net.addSwitch('s6', failMode="standalone", dpid='6', protocols ='OpenFlow13', cls=OVSKernelSwitch) # L2 Switch Net B (no ip)
    #s6 = net.addSwitch('s6', cls=OVSSwitch, failMode="standalone", dpid='0000000000000006', protocols ='OpenFlow13') # L2 Switch Net B (no ip)
    
    info('*** Add hosts/\n')
    h1 = net.addHost('h1', ip='192.168.1.10/24', mac = '00:00:00:00:00:01', defaultRoute='via 192.168.1.254')
    h2 = net.addHost('h2', ip='192.168.2.10/24', mac = '00:00:00:00:00:02', defaultRoute='via 192.168.2.254')
    h3 = net.addHost('h3', ip='192.168.3.10/24', mac = '00:00:00:00:00:03', defaultRoute='via 192.168.3.254')
    h4 = net.addHost('h4', ip='192.168.4.10/24', mac = '00:00:00:00:00:04', defaultRoute='via 192.168.4.254')
    h5 = net.addHost('h5', ip='192.168.5.10/24', mac = '00:00:00:00:00:05', defaultRoute='via 192.168.5.254')

    h7 = net.addHost('h7', ip='192.168.11.7/24', mac = '00:00:00:00:00:77', defaultRoute='via 192.168.11.254')
    h8 = net.addHost('h8', ip='192.168.20.8/24', mac = '00:00:00:00:00:88', defaultRoute='via 192.168.20.254')

    info('*** stations/\n')
    mov=  net.addStation('mov',  ip='192.168.11.11/24',  position='452.0,600.0,0', mac = '00:00:00:00:00:07',wlans=1, defaultRoute='via 192.168.11.254')
    mov2= net.addStation('mov2', ip='192.168.11.12/24',  position='626.0,600.0,0', mac = '00:00:00:00:00:08',wlans=1, defaultRoute='via 192.168.11.254')
    mov3= net.addStation('mov3', ip='192.168.20.11/24',  position='1200.0,600.0,0',mac = '00:00:00:00:00:09',wlans=1, defaultRoute='via 192.168.20.254')
    #s7 = net.addSwitch('s2', cls=OVSSwitch, dpid='0000000000000007') # L2 Switch Net C (no ip)
    
    info('*** Add AcessPoints/\n')

    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mode='g', channel='1', dpid='7', wlans=1, mac = '00:00:00:00:00:11',
                            position='448.0,440.0,0', failMode="standalone", cls=OVSKernelAP, protocols ='OpenFlow13')

    ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', mode='g', channel='6', dpid='8', wlans=1, mac = '00:00:00:00:00:12',
                            position='647.0,446.0,0', failMode="standalone", cls=OVSKernelAP, protocols ='OpenFlow13')

    ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', mode='g', channel='11',dpid='9', wlans=1, mac = '00:00:00:00:00:13',
                            position='1190.0,450.0,0', failMode="standalone", cls=OVSKernelAP, protocols ='OpenFlow13')
    #ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mac ='00:00:00:00:00:07', mode='g', channel='1',
    #                            failMode="standalone", position='31,60,0', range= 30, cls=OVSBridgeAP)

    #ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', mac ='00:00:00:00:00:08', mode='g', channel='1',
    #                            failMode="standalone", position='36,60,0', range= 30, cls=OVSBridgeAP)

    #ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', mac ='00:00:00:00:00:09', mode='g', channel='6',
    #                            failMode="standalone", position='47,60,0',  range= 30, cls=OVSBridgeAP)
    #ap4 = net.addAccessPoint('ap4', ssid='ssid-ap4', ip='192.168.4.114/24', mac ='00:00:00:00:14:24', mode='g', channel='1',
    #                             failMode="standalone", position='100,50,0', defaultRoute='via 192.168.4.1', range=45)

    #ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', mode='g', channel='6', dpid='8', wlans=1, mac = '00:00:00:00:00:12',
    #                        position='647.0,446.0,0', failMode="standalone", cls=OVSKernelAP, protocols ='OpenFlow13')
    #
    #ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', mode='g', channel='11',dpid='9', wlans=1, mac = '00:00:00:00:00:13',
    #                        position='1190.0,450.0,0', failMode="standalone", cls=OVSKernelAP, protocols ='OpenFlow13')


    #net.setAssociationCtrl(ac='ssf')
    #net.auto_association()

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    
    if '-p' not in args:
                net.plotGraph(max_x=250, max_y=250)


    """ if '-c' in args:
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
    """
    net.auto_association()
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
    #net.addLink(ap1, h7)
    #net.addLink(ap3, h8)
   
    
    #net.addLink(mov,ap1,0,0)

    #net.addLink(ap3,ap1)
    #net.addLink(ap1,h1)
    # net.addLink(ap1,mov2)
    
    #net.addLink(ap3,mov3,1,0)

    # net.addLink(s6,ap1,2,1)
    # net.addLink(s6,ap2,3,1)
    # net.addLink(s2,ap3,5,1)

    
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

    s6.setMAC('60:00:00:00:06:10', intf='s6-eth1')
    s6.setMAC('60:00:00:00:06:20', intf='s6-eth2')
    s6.setMAC('60:00:00:00:06:30', intf='s6-eth3')

    #ap1.setMAC('60:00:00:00:06:40', intf='ap1-eth1')
    #ap1.setMAC('60:00:00:00:07:77', 'ap1-eth2')
    #ap2.setMAC('60:00:00:00:06:50', intf='ap2-eth1')

    #for controller in net.controllers: controller.start()

    #c0.start()
    #info("*** Starting APs\n")

    info("*** Starting network\n")

    net.build()
    for controller in net.controllers:
        controller.start()
    info('*** Starting switches/APs\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s5').start([c0])
    net.get('s6').start([c0])
    net.get('ap1').start([c0])
    net.get('ap2').start([c0]) 
    net.get('ap3').start([c0])

    #time.sleep(2)
    #cmd = 'iw dev {} connect {} {}'

    info('\nSetting up of IP addresses in the SW\n')
    s1.setIP('10.0.0.1/24', intf='s1-eth1')
    s1.setIP('192.168.1.254/24', intf='s1-eth2')
    s1.setIP('10.0.3.1/24', intf='s1-eth3')
    s1.setIP('10.0.1.1/24', intf='s1-eth4')
    s1.setIP('192.168.11.254/24', intf='s1-eth5')
    #s1.cmd("ifconfig s1-eth1 0")
    #s1.cmd("ifconfig s1-eth2 0")
    #s1.cmd("ifconfig s1-eth3 0")
    #s1.cmd("ifconfig s1-eth4 0")
    #s1.cmd("ifconfig s1-eth5 0")
    #mov.cmd("ifconfig mov-wlan 0")
    #s1.cmd("ifconfig s1-eth6 0")
    #s1.cmd("ip addr add 10.0.0.1/24 brd + dev s1-eth1")
    #s1.cmd("ip addr add 192.168.1.254/24 brd + dev s1-eth2")
    #s1.cmd("ip addr add 10.0.3.1/24 brd + dev s1-eth3")
    #s1.cmd("ip addr add 10.0.1.1/24 brd + dev s1-eth4")
    #s1.cmd("ip addr add 192.168.11.254/24 brd + dev s1-eth5")   
    
    s1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    #s2.cmd("ifconfig s2-eth1 0")
    #s2.cmd("ifconfig s2-eth2 0")
    #s2.cmd("ifconfig s2-eth3 0")
    #s2.cmd("ifconfig s2-eth4 0")
    #s2.cmd("ifconfig s2-eth5 0")
    #ap3.cmd("ifconfig ap3-eth1 0")
    #s2.cmd("ip addr add 10.0.0.2/24 brd + dev s2-eth1")
    #s2.cmd("ip addr add 192.168.2.254/24 brd + dev s2-eth2")
    #s2.cmd("ip addr add 10.0.6.1/24 brd + dev s2-eth3")
    #s2.cmd("ip addr add 10.0.2.1/24 brd + dev s2-eth4")
    #s2.cmd("ip addr add 192.168.20.254/24 brd + dev s2-eth5")
    #ap3.cmd("ip addr add 192.168.20.253/24 brd + dev ap3-eth1")

    s2.setIP('10.0.0.2/24', intf='s2-eth1')
    s2.setIP('192.168.2.254/24', intf='s2-eth2')
    s2.setIP('10.0.6.1/24', intf='s2-eth3')
    s2.setIP('10.0.2.1/24', intf='s2-eth4')
    s2.setIP('192.168.20.254/24 ', intf='s2-eth5')
    s2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    

    #s3.cmd("ifconfig s3-eth1 0")
    #s3.cmd("ifconfig s3-eth2 0")
    #s3.cmd("ifconfig s3-eth3 0")
    #s3.cmd("ip addr add 10.0.3.2/24 brd + dev s3-eth1")
    #s3.cmd("ip addr add 192.168.3.254/24 brd + dev s3-eth2")
    #s3.cmd("ip addr add 10.0.5.2/24 brd + dev s3-eth3")

    s3.setIP('10.0.3.2/24', intf='s3-eth1')
    s3.setIP('192.168.3.254/24', intf='s3-eth2')
    s3.setIP('10.0.5.2/24', intf='s3-eth3')
    s3.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    #s4.cmd("ifconfig s4-eth1 0")
    #s4.cmd("ifconfig s4-eth2 0")
    #s4.cmd("ifconfig s4-eth3 0")
    #s4.cmd("ifconfig s4-eth4 0")
    #s4.cmd("ifconfig s4-eth5 0")
    #s4.cmd("ip addr add 10.0.6.2/24 brd + dev s4-eth1")
    #s4.cmd("ip addr add 192.168.4.254/24 brd + dev s4-eth2")
    #s4.cmd("ip addr add 10.0.4.1/24 brd + dev s4-eth3")

    s4.setIP('10.0.6.2/24', intf='s4-eth1')
    s4.setIP('192.168.4.254/24', intf='s4-eth2')
    s4.setIP('10.0.5.2/24', intf='s4-eth3')
    s4.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    #s5.cmd("ifconfig s5-eth1 0")
    #s5.cmd("ifconfig s5-eth2 0")
    #s5.cmd("ifconfig s5-eth3 0")
    #s5.cmd("ifconfig s5-eth4 0")
    #s5.cmd("ifconfig s5-eth5 0")
    #s5.cmd("ip addr add 10.0.5.1/24 brd + dev s5-eth1")
    #s5.cmd("ip addr add 10.0.4.2/24 brd + dev s5-eth2")
    #s5.cmd("ip addr add 10.0.2.2/24 brd + dev s5-eth3")
    #s5.cmd("ip addr add 10.0.1.2/24 brd + dev s5-eth4")
    #s5.cmd("ip addr add 192.168.5.254/24 brd + dev s5-eth5")


    s5.setIP('10.0.5.1/24', intf='s5-eth1')
    s5.setIP('10.0.4.2/24', intf='s5-eth2')
    s5.setIP('10.0.2.2/24', intf='s5-eth3')
    s5.setIP('10.0.1.2/24', intf='s5-eth4')
    s5.setIP('192.168.5.254/24', intf='s5-eth5')
    s5.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    #s6.setIP('192.168.11.253/24', intf='s6-eth1')
    #s6.setIP('192.168.11.252/24', intf='s6-eth2')
    #s6.setIP('192.168.11.251/24', intf='s6-eth3')
    #s6.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward") 


    ap1.setIP('192.168.11.1/24', intf='ap1-wlan1')
    ap2.setIP('192.168.11.2/24', intf='ap2-wlan1')
    ap3.setIP('192.168.20.20/24',intf='ap3-wlan1')


    #ap1.setIP('192.168.11.3/24', intf='ap1-eth1')
    #ap2.setIP('192.168.11.4/24', intf='ap2-eth1')
    #ap3.setIP('192.168.20.253/24', intf='ap3-eth1')

    os.system('ip link set hwsim0 up')
    s6.cmdPrint('ovs-vsctl show')

    info('*** Starting switches\n')
    s1.cmd('ifconfig s1 192.168.1.254 netmask 255.255.255.0 up')
    s2.cmd('ifconfig s2 192.168.2.254 netmask 255.255.255.0 up')
    s3.cmd('ifconfig s3 192.168.3.254 netmask 255.255.255.0 up')
    s4.cmd('ifconfig s4 192.168.4.254 netmask 255.255.255.0 up')
    s5.cmd('ifconfig s5 192.168.5.254 netmask 255.255.255.0 up')
    s6.cmd('ifconfig s6 0.0.0.0 up')
    time.sleep(2)


    ap1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    #ap1.cmd('route add -net 192.168.11.0/24 dev s1-eth5') #segunda rota para o AP funcionar
    ap1.cmd('route add -net 192.168.11.0/24 dev ap1-wlan1') #Aqui esta a fazer os AP funcionarem com as stations
    ap2.cmd('route add -net 192.168.11.0/24 dev ap1-wlan1') #Aqui esta a fazer os AP funcionarem com as stations
    ap3.cmd('route add -net 192.168.20.0/24 dev ap3-wlan1') #Aqui esta a fazer os AP funcionarem com as station

    mov.setDefaultRoute('dev mov-wlan0 via s1-eth5')
    mov3.setDefaultRoute('dev mov3-wlan0 via s2-eth5')

    mov.cmd('ip route add default via %s' % ap1.IP(intf='ap1-wlan1'))#Rota que faz o mov passar do S1 para fora
    mov3.cmd('ip route add default via %s' % ap3.IP(intf='ap3-wlan1'))#Rota que faz o mov3 passar do S2 para  fora
    ap1.cmd('route add -net 192.168.11.11/24 dev s1-eth5') #nexthop
    ap1.cmd('route add -net 192.168.11.12/24 dev s1-eth5')
    ap3.cmd('route add -net 192.168.20.11/24 dev s2-eth5')

    # h1.cmd('route add -net 192.168.11.0/24 via 192.168.1.254')
    # mov.cmd('route add -net 192.168.1.0/24 via 192.168.11.254')

    # h7.cmd('route add -net 192.168.20.0/24 via 192.168.11.1')
    # h8.cmd('route add -net 192.168.11.0/24 via 192.168.20.20')
    
    #mov.cmd('ip route add 192.168.1.10/24 via ap1-wlan1')
    #h1.cmd('ip route add 192.168.11.0/24 via 192.168.1.254')

    #ap1.cmd('ovs-ofctl add-flow ap1 priority=100,dl_type=0x800, nw_dst=192.168.11.11, action=output:1')
    #s6.setIP('192.168.11.253/24', intf='s6-eth1')
    #s6.setIP('192.168.11.221/24', intf='s6-eth2')
    #s6.setIP('192.168.11.231/24', intf='s6-eth3')



    
    # Set IP addresses for the switch interface inside the namespace
   
    
    # ap1.cmd("ip link add name {name}-eth0 type veth peer name {name}-eth1".format(name=name))
    # ap1.cmd("ip link set {name}-eth1 netns {name}".format(name=name))
    # ap1.cmd("ip netns exec {name} ip link set lo up".format(name=name))
    # ap1.cmd("ip netns exec {name} ip link set {name}-eth1 up".format(name=name))
    # ap1.cmd("ip netns exec {name} ip addr add 10.0.0.1/24 dev {name}-eth1".format(name=name)
    
    """ 
    ap1.cmd("ip link add veth0 type veth peer name veth1")
    ap1.cmd("ip link set veth0 netns ap1-wlan1")
    #ap1.cmd("ip netns exec ap1-wlan1 ip addr add 192.168.11.1/24 dev veth0")
    ap1.cmd("ip link set veth1 s1-eth5")
    ap1.cmd("ip addr add 192.168.11.254/24 dev veth1")
    ap1.cmd("ip addr add 192.168.11.1/24 dev ap1-wlan1")
    #ap1.setIP('192.168.11.1/24', intf='ap1-wlan1')
    ap1.setIP('192.168.11.2/24', intf='ap1-eth1') """

    #ap1.cmd("sudo ovs-vsctl add-port s1-eth5 veth1")
    #ap1.cmd("sudo ip link set veth0 up")
    #ap1.cmd("sudo ip link set veth1 up")
    #ap1.cmd("sysctl -w net.ipv4.conf.veth0.forwarding=1")


    #s1.cmd("ifconfig s1-eth1 0")
    #s1.cmd("ifconfig s1-eth2 0")
    #s1.cmd("ifconfig s1-eth3 0")
    #s1.cmd("ifconfig s1-eth4 0")
    #s1.cmd("ifconfig s1-eth5 0")
    #mov.cmd("ifconfig mov-wlan 0")
    #s1.cmd("ifconfig s1-eth6 0")
    #s1.cmd("ip addr add 10.0.0.1/24 brd + dev s1-eth1")
    #s1.cmd("ip addr add 192.168.1.254/24 brd + dev s1-eth2")
    #s1.cmd("ip addr add 10.0.3.1/24 brd + dev s1-eth3")
    #s1.cmd("ip addr add 10.0.1.1/24 brd + dev s1-eth4")
    #s1.cmd("ip addr add 192.168.11.254/24 brd + dev s1-eth5")   
    
    #s1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # s2.cmd("ifconfig s2-eth1 0")
    # s2.cmd("ifconfig s2-eth2 0")
    # s2.cmd("ifconfig s2-eth3 0")
    # s2.cmd("ifconfig s2-eth4 0")
    # s2.cmd("ifconfig s2-eth5 0")
    
    # s2.cmd("ip addr add 10.0.0.2/24 brd + dev s2-eth1")
    # s2.cmd("ip addr add 192.168.2.254/24 brd + dev s2-eth2")
    # s2.cmd("ip addr add 10.0.6.1/24 brd + dev s2-eth3")
    # s2.cmd("ip addr add 10.0.2.1/24 brd + dev s2-eth4")
    # s2.cmd("ip addr add 192.168.20.254/24 brd + dev s2-eth5")
    # #ap3.cmd("ip addr add 192.168.20.253/24 brd + dev ap3-eth1")
    # s2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # s3.cmd("ifconfig s3-eth1 0")
    # s3.cmd("ifconfig s3-eth2 0")
    # s3.cmd("ifconfig s3-eth3 0")
    # s3.cmd("ip addr add 10.0.3.2/24 brd + dev s3-eth1")
    # s3.cmd("ip addr add 192.168.3.254/24 brd + dev s3-eth2")
    # s3.cmd("ip addr add 10.0.5.2/24 brd + dev s3-eth3")
    # s3.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # s4.cmd("ifconfig s4-eth1 0")
    # s4.cmd("ifconfig s4-eth2 0")
    # s4.cmd("ifconfig s4-eth3 0")
    
    # s4.cmd("ip addr add 10.0.6.2/24 brd + dev s4-eth1")
    # s4.cmd("ip addr add 192.168.4.254/24 brd + dev s4-eth2")
    # s4.cmd("ip addr add 10.0.4.1/24 brd + dev s4-eth3")
    # s4.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # s5.cmd("ifconfig s5-eth1 0")
    # s5.cmd("ifconfig s5-eth2 0")
    # s5.cmd("ifconfig s5-eth3 0")
    # s5.cmd("ifconfig s5-eth4 0")
    # s5.cmd("ifconfig s5-eth5 0")
    # s5.cmd("ip addr add 10.0.5.1/24 brd + dev s5-eth1")
    # s5.cmd("ip addr add 10.0.4.2/24 brd + dev s5-eth2")
    # s5.cmd("ip addr add 10.0.2.2/24 brd + dev s5-eth3")
    # s5.cmd("ip addr add 10.0.1.2/24 brd + dev s5-eth4")
    # s5.cmd("ip addr add 192.168.5.254/24 brd + dev s5-eth5")

    # ap1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # ap2.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    # ap3.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

   
    
    #mov.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    #ap1.cmd('route add  mov gw 192.168.11.254')
    #s1.cmd('route add -net 192.168.11.11/24 gw 192.168.1.254')
    #ap1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    #ap2.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    #ap3.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

    

    # ap1.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    # ap2.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    #ap1.setIP('192.168.11.1/24', intf='ap1-wlan1')
    #ap1.setIP('192.168.11.22/24', intf='ap1-eth1')

    #ap2.setIP('192.168.11.2/24', intf='ap2-wlan1')
    #ap2.setIP('192.168.11.23/24', intf='ap2-eth1')

    #ap1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    #ap2.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

    #mov.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    #mov.cmd('ip route add default 192.168.11.11/24 via mov-wlan0')
    

    # mov.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    # mov.cmd('route add -net 192.168.1.0/24 gw 192.168.1.254')
    # mov.cmd('route add -net 192.168.2.0/24 gw 192.168.2.254')
    # mov.cmd('route add -net 192.168.4.0/24 gw 192.168.4.254')

    # mov2.cmd('route add -net 192.168.11.0/24 gw 192.168.11.254')
    # mov2.cmd('route add -net 192.168.1.0/24 gw 192.168.1.254')
    # mov2.cmd('route add -net 192.168.2.0/24 gw 192.168.2.254')
    # mov2.cmd('route add -net 192.168.4.0/24 gw 192.168.4.254')

    #s5.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    """ 
    s6.cmd("ifconfig s6-eth1 0")
    s6.cmd("ifconfig s6-eth2 0")
    s6.cmd("ifconfig s6-eth3 0")
    s6.cmd("ip addr add 192.168.11.253/24 brd + dev s6-eth1")
    s6.cmd("ip addr add 192.168.11.221/24 brd + dev s6-eth2")
    s6.cmd("ip addr add 192.168.11.231/24 brd + dev s6-eth3")
    s6.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")  """
    
    #s6.cmd("ifconfig s6-eth1 0")
    #s6.cmd("ifconfig s6-eth2 0")
    #s6.cmd("ifconfig s6-eth3 0")
    #s6.cmd("ip addr add 192.168.11.253/24 brd + dev s6-eth1")
    #s6.cmd("ip addr add 192.168.11.221/24 brd + dev s6-eth2")
    #s6.cmd("ip addr add 192.168.11.231/24 brd + dev s6-eth3")
    #s6.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

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
    args = sys.argv
    Topology(args)

