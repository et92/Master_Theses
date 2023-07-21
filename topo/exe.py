
import os

import sys
from hashlib import sha224
from mininet.node import RemoteController, OVSKernelSwitch, Controller
from mininet.node import OVSSwitch
from mn_wifi.cli import CLI
from mn_wifi.net import MininetWithControlWNet
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import call
from mn_wifi.associationControl import AssociationControl
from mn_wifi.link import wmediumd
from mn_wifi.link import adhoc
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import OVSKernelAP, UserAP, OVSBridgeAP, OVSAP
from mn_wifi.wmediumdConnector import interference
from time import sleep
#from mn_wifi.propagationModels import propagationModel
from mn_wifi.sumo.runner import sumo

import threading
import time

from mininet.node import Node, UserSwitch, OVSSwitch, CPULimitedHost
from mininet.moduledeps import pathCheck
from mininet.link import Intf
from mn_wifi.link import WirelessIntf, physicalMesh, ITSLink
from mininet.util import dumpNodeConnections


        
def Topology(args):
    os.system ('sudo ufw disable')
    os.system('service network-manager stop')
    info("Creating nodes...")
    
    net = Mininet_wifi( controller=RemoteController, link=wmediumd, wmediumd_mode=interference)
    #net = Mininet_wifi(switch=OVSKernelSwitch, waitConnected=True)
    
    info('Defining to remote controller on port 6655 (L3 switch)\n')
    c1 = net.addController(name='c1',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6653) #L3
    
    net.useExternalProgram(program=sumo, port=8813,
                        #config_file='/home/parallels/2023-07-19-16-26-39/osm.sumocfg',
                        #config_file='/home/parallels/mininet-wifi/mn_wifi/sumo/data/map.sumocfg',
                        config_file='/home/parallels/Documents/SumoTutorial/second_exemplo/second.sumocfg',
                        extra_params=["--start --delay 350"],
                        clients=1, exec_order=0)                
    
    

    info('Adding L3 switch\n')
    s1 = net.addSwitch('s1', failMode="standalone", dpid='1', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s2 = net.addSwitch('s2', failMode="standalone", dpid='2', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s3 = net.addSwitch('s3', failMode="standalone", dpid='3', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s4 = net.addSwitch('s4', failMode="standalone", dpid='4', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch
    s5 = net.addSwitch('s5', failMode="standalone", dpid='5', protocols ='OpenFlow13', cls=OVSKernelSwitch)  # L3 switch

    info('Adding L2 switches\n')
    s6 = net.addSwitch('s6', failMode="standalone", dpid='6', protocols ='OpenFlow13', cls=OVSKernelSwitch) # L2 Switch Net B (no ip)

    
    
    info('*** Add hosts/\n')
    h1 = net.addHost('h1', ip='192.168.1.10/24', mac = '00:00:00:00:00:01', defaultRoute='via 192.168.1.254')
    h2 = net.addHost('h2', ip='192.168.2.10/24', mac = '00:00:00:00:00:02', defaultRoute='via 192.168.2.254')
    h3 = net.addHost('h3', ip='192.168.3.10/24', mac = '00:00:00:00:00:03', defaultRoute='via 192.168.3.254')
    h4 = net.addHost('h4', ip='192.168.4.10/24', mac = '00:00:00:00:00:04', defaultRoute='via 192.168.4.254')
    h5 = net.addHost('h5', ip='192.168.5.10/24', mac = '00:00:00:00:00:05', defaultRoute='via 192.168.5.254')


    info('*** Add AcessPoints/\n')

    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mode='g', channel='1', dpid='7',
                            position='448.0,440.0,0', failMode="standalone", cls=UserAP, protocols ='OpenFlow13')

    ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', mode='g', channel='6', dpid='8',
                            position='647.0,446.0,0', failMode="standalone", cls=UserAP, protocols ='OpenFlow13')

    ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', mode='g', channel='11', dpid='9',
                            position='1190.0,450.0,0', failMode="standalone",  cls=UserAP, protocols ='OpenFlow13')

    #h7 = net.addHost('h7', ip='192.168.11.7/24', mac = '00:00:00:00:00:77', defaultRoute='via 192.168.11.22', position='33,60,0')

    info('*** stations/\n')
    car1=  net.addCar('car1',ip='192.168.11.11/24', defaultRoute='via 192.168.11.254', position='452.0,600.0,0', band=20)
    car2= net.addCar('car2', ip='192.168.11.12/24', defaultRoute='via 192.168.11.254',  position='626.0,600.0,0', band=20)
    car3= net.addCar('car3', ip='192.168.20.11/24', defaultRoute='via 192.168.20.254',  position='950.0,600.0,0',band=20)
    
    
    #net.setAssociationCtrl(ac='ssf')
    #net.auto_association()

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    
    """     if '-p' not in args:
                net.plotGraph(max_x=1550, max_y=1550)
    """

    if '-c' in args:
        car1.coord = ['448.0,440.0,0.0', '647.0,446.0,0.0', '1191.0,450.0,0.0']
        car3.coord = ['20.0,60.0,0.0', '30.0,60.0,0.0', '31.0,30.0,0.0']
        
    #net.setMobilityModel(time=0, model='GaussMarkov', max_x=160, max_y=160, seed=20)
    net.startMobility(time=0, mob_rep=1, reverse=True)

    p1, p2= dict(), dict()
    if '-c' not in args:
                p1 = {'position': '20.0,60.0,0.0'}
                p2 = {'position': '210.0,60.0,0.0'}
             

    net.mobility(car1, 'start', time=1, **p1)
    net.mobility(car2, 'start', time=1, **p1)
    #net.mobility(car, 'stop', time=222, **p2)
    net.mobility(car1, 'stop', time=222, **p1)
    net.mobility(car2, 'stop', time=222, **p1)
    net.stopMobility(time=230)
   
    net.stopMobility(time=3600)
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
    #net.addLink(car,ap1)
    # net.addLink(ap1,car2)
    # net.addLink(ap3,car3)
    
    
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

    # s6.setMAC('60:00:00:00:06:10', intf='s6-eth1')
    # s6.setMAC('60:00:00:00:06:20', intf='s6-eth2')
    # s6.setMAC('60:00:00:00:06:30', intf='s6-eth3')

    
    
    #ap1.setMAC('60:00:00:00:06:40',intf='ap1-eth1')
    
    #ap2.setMAC('60:00:00:00:06:50', intf='ap2-eth1')

    #for controller in net.controllers: controller.start()

    #c0.start()
    #c1.start()
    #info("*** Starting APs\n")

    info("*** Starting network\n")

    net.build()
    for controller in net.controllers:
        controller.start()
    info('*** Starting switches/APs\n')
    s1.start([c1])
    s2.start([c1])
    s3.start([c1])
    s4.start([c1])
    s5.start([c1])
    s6.start([])
    ap1.start([c1])
    ap2.start([c1])
    ap3.start([c1])

    # net.get('s1').start([c1])
    # net.get('s2').start([c1])
    # net.get('s3').start([c1])
    # net.get('s4').start([c1])
    # net.get('s5').start([c1])
    # net.get('s6').start([c1])
    # net.get('ap1').start([c1])
    # net.get('ap2').start([c1]) 
    # net.get('ap3').start([c1])

    #sleep(2)
    #cmd = 'iw dev {} connect {} {}'


    info('\nSetting up of IP addresses in the SW\n')
    s1.setIP('10.0.0.1/24', intf='s1-eth1')
    s1.setIP('192.168.1.254/24', intf='s1-eth2')
    s1.setIP('10.0.3.1/24', intf='s1-eth3')
    s1.setIP('10.0.1.1/24', intf='s1-eth4')
    s1.setIP('192.168.11.254/24', intf='s1-eth5')


    s2.setIP('10.0.0.2/24', intf='s2-eth1')
    s2.setIP('192.168.2.254/24', intf='s2-eth2')
    s2.setIP('10.0.6.1/24', intf='s2-eth3')
    s2.setIP('10.0.2.1/24', intf='s2-eth4')
    s2.setIP('192.168.20.254/24 ', intf='s2-eth5')


    s3.setIP('10.0.3.2/24', intf='s3-eth1')
    s3.setIP('192.168.3.254/24', intf='s3-eth2')
    s3.setIP('10.0.5.2/24', intf='s3-eth3')


    s4.setIP('10.0.6.2/24', intf='s4-eth1')
    s4.setIP('192.168.4.254/24', intf='s4-eth2')
    s4.setIP('10.0.5.2/24', intf='s4-eth3')


    s5.setIP('10.0.5.1/24', intf='s5-eth1')
    s5.setIP('10.0.4.2/24', intf='s5-eth2')
    s5.setIP('10.0.2.2/24', intf='s5-eth3')
    s5.setIP('10.0.1.2/24', intf='s5-eth4')
    s5.setIP('192.168.5.254/24', intf='s5-eth5')
    
    #s6.setIP('192.168.11.253/24', intf='s6-eth1')
    #s6.setIP('192.168.11.252/24', intf='s6-eth2')
    #s6.setIP('192.168.11.251/24', intf='s6-eth3')
    #s6.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward") 


    ap1.setIP('192.168.11.1/24', intf='ap1-wlan1')
    ap2.setIP('192.168.11.2/24', intf='ap2-wlan1')
    ap3.setIP('192.168.20.20/24', intf='ap3-wlan1')

    #ap1.setIP('192.168.11.3/24', intf='ap1-eth1')
    #ap2.setIP('192.168.11.4/24', intf='ap2-eth1')
    #ap3.setIP('192.168.20.253/24', intf='ap3-eth1')

    '''  
    car.cmd("sudo ovs-vsctl add-br car-wlan0")
    car.cmd("sudo ovs-vsctl set bridge car-wlan0 other-config:hwaddr=00:00:00:00:00:06")


    car2.cmd("sudo ovs-vsctl add-br car2-wlan0")
    car2.cmd("sudo ovs-vsctl set bridge car2-wlan0 other-config:hwaddr=00:00:00:00:00:12")


    car3.cmd("sudo ovs-vsctl add-br car3-wlan0")
    car3.cmd("sudo ovs-vsctl set bridge car3-wlan0 other-config:hwaddr=00:00:00:00:00:13")
     '''
    os.system('ip link set hwsim0 up')
    

    
    #os.system('ovs-ofctl -O OpenFlow13 add-flow ap1 in_port=car-wlan0,actions=output:1')
    #os.system('ovs-ofctl -O OpenFlow13 mod-flows s6 in_port=2,actions=output:1')

   
    # ap1.cmd('ifconfig ap1-wlan1 192.168.11.1 netmask 255.255.255.0')
    # ap1.cmd('service dnsmasq restart')
    # ap1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
   
    

    ap1.cmd('sysctl net.ipv4.ip_forward=1')
    ap1.cmd('route add -net 192.168.11.0/24 dev ap1-wlan1') #Aqui esta a fazer os AP funcionarem com as stations
    ap2.cmd('route add -net 192.168.11.0/24 dev ap1-wlan1') #Aqui esta a fazer os AP funcionarem com as stations
    ap3.cmd('route add -net 192.168.20.0/24 dev ap3-wlan1') #Aqui esta a fazer os AP funcionarem com as stations

    car1.cmd('ip route add default via %s' % s1.IP(intf='s1-eth5'))
    car3.cmd('ip route add default via %s' % s2.IP(intf='s2-eth5'))
    ap1.cmd('route add -net 192.168.1.0/24 dev ap1-wlan1') #nexthop



    h1.cmd('route add -net 192.168.11.0/24 via 192.168.1.254')
    
    car1.cmd('route add -net 192.168.1.0/24 via 192.168.11.254')
    


    CLI(net) # Start command line
    net.stop() # Stop Network

if __name__ == '__main__':
    setLogLevel('info')
    Topology(sys.argv)
