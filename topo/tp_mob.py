import sys
from hashlib import sha224
from mn_wifi.net import Mininet_wifi
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from subprocess import call
from mn_wifi.cli import CLI
from mn_wifi.associationControl import AssociationControl

import threading
import time


def Topology(args):
    info("Creating nodes...")
    #info('Net A -> 192.168.1.0/24\nNet B -> 192.168.2.0/24\nNet C -> 192.168.3.0/24\n')

    net = Mininet_wifi( controller=RemoteController, switch=OVSSwitch)
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
    s1 = net.addSwitch('s1', cls=OVSSwitch, dpid='0000000000000001')  # L3 switch
    s2 = net.addSwitch('s2', cls=OVSSwitch, dpid='0000000000000002')  # L3 switch
    s3 = net.addSwitch('s3', cls=OVSSwitch, dpid='0000000000000003')  # L3 switch
    s4 = net.addSwitch('s4', cls=OVSSwitch, dpid='0000000000000004')  # L3 switch
    s5 = net.addSwitch('s5', cls=OVSSwitch, dpid='0000000000000005')  # L3 switch

    info('Adding L2 switches\n')
    s6 = net.addSwitch('s6', cls=OVSSwitch, dpid='0000000000000006') # L2 Switch Net B (no ip)
    #s7 = net.addSwitch('s2', cls=OVSSwitch, dpid='0000000000000007') # L2 Switch Net C (no ip)
    

    info('*** Add hosts/\n')
    h1 = net.addHost('h1', ip='192.168.1.10/24', mac = '00:00:00:00:00:01', defaultRoute='via 192.168.1.254')
    h2 = net.addHost('h2', ip='192.168.2.10/24', mac = '00:00:00:00:00:02', defaultRoute='via 192.168.2.254')
    h3 = net.addHost('h3', ip='192.168.3.10/24', mac = '00:00:00:00:00:03', defaultRoute='via 192.168.3.254')
    h4 = net.addHost('h4', ip='192.168.4.10/24', mac = '00:00:00:00:00:04', defaultRoute='via 192.168.4.254')
    h5 = net.addHost('h5', ip='192.168.5.10/24', mac = '00:00:00:00:00:05', defaultRoute='via 192.168.5.254')

    info('*** stations/\n')
    sta6= net.addStation ('sta6',ip ='192.168.1.11/24', mac ='00:00:00:00:00:06', defaultRoute='via 192.168.1.254')


    info('*** Add AcessPoints/\n')

    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', ip='192.168.11.1/24', mac ='00:00:00:00:00:07', mode='g', channel='1',
                                 failMode="standalone", position='20,60,0', defaultRoute='via 192.168.10.253', range= 35)
    ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', ip='192.168.11.2/24', mac ='00:00:00:00:00:08', mode='g', channel='1',
                                 failMode="standalone", position='100,60,0', defaultRoute='via 192.168.10.253', range= 35)
    ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', ip='192.168.20.253/24', mac ='00:00:00:00:00:09', mode='g', channel='1',
                                 failMode="standalone", position='175,60,0', defaultRoute='via 192.168.20.254', range= 35)
    #ap4 = net.addAccessPoint('ap4', ssid='ssid-ap4', ip='192.168.4.114/24', mac ='00:00:00:00:14:24', mode='g', channel='1',
                                 #failMode="standalone", position='100,50,0', defaultRoute='via 192.168.4.1', range=45)


    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

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
    net.addLink(s2,ap3,5,2)


    if '-p' not in args:
                net.plotGraph(max_x=250, max_y=250)
        
    if '-c' in args:
        sta6.coord = ['10.0,210.0,0.0', '120.0,210.0,0.0', '120.0,210.0,0.0']
        
    net.startMobility(time=0, mob_rep=1, reverse=False)

    p1, p2= dict(), dict()
    if '-c' not in args:
                p1 = {'position': '10.0,60.0,0.0'}
                p2 = {'position': '210.0,60.0,0.0'}
             

    net.mobility(sta6, 'start', time=1, **p1)
    net.mobility(sta6, 'stop', time=222, **p2)
    net.stopMobility(time=230)


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
    ap3.setMAC('20:00:00:00:02:60', 'ap3-eth2')


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
    s6.start([c0])
    ap1.start([c1])
    ap2.start([c1])
    ap3.start([c1])
        

    info('\nSetting up of IP addresses in the SW\n')
    s1.cmd("ifconfig s1-eth1 0")
    s1.cmd("ifconfig s1-eth2 0")
    s1.cmd("ifconfig s1-eth3 0")
    s1.cmd("ifconfig s1-eth4 0")
    s1.cmd("ifconfig s1-eth5 0")
    #s1.cmd("ifconfig s1-eth6 0")
    s1.cmd("ip addr add 10.0.0.1/24 brd + dev s1-eth1")
    s1.cmd("ip addr add 192.168.1.254/24 brd + dev s1-eth2")
    s1.cmd("ip addr add 10.0.3.1/24 brd + dev s1-eth3")
    s1.cmd("ip addr add 10.0.1.1/24 brd + dev s1-eth4")
    s1.cmd("ip addr add 192.168.10.254/24 brd + dev s1-eth5")   
    #s1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    s2.cmd("ifconfig s2-eth1 0")
    s2.cmd("ifconfig s2-eth2 0")
    s2.cmd("ifconfig s2-eth3 0")
    s2.cmd("ifconfig s2-eth4 0")
    s2.cmd("ifconfig s2-eth5 0")
    ap3.cmd("ifconfig ap3-eth2 0")
    s2.cmd("ip addr add 10.0.0.2/24 brd + dev s2-eth1")
    s2.cmd("ip addr add 192.168.2.254/24 brd + dev s2-eth2")
    s2.cmd("ip addr add 10.0.6.1/24 brd + dev s2-eth3")
    s2.cmd("ip addr add 10.0.2.1/24 brd + dev s2-eth4")
    s2.cmd("ip addr add 192.168.20.254/24 brd + dev s2-eth5")
    ap3.cmd("ip addr add 192.168.20.253/24 brd + dev ap3-eth2")
    #s2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    

    s3.cmd("ifconfig s3-eth1 0")
    s3.cmd("ifconfig s3-eth2 0")
    s3.cmd("ifconfig s3-eth3 0")
    s3.cmd("ip addr add 10.0.3.2/24 brd + dev s3-eth1")
    s3.cmd("ip addr add 192.168.3.254/24 brd + dev s3-eth2")
    s3.cmd("ip addr add 10.0.5.2/24 brd + dev s3-eth3")
    #s3.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    s4.cmd("ifconfig s4-eth1 0")
    s4.cmd("ifconfig s4-eth2 0")
    s4.cmd("ifconfig s4-eth3 0")
    #s4.cmd("ifconfig s4-eth4 0")
    #s4.cmd("ifconfig s4-eth5 0")
    s4.cmd("ip addr add 10.0.6.2/24 brd + dev s4-eth1")
    s4.cmd("ip addr add 192.168.4.254/24 brd + dev s4-eth2")
    s4.cmd("ip addr add 10.0.4.1/24 brd + dev s4-eth3")
    #s4.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
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
    #s5.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    s6.cmd("ifconfig s6-eth1 0")
    s6.cmd("ifconfig s6-eth2 0")
    s6.cmd("ifconfig s6-eth3 0")
    ap1.cmd("ifconfig ap1-eth1 0")
    ap2.cmd("ifconfig ap2-eth1 0")
    s6.cmd("ip addr add 192.168.10.253/24 brd + dev s6-eth1")
    s6.cmd("ip addr add 192.168.11.253/24 brd + dev s6-eth2")
    s6.cmd("ip addr add 192.168.11.254/24 brd + dev s6-eth3")
    ap1.cmd("ip addr add 192.168.11.1/24 brd + dev ap1-eth1")
    ap2.cmd("ip addr add 192.168.11.2/24 brd + dev ap2-eth1")
    #s6.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")


    CLI(net) # Start command line
    net.stop() # Stop Network

if __name__ == '__main__':
    setLogLevel('info')
    Topology(sys.argv)

    
        # sta11.cmd('iw dev %s interface add mon0 type monitor' % sta11.params['wlan'][0])
        # sta11.cmd('ifconfig mon0 up')
        # sta11.cmd('wireshark -i mon0 &')

        #ap1.cmd('ovs-ofctl add-flow "ap1" in_port=1,actions=normal')
        #ap1.cmd('ovs-ofctl add-flow "ap1" in_port=2,actions=normal')
        #ap2.cmd('ovs-ofctl add-flow "ap2" in_port=1,actions=normal')
        #ap2.cmd('ovs-ofctl add-flow "ap2" in_port=2,actions=normal')
                
              
