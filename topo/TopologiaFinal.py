#!/usr/bin/python
import sys
import os
from mininet.node import Controller, OVSKernelSwitch,  Host
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import Station, OVSKernelAP
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from subprocess import call
from mininet.node import RemoteController


def topology(args):

    net = Mininet_wifi(topo=None,
                       build=False,
                       link=wmediumd,
                       wmediumd_mode=interference,
                       controller=RemoteController
                       )

    info( '*** Adding controller\n' )

    
    c0 = net.addController(name='c0',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6633)
                           
    info('Adding L3 switch\n')
    s1 = net.addSwitch('s1', dpid='0000000000000001', cls=OVSKernelSwitch, protocols ='OpenFlow13')  # L3 switch
    s2 = net.addSwitch('s2', dpid='0000000000000002', cls=OVSKernelSwitch, protocols ='OpenFlow13')  # L3 switch
    s3 = net.addSwitch('s3', dpid='0000000000000003', cls=OVSKernelSwitch, protocols ='OpenFlow13')  # L3 switch
    s4 = net.addSwitch('s4', dpid='0000000000000004', cls=OVSKernelSwitch, protocols ='OpenFlow13')  # L3 switch
    s5 = net.addSwitch('s5', dpid='0000000000000005', cls=OVSKernelSwitch, protocols ='OpenFlow13')  # L3 switch

    info('Adding L2 switches\n')
    s6 = net.addSwitch('s6', dpid='0000000000000006', cls=OVSKernelSwitch, protocols ='OpenFlow13') # L2 Switch Net B (no ip)
     
    ap1 = net.addAccessPoint('ap1', dpid='0000000000000007', cls=OVSKernelAP, ssid='ap1-ssid',
                             channel='1', mode='g', position='632.0,345.0,0', protocols ='OpenFlow13')
    ap2 = net.addAccessPoint('ap2', dpid='0000000000000008', cls=OVSKernelAP, ssid='ap2-ssid',
                             channel='1', mode='g', position='947.0,338.0,0', protocols ='OpenFlow13')
    ap3 = net.addAccessPoint('ap3', dpid='0000000000000009', cls=OVSKernelAP, ssid='ap3-ssid',
                             channel='1', mode='g', position='1200.0,358.0,0',protocols ='OpenFlow13')

    info( '*** Add hosts/stations\n')
    sta1 = net.addStation('sta1', ip='192.168.1.2',
                           position='452.0,573.0,0')
    sta2 = net.addStation('sta2', ip='192.168.1.3',
                           position='626.0,578.0,0')
    sta3 = net.addStation('sta3', ip='192.168.2.2',
                           position='906.0,566.0,0')
    sta4 = net.addStation('sta4', ip='192.168.2.3',
                           position='1071.0,554.0,0')
    
    info('*** Add hosts/\n')
    h1 = net.addHost('h1', cls=Host, ip='192.168.1.4', mac='00:00:00:00:00:01', defaultRoute='via 192.168.1.254')
    h2 = net.addHost('h2', cls=Host, ip='192.168.2.4', mac='00:00:00:00:00:08', defaultRoute='via 192.168.2.254')
    h3 = net.addHost('h3', cls=Host, ip='192.168.3.4', mac='10:00:00:00:00:08', defaultRoute='via 192.168.3.254')
    h4 = net.addHost('h4', cls=Host, ip='192.168.4.4',mac ='00:00:00:00:00:04', defaultRoute='via 192.168.4.254')
    h5 = net.addHost('h5', cls=Host, ip='192.168.5.4',mac ='00:00:00:00:00:05', defaultRoute='via 192.168.5.254')

    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=3)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()
    if '-p' not in args:
                net.plotGraph(max_x=1550, max_y=1550)


    info( '*** Add links\n')
    net.addLink(s1, s2)
    net.addLink(s1, ap1)
    net.addLink(s1, ap2)
    net.addLink(sta1, ap1)
    net.addLink(sta2, ap1)
    net.addLink(h1, ap1)
    net.addLink(s2, h3)

    net.addLink(sta3, ap2)
    net.addLink(sta4, ap2)
    net.addLink(h2, ap2)
    

    #net.plotGraph(max_x=1000, max_y=1000)

    s1.setMAC('10:00:00:00:00:01', 's1-eth1')
    s1.setMAC('10:00:00:00:00:02', 's1-eth2')
    s1.setMAC('10:00:00:00:00:03', 's1-eth3')
    
    s2.setMAC('20:00:00:00:00:01', 's2-eth1')
    s2.setMAC('20:00:00:00:00:02', 's2-eth2')
    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()
    
    #net.addNAT().configDefault()
    info( '*** Starting switches/APs\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s5').start([c0])
    net.get('s6').start([c0])
    net.get('ap1').start([c0])
    net.get('ap2').start([c0]) 
    net.get('ap3').start([c0])
    
    
    s1.cmd("ifconfig s1-eth1 0")
    s1.cmd("ifconfig s1-eth2 0")
    s1.cmd("ifconfig s1-eth3 0")
  
    s1.cmd("ip addr add 192.168.1.254/24 brd + dev s1-eth1")
    s1.cmd("ip addr add 192.168.2.254/24 brd + dev s1-eth2")
    s1.cmd("ip addr add 10.0.0.1/24 brd + dev s1-eth3")
 
    s1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    s2.cmd("ifconfig s2-eth1 0")
    s2.cmd("ifconfig s2-eth2 0")

    s2.cmd("ip addr add 10.0.0.2/24 brd + dev s2-eth1")
    s2.cmd("ip addr add 192.168.3.100/24 brd + dev s2-eth2")

    s2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")


    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    topology(sys.argv)
