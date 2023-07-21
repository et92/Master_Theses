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
from mn_wifi.link import wmediumd,mesh
from mn_wifi.link import adhoc
from mn_wifi.sumo.runner import sumo
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import OVSKernelAP, UserAP, OVSBridgeAP, OVSAP
from mn_wifi.wmediumdConnector import interference

import threading
import time

        
def Topology(args):
    os.system ('sudo ufw disable')
    os.system('service network-manager stop')
    info("Creating nodes...")
    
    net = Mininet_wifi( controller=RemoteController, link=wmediumd, wmediumd_mode=interference, accessPoint=OVSBridgeAP,)
   
    info('Defining to remote controller on port 6653 (L3 switch)\n')
    c1 = net.addController(name='c1',
                        controller=RemoteController,
                        ip='127.0.0.1',
                        protocol='tcp',
                        port=6653) #L3
    
    info("*** Creating nodes: car\n")
    #cars = []
    """ for id in range(0, 3):
        cars.append(net.addCar('car%s' % (id + 1), wlans=2, encrypt='wpa2,'))
     """
   
    info('*** stations/\n')
    car1= net.addCar('car1',ip='192.168.11.11/24', defaultRoute='via 192.168.11.254', wlans=1, encrypt='wpa2',)
    car2= net.addCar('car2', ip='192.168.11.12/24', defaultRoute='via 192.168.11.254',  wlans=1, encrypt='wpa2',)
    car3= net.addCar('car3', ip='192.168.20.11/24', defaultRoute='via 192.168.20.254', wlans=1, encrypt='wpa2',)


    """ info("*** Creating nodes: rsu\n")
    rsus = []
    for id in range(0, 3):
        rsus.append(net.addCar('rsu%s' % (id + 1), wlans=2, encrypt='wpa2,'))
    """


    poss = ['200.00,200.00,0.0', '400.00,200.00,0.0', '600.00,200.00,0.0']
    ap1 = net.addAccessPoint('ap1', ssid='ap1-ssid', mac='00:00:00:11:00:01',
                            mode='g', channel='1', passwd='123456789a',
                            encrypt='wpa2', position=poss[0])
    ap2 = net.addAccessPoint('ap2', ssid='ap2-ssid', mac='00:00:00:11:00:02',
                            mode='g', channel='6', passwd='123456789a',
                            encrypt='wpa2', position=poss[1])
    ap3 = net.addAccessPoint('ap3', ssid='ap3-ssid', mac='00:00:00:11:00:03',
                            mode='g', channel='11', passwd='123456789a',
                            encrypt='wpa2', position=poss[2])
    

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


    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=3.8)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    """  if '-p' not in args:
                net.plotGraph(max_x=1550, max_y=1550)
    """
    info("*** Adding link\n")
    
    """  net.addLink(rsus[0], rsus[1])
    net.addLink(rsus[1], rsus[2])

    #Experimental, apagar depois
    net.addLink(ap1, ap2)
    net.addLink(ap2, ap3) """
   
    #net.auto_association()
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

   

    """ for rsu in rsus:
        net.addLink(rsu, intf=rsu.wintfs[1].name,
                    cls=mesh, ssid='mesh-ssid', channel=5) """
    """ 
    for car in cars:
        net.addLink(car, intf=car.wintfs[1].name,
                    cls=mesh, ssid='mesh-ssid', channel=5)
     """ 
    
    # Add wireless mesh links between car1, car2, and car3 interfaces
    for car in [car1, car2, car3]:
        net.addLink(car, intf=car.wintfs[0].name, cls=mesh, ssid='mesh-ssid', channel=5)


    info("*** Starting sumo\n")
    # change config_file name if you want
    # use --random for active the probability attribute of sumo
    net.useExternalProgram(program=sumo, port=8813,
                           #config_file="/home/parallels/mininet-wifi/mn_wifi/sumo/sdvanets/sumo_files/minimal/map.sumocfg",
                           config_file='/home/parallels/Documents/Master_Theses/SumoTutorial/second_exemplo/second.sumocfg',
                           extra_params=["--start --delay 650"],
                           clients=1, exec_order=0
                           )
    
  

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

    """ for rsu in rsus:
        rsu.setIP('192.168.11.%s/24' % (int(rsus.index(rsu)) + 101),
                  intf='%s-wlan0' % rsu)
        rsu.setIP('192.168.20.%s/24' % (int(rsus.index(rsu)) + 101),
                  intf='%s-mp1' % rsu)
    
    for rsu, pos in zip(rsus, poss):
        rsu.setPosition(pos=pos)
    """

    """  car1.setIP('192.168.11.11/24', intf='car1-wlan0')
    car2.setIP('192.168.11.12/24', intf='car2-wlan0')
    car3.setIP('192.168.20.11/24', intf='car3-wlan0') """

    car1.cmd('ip route add default via 192.168.11.254')
    car2.cmd('ip route add default via 192.168.11.254')
    car3.cmd('ip route add default via 192.168.20.254')
    
    
    """
    for car in cars:
        car.setIP('192.168.11.%s/24' % (int(cars.index(car)) + 1),
                  intf='%s-wlan0' % car)
         car.setIP('192.168.1.%s/24' % (int(cars.index(car)) + 1),
                  intf='%s-mp1' % car) """

    info("*** Starting telemetry\n")
    # Track the position of the nodes
    nodes = net.cars + net.aps
    net.telemetry(nodes=nodes, data_type='position',
                  min_x=0, min_y=0,
                  max_x=1000, max_y=1000)
    
    """ info("*** Starting agents\n")
    for car in net.cars:
        if car.name in [rsu.name for rsu in rsus]:
            car.cmd('xterm -e python3 -m network_agent '
                    '--log -srnm --filename %s --name=%s --verbose --rsu &' % (car, car))
        else:
            car.cmd('xterm -e python3 -m network_agent --name=%s -srmn --verbose &' % car)
    """
     
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

    ap1.setIP('192.168.11.1/24', intf='ap1-wlan1')
    ap2.setIP('192.168.11.2/24', intf='ap2-wlan1')
    ap3.setIP('192.168.20.20/24', intf='ap3-wlan1')

    #ap1.setIP('192.168.11.3/24', intf='ap1-eth1')
    #ap2.setIP('192.168.11.4/24', intf='ap2-eth1')
    #ap3.setIP('192.168.20.253/24', intf='ap3-eth1')

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
