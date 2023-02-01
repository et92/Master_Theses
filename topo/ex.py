#!/usr/bin/python

'Example for Handover'

from mininet.node import Controller
from mininet.log import setLogLevel, info
from mn_wifi.node import OVSKernelAP
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi



def topology():
    "Create a network."
    net = Mininet_wifi(controller=Controller, accessPoint=OVSKernelAP)

    info("*** Creating nodes\n")
    mov = net.addStation('mov', mac='00:00:00:00:00:02', ip='10.0.0.2/8',
                          position="0,50,0")
    h1 = net.addStation("h1", mac="00:00:00:00:00:03", ip="10.0.0.3/8", position="15,60,0")
    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mode='g', channel='1',
                             position='15,50,0', range=20)
    ap2 = net.addAccessPoint('ap2', ssid='ssid-ap1', mode='g', channel='6', position='55,50,0', range=20)
    ap3 = net.addAccessPoint('ap3', ssid='ssid-ap1', mode='g', channel='1',
                             position='100,50,0', range=20)
    c1 = net.addController('c1', controller=Controller)

    net.setPropagationModel(model="logDistance", exp=5)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info("*** Creating links\n")
    net.addLink(ap1, h1)
    net.addLink(ap1, ap2)
    net.addLink(ap1, ap3)

    net.plotGraph(max_x=100, max_y=100)

    #'''
    net.startMobility(time=0)
    net.mobility(mov, 'start', time=1, position='0,50,0')
    net.mobility(mov, 'stop', time=49, position='100,50,0')
    net.stopMobility(time=50)
    #'''

    info("*** Starting network\n")
    net.build()
    c1.start()
    ap1.start([c1])
    ap2.start([c1])
    ap3.start([c1])

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
