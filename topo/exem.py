from mininet.node import RemoteController, Controller
from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference

def topology():
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
   
    s1 = net.addSwitch('s1', mac='00:00:00:00:00:01', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', mac='00:00:00:00:00:02', protocols='OpenFlow13')
    ap1 = net.addAccessPoint('ap1' ,position='100,100,0', mac='00:00:00:00:00:03', ssid='ssid1', mode='g', channel='1', protocols='OpenFlow13')
    sta1 = net.addStation('sta1', position='50,50,0', mac='00:00:00:00:00:04')
    h1 = net.addHost('h1', ip='10.0.0.4/24')
    h2 = net.addHost('h2', ip='10.0.0.5/24')
   
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', protocol='tcp', port=6653)
   
    net.setPropagationModel(model="logDistance", exp=3.2)
    net.configureWifiNodes()
   
    net.addLink(s1,s2)
    net.addLink(s2,ap1)
    net.addLink(h1,s1)
    net.addLink(h2,s2)
    net.addLink(ap1,sta1,0,0)
   
   
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    ap1.start([c0])

   
    CLI(net)
   
    net.stop()
   
if __name__ == '__main__':
   setLogLevel('info')
   topology()
