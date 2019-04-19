#!/usr/bin/python
"""
This is the most simple example to showcase Containernet.
"""
from mininet.net import Containernet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.link import Link
import time
setLogLevel('info')

net = Containernet(controller=Controller)
#m-> no SDN controller
#net = Containernet()
#info('*** Adding controller\n')
net.addController('c0')
info('*** Adding switches for the local nets\n')
#m-> don't know if we should add 1 switch for each local net at AAS
#m-> adding one switch for each AS


s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')

sa = net.addSwitch('s4')
sb = net.addSwitch('s5')

#s4 = net.addSwitch('s4')


info('*** Adding docker containers\n')

R1 = net.addDocker('R1', ip="11.0.0.1/24", dimage="r1-quagga")
R2 = net.addDocker('R2', ip="12.0.0.1/24", dimage="r2-quagga")
R3 = net.addDocker('R3', ip="13.0.0.1/24", dimage="r3-quagga")

# add end host code here
WS = net.addDocker('WS', ip="13.0.0.2/24", dimage="quaggabase")
C1 = net.addDocker('C1', ip="11.0.0.2/24", dimage="quaggabase")


info("Configuring IP addresses of the local connections\n")

# Link routers to each other
net.addLink(R1,sa,params1={"ip":"9.0.0.1/24"})
net.addLink(R2,sa,params1={"ip":"9.0.0.2/24"})
net.addLink(R2,sb,params1={"ip":"9.0.1.1/24"})
net.addLink(R3,sb,params1={"ip":"9.0.1.2/24"})

# Link routers to their associated AS switches
net.addLink(R1,s1,params1={"ip":"11.0.0.1/24"})
net.addLink(R2,s2,params1={"ip":"12.0.0.1/24"})
net.addLink(R3,s3,params1={"ip":"13.0.0.1/24"})

# Link hosts to their AS switches
net.addLink(WS,s3,params1={"ip":"13.0.0.2/24"})
net.addLink(C1,s1,params1={"ip":"11.0.0.2/24"})

R1.cmd('/start.sh &')
R2.cmd('/start.sh &')
R3.cmd('/start.sh &')

WS.cmd('route add default gw 13.0.0.1')
C1.cmd('route add default gw 11.0.0.1')

info('*** Starting network\n')
net.start()
info('*** Stalling for 5 seconds to allow BGP advertisisng \n')
time.sleep(5)
info('*** Testing connectivity\n')
net.ping([R1, R2])
net.ping([R2, R3])
net.ping([R1, R3])
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()

