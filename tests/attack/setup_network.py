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
s4 = net.addSwitch('s4')

sa = net.addSwitch('s5')
sb = net.addSwitch('s6')
# Attacker switch
sc = net.addSwitch('s7')



info('*** Adding docker containers\n')

R1 = net.addDocker('R1', ip="11.0.1.254/24", dimage="r1-quagga")
R2 = net.addDocker('R2', ip="12.0.1.254/24", dimage="r2-quagga")
R3 = net.addDocker('R3', ip="13.0.1.254/24", dimage="r3-quagga")
# Attacker node
R4 = net.addDocker('R4', ip="13.0.1.254/24", dimage="r4-quagga")

# add end host code here
WS = net.addDocker('WS', ip="13.0.1.1/24", dimage="ws-quagga")
AWS = net.addDocker('AWS', ip="13.0.1.1/24", dimage="ws-quagga")
C1 = net.addDocker('C1', ip="11.0.1.1/24", dimage="quaggabase")


info("Configuring IP addresses of the local connections\n")

# Attack link
net.addLink(R1,sc,params1={"ip":"9.0.4.1/24"})
net.addLink(R4,sc,params1={"ip":"9.0.4.2/24"})

# Link routers to each other
net.addLink(R1,sa,params1={"ip":"9.0.0.1/24"})
net.addLink(R2,sa,params1={"ip":"9.0.0.2/24"})
net.addLink(R2,sb,params1={"ip":"9.0.1.1/24"})
net.addLink(R3,sb,params1={"ip":"9.0.1.2/24"})

# Link routers to their associated AS switches
net.addLink(R1,s1,params1={"ip":"11.0.1.254/24"})
net.addLink(R2,s2,params1={"ip":"12.0.1.254/24"})
net.addLink(R3,s3,params1={"ip":"13.0.1.254/24"})
net.addLink(R4,s4,params1={"ip":"13.0.1.254/24"})

# Link hosts to their AS switches
net.addLink(C1,s1,params1={"ip":"11.0.1.1/24"})
net.addLink(WS,s3,params1={"ip":"13.0.1.1/24"})
net.addLink(AWS,s4,params1={"ip":"13.0.1.1/24"})

R1.cmd('/start.sh &')
R2.cmd('/start.sh &')
R3.cmd('/start.sh &')

# Magic sauce to make the attacker node behave right. There's a
# strange behavior that makes it such that the node doesn't
# do what it should unless some non-bash command has been run
# via the Docker.cmd member or by creating an interative
# terminal via docker exec.
R4.cmd('ifconfig')

WS.cmd('route del default')
WS.cmd('route add default gw 13.0.1.254')
AWS.cmd('route del default')
AWS.cmd('route add default gw 13.0.1.254')
C1.cmd('route del default')
C1.cmd('route add default gw 11.0.1.254')

WS.cmd('/webserver.py &')
AWS.cmd("/webserver.py --text 'Attacking Webserver' &")

info('*** Starting network\n')
net.start()
info('*** Stalling for 10 seconds to allow BGP advertisisng \n')
time.sleep(10)
info('*** Testing connectivity\n')
net.ping([R1, R2])
net.ping([R2, R3])
net.ping([C1, WS])

info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()

