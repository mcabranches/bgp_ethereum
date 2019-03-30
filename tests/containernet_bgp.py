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
#s4 = net.addSwitch('s4')




info('*** Adding docker containers\n')
#R1 = net.addDocker('R1', ip='10.0.0.251', dimage="quagga")
#R2 = net.addDocker('R2', ip='10.0.0.252', dimage="quagga")
#R3 = net.addDocker('R3', ip='10.0.0.253', dimage="quagga")
#R3 = net.addDocker('R4', ip='10.0.0.253', dimage="quagga")

R1 = net.addDocker('R1', dimage="r1-quagga")
R2 = net.addDocker('R2', dimage="r2-quagga")
R3 = net.addDocker('R3', dimage="r3-quagga")
#R4 = net.addDocker('R4', dimage="r4-quagga")
#m-> connect R1->R2 using a link object (no switch)
linkR1R2 = Link(R1, R2)
linkR2R3 = Link(R2, R3)
#linkR1R4 = Link(R1, R4)
#m-> links to the local switches
linkR11s1 = Link(R1, s1)
linkR12s1 = Link(R1, s1)
linkR13s1 = Link(R1, s1)
linkR21s2 = Link(R2, s2)
linkR22s2 = Link(R2, s2)
linkR23s2 = Link(R2, s2)
linkR31s3 = Link(R3, s3)
linkR32s3 = Link(R3, s3)
linkR33s3 = Link(R3, s3)
#linkR41s4 = Link(R4, s4)
#linkR42s4 = Link(R4, s4)
#linkR43s4 = Link(R4, s4)

info("Configuring IP addresses of the local connections\n")
#AS1
R1.setIP('11.0.1.254/24', intf=linkR11s1.intf1)
R1.setIP('11.0.2.254/24', intf=linkR12s1.intf1)
R1.setIP('11.0.3.254/24', intf=linkR13s1.intf1)
#AS2
R2.setIP('12.0.1.254/24', intf=linkR21s2.intf1)
R2.setIP('12.0.2.254/24', intf=linkR22s2.intf1)
R2.setIP('12.0.3.254/24', intf=linkR23s2.intf1)
#AS3
R3.setIP('13.0.1.254/24', intf=linkR31s3.intf1)
R3.setIP('13.0.2.254/24', intf=linkR32s3.intf1)
R3.setIP('13.0.3.254/24', intf=linkR33s3.intf1)
#AS4 (rogue)
#R4.setIP('13.0.1.254/24', intf=linkR41s4.intf1)
#R4.setIP('13.0.2.254/24', intf=linkR42s4.intf1)
#R4.setIP('13.0.3.254/24', intf=linkR43s4.intf1)

#AS links
R1.setIP('9.0.0.1/24', intf=linkR1R2.intf1)
R2.setIP('9.0.0.2/24', intf=linkR1R2.intf2)
R2.setIP('9.0.1.1/24', intf=linkR2R3.intf1)
R3.setIP('9.0.1.2/24', intf=linkR2R3.intf2)
#R1.setIP('9.0.4.1/24', intf=linkR1R4.intf1)
#R4.setIP('9.0.4.2/24', intf=linkR1R4.intf2)
#info('*** Adding manual routes for testing')
#R2.cmd('route add -net 10.0.124.0/24 gw 10.0.123.1')
#R3.cmd('route add -net 10.0.123.0/24 gw 10.0.124.1')
R1.cmd('/start.sh &')
R2.cmd('/start.sh &')
R3.cmd('/start.sh &')
#R4.cmd('/start.sh &')
#info('*** Adding switches\n')
#s1 = net.addSwitch('s1')
#s2 = net.addSwitch('s2')
#info('*** Creating links\n')
#net.addLink(R1, s1)
#net.addLink(s1, s2, cls=TCLink, delay='100ms', bw=1)
#net.addLink(s2, R2)
info('*** Starting network\n')
net.start()
info('*** Testing connectivity\n')
net.ping([R1, R2])
#net.ping([R1, R3])
#net.ping([R2, R3])
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()

