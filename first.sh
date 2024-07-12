#!/usr/bin/python3
from mininet.net import Mininet
from mininet.node import Controller , RemoteController , OVSKernelSwitch ,UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link ,TCLink

import os  
from time import sleep 


def topology():
	net = Mininet(controller =RemoteController ,link=TCLink, switch = OVSKernelSwitch)
	c0 = net.addController('co' , controller = RemoteController , ip = '127.0.0.1' ,port=6633)
	s1 = net.addSwitch('s1',listenport=6673, mac = '00:00:00:00:00:01')
	s2 = net.addSwitch('s2',listenport=6674, mac = '00:00:00:00:00:02')
	s3 = net.addSwitch('s3',listenport=6675, mac = '00:00:00:00:00:03')
	h1 = net.addHost('h1' , mac = '00:00:00:00:01')	
	h2 = net.addHost('h2' , mac = '00:00:00:00:02')
	h3 = net.addHost('h3' , mac = '00:00:00:00:03')
	h4 = net.addHost('h4' , mac = '00:00:00:00:04')
	h5 = net.addHost('h5' , mac = '00:00:00:00:05')
	h6 = net.addHost('h6' , mac = '00:00:00:00:06')	
	c0 = net.addController ('c0' , controller = RemoteController , ip = '127.0.0.1' , port = 6633)
	net.addLink(s1 , s2)
	net.addLink(s1 , s3)
	net.addLink(s1 , h1)
	net.addLink(s1 , h2)
	net.addLink(s1 , h3)
	net.addLink(s1 , h4)
	net.addLink(s2 , h5)
	net.addLink(s2 , h6)
	
	net.build()
	net.start()
	c0.start()
	s2.start([c0])
	s1.start([c0])
	
	h2.cmd('tshark> rec.txt&')
	h1.cmd('ping -c 2 '+str(h2.IP()))
	CLI(net)
	net.stop()
if __name__ == '__main__':
	setLogLevel('info')
	topology()
