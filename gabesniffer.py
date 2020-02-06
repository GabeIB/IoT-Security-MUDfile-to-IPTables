#!/opt/bin/python

#Workspace for scapy's sniff to monitor for IoT device activities
#Detect new joining IoT devices and dynamically update domain endpoints IP Addrs

from scapy.all import *
from PacketHandler import *

#URL to mongodb. Include ssl=true&ssl_cert_reqs=CERT_NONE if there are ssl certificate issues
#change UserName:Password
dbURL = 'mongodb://UserName:Password@riotcluster-shard-00-00-i0ezx.mongodb.net:27017,riotcluster-shard-00-01-i0ezx.mongodb.net:27017,riotcluster-shard-00-02-i0ezx.mongodb.net:27017/test?ssl=true&ssl_cert_reqs=CERT_NONE&replicaSet=RiotCluster-shard-0&authSource=admin&retryWrites=true&w=majority'


#initialize packet handler
packetHandler = PacketHandler(dbURL)
print "starting sniffer"
#capture all packets
#store=0 prevents scapy from leaking memory
sniff(prn=packetHandler.sniff, store=0)
