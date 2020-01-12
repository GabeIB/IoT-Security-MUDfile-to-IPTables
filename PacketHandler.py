#!/opt/bin/python
#Gabriel Brown - gb2582@columbia.edu

from FirewallManager import *
from PacketHandlerUtils import *
from scapy.all import *

class PacketHandler:

    def __init__(self, dbName):
        self.firewallManager = FirewallManager(dbName)
        self.errorLog = open('error_log.txt', "w+")

#handles DNS packets
    def DNSHandler(self, pkt):
        udp, dns = pkt[UDP], pkt[DNS]
        if pkt[UDP].dport == 53:
            mac_addr = pkt[Ether].src
            domain = pkt[DNS].qd.qname
            self.firewallManager.updateDNSMapping(mac_addr, domain)

#handles DHCP packets
#implement iptable based on device type
#add to database
    def DHCP_unknownDevice(self, pkt, mac_addr):
        if isIoT(pkt): #we're only firewalling IoT devices
            mud_url = get161URL(pkt)
            if mud_url != None:
                mud_file = getMUD161(mud_url)
            else:
                print("no op 161")
                mud_file = getMCSMUD(pkt)
            if(mud_file != None):
                self.firewallManager.MUDtoFirewall(mac_addr, mud_file)
        else:
            print("not an iot device")

#checks if database has already registered the device
#if not, it calls another DHCP Handler
    def DHCPHandler(self, pkt):
        mac_addr = str(pkt[Ether].src)
        print("gsniffer detected: "+mac_addr)
        if self.firewallManager.isMACRegistered(mac_addr):
            print("mac already registered")
        else:
            print("registering device")
            self.DHCP_unknownDevice(pkt, mac_addr)

#logs packets to error log
    def logPacketError(self, pkt):
        self.errorLog.write("packet handle error:")
        self.errorLog.write(str(pkt))

#calls the appropriate Handler function based on packet type
    def _sniff(self, pkt):
        pktType = identifyPacket(pkt)
        if pktType == 'DNS':
            self.DNSHandler(pkt)
        elif pktType == 'DHCP':
            self.DHCPHandler(pkt)

#wrapper function that calls _sniff and catches errors
#this is for security so that a malformed packet won't crash the program
    def sniff(self, pkt):
        #try:
        self._sniff(pkt)
        #except Exception as e:
         #   print("Error in sniff: "+str(e))
          #  self.logPacketError(pkt)

