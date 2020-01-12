#utility methods for PacketHandler Class
#Gabriel Brown - gb2582@columbia.edu

import ssl
import urllib2
from scapy.all import *

#taken from old script needs to be modified to be easier to understand
def layer_expand(pkt):
    yield pkt.name
    while pkt.payload:
        pkt = pkt.payload
        yield pkt.name

#decides if a DHCP request is from an IoT Device
#if has option 161 -> IoT Device
#if hostname in parameter-request-list -> IoT Device
#Domain name NOT in parameter-request-list -> IoT Device
#vendor-class-ID:soc in labels -> IoT Device
#maximum-dhcp-size:1496 -> IoT
#else General Purpose
def isIoT(pkt):
    if get161URL(pkt) != None:
        return True
    else:
        #parse DHCP
        options = pkt[DHCP].options
        param_req_list = None
        max_dhcp_size = None
        vendor_class_id = None
        for option in options:
            if option != 'end':
                if option[0] == 'param_req_list':
                    param_req_list = option
                if option[0] == 'max_dhcp_size':
                    max_dhcp_size = option[1]
                if option[0] == 'vendor_class_id':
                    vendor_class_id = option[1]
        #parse relevant info from param_req_list
        req_domain = False
        req_hostname = False
        for param in param_req_list:
            if param == '\x0c':
                req_hostname = True
            if param == '\x0f': 
                req_domain = True
        #decision tree
        if req_hostname:
            return True
        elif not req_domain:
            return True
        elif vendor_class_id == 'soc':
            return True
        elif max_dhcp_size == 1496:
            return True
        else:
            return False

#takes a DHCP packet returns a list of tuples
#first in tuple is option number
#second in tuple is value
def getDHCPOptions(pkt):
    optionList = pkt[DHCP].options
    if(len(optionList)<1):
        return None
    return optionList

#returns URL in option 161 of DHCP packet - none if no such option exists
def get161URL(pkt):
    options = getDHCPOptions(pkt)
    for opt in options:
        if opt[0] == 161:
            return str(opt[1])
    return None

def getMUD161(mud_addr):
    #try:
    if(mud_addr == None):
        print("mud op 161 error")
    req = urllib2.Request(mud_addr)
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    result = urllib2.urlopen(req, context = gcontext)
    profile = result.read().decode('utf-8')
    return profile
    #except Exception as e:
    #    print("error fetching mudfile: "+str(e))
    #    return None

#returns true if 
def hasOp161(pkt):
    if get161URL(pkt) != None:
        return True
    else:
        return False

def getMCSMUD(pkt):
    pass

#identifies the packet type
#currently only identifies DNS, DHCP, and OTHER
def identifyPacket(pkt):
    layers = list(layer_expand(pkt))
    if "DNS" in layers:
        type = 'DNS'
    elif "BOOTP" in layers:
        type = 'DHCP'
    else:
        type = 'OTHER'
    return type


