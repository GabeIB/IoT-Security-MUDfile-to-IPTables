#manages firewall on router
#this implementation uses iptables
#Gabriel Brown - gb2582

from subprocess import call
from DatabaseManager import *
from DeviceChain import * #does most of the heavy lifting with buildChain
from gmud_decode import * #MUDtoRules
import dns.resolver

iot_chain = 'iot_chain' #this is the name of the iptables chain that all traffic is directed through

def better_call(command):
        try:
            call(command, shell=True)
        except Exception as e:
            print("error making iptables call: "+str(e))

class FirewallManager:

    def __init__(self, dbName):
        self.dbManager = DatabaseManager(dbName)
        self.initIPTables()
        self.deviceDict = dict()
        self.loadRulesFromDB()

    def MUDtoFirewall(self, mac_addr, mud_file):
        in_rules, out_rules = MUDtoRules(mud_file)
        try:
            self.implementDeviceRules(mac_addr, in_rules, out_rules)
        except:
            print("exception occured")
        self.dbManager.addIoT(mac_addr, in_rules, out_rules)
        
    def isMACRegistered(self, mac_address):
        return self.dbManager.isMACRegistered(mac_address)

    #a rule is of the form [protocol, port, domain] where all are strings
    def implementDeviceRules(self, mac_addr, in_rules, out_rules):
        self.deviceDict[mac_addr] = DeviceChain(mac_addr)
        self.deviceDict[mac_addr].buildChain(out_rules)

#make chain called iot-chain and route all forward traffic through this chain
    def initIPTables(self):
        make_device_chain = 'iptables -N ' + iot_chain
        route_device_chain = 'iptables -I FORWARD 1 -j '+iot_chain
        call(make_device_chain, shell=True)
        call(route_device_chain, shell=True) 

    def newGenPurpose(self, mac):
        self.dbManager.addGenDevice(mac)

    def loadRulesFromDB(self):
        mac_list = self.dbManager.getIoTList()
        for mac in mac_list:
            in_rules, out_rules = self.dbManager.getRules(mac)
            self.implementDeviceRules(mac, in_rules, out_rules)

    def updateDNSMapping(self, mac_addr, domain):
        domain = domain[:len(domain)-1] #for some reason domain names end with a '.'
        if mac_addr in self.deviceDict:
            self.deviceDict[mac_addr].refreshDomain(domain)
