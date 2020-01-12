#Gabriel Brown - gb2582@columbia.edu

from mongoengine import *
import os

class IoT(Document):
    mac_addr = StringField(required = True, max_length=20)
    allowed_in = ListField(ListField(StringField()))
    allowed_out = ListField(ListField(StringField()))

class NoT(Document):
    mac_addr = StringField(required = True, max_length=20)

class DatabaseManager:
    def __init__(self, dbURL):
        connect(host = dbURL)
        self.addGenDevice('10:da:43:96:1d:64')

    def isMACRegistered(self, mac_address):
        IoTDevices = IoT.objects(mac_addr=mac_address)
        NoTDevices = NoT.objects(mac_addr=mac_address)
        if(len(IoTDevices)==0 and len(NoTDevices)==0):
            return False
        else:
            return True

#returns a list of mac addresses in database
    def getIoTList(self):
        devices = list()
        for d in IoT.objects:
            devices.append(d.mac_addr)
        return devices

    def addIoT(self, mac, in_rules, out_rules):
        post = IoT(
                mac_addr = mac,
                allowed_in = in_rules,
                allowed_out = out_rules
                )
        post.save()

    def removeIoT(self, mac):
        device = IoT.objects(mac_addr=mac)
        if(len(device) != 0):
            for d in device:
                d.delete()

    def getGenList(self):
        devices = list()
        for d in NoT.objects:
            devices.append(d.mac_addr)
        return devices

    def addGenDevice(self, mac):
        post = NoT(
                mac_addr = mac
                )
        post.save()

    def removeGenDevice(self, mac):
        device = NoT.objects(mac_addr=mac)
        if(len(device) !=0):
            for d in device:
                d.delete()

#assumption is that each database entry is uniquely
#identified by its mac address. If there are 2 entries with
#same mac address in the database this will only return the
#first one - this SHOULD not be an issue but should be noted
    def getRules(self,mac):
        device = IoT.objects(mac_addr=mac)
        if(len(device) == 0):
            return None
        else:
            return(device[0].allowed_in, device[0].allowed_out)
