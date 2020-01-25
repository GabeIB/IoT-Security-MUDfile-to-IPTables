# IoT-Security-MUDfile-to-IPTables
DD-WRT scripts for creating IPTables rules for IoT devices with MUD files

Full technical on GabrielBrown.net/blog/IoTSec1/IRT_final_report.pdf

tl;dr: IoT devices are especially susceptible to security threats, and because of their limited computational power, normal approaches for securing devices aren't effective. However, IoT devices only need to connect to a small set of endpoints over the network to perform their intended function. Thus, we can limit the endpoints an IoT devices is allowed to communicate with, without limiting the functionality of the device.

This characteristic of IoT devices was used to create RFC 8520. Essentially, the standard suggests that IoT manufacturers create a Manufacturer Usage Description File (MUD file) for each of their IoT devices that, among other things, contains a set of endpoints that the device needs to communicate with to function properly. Manufacturers will then host this MUD file on a server and include a url to the MUD file in option 161 of their IoT devices DHCP request.

This script is meant to run on a DD-WRT router. It sniffs all traffic through the router, and when it sees a DHCP Discover packet with a URL in option 161, it downloads the MUD file and turns the set of allowed endpoints into a set of IPTables rules. It does a number of things to ensure robust functionality.



dependencies: scapy, dnspython, mongoengine, ssl, urllib2

Run by running python gabesniffer.py on command line. This project is hosted for documentation purposes - not to run out of the box. dbURL must be a valid URL to a mongo database (ideally hosted with Atlas).
