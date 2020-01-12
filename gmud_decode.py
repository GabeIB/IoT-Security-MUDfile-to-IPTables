import json
import sys
global json_object

def mud_decode(f):
#    try:
    print(f)
    json_object = json.loads(f)
#    except ValueError:
#	return None
    ACL_array = json_object["ietf-access-control-list:access-lists"]["acl"]
    return ACL_array

def file_to_acl(f):
    try:
	with open(file, 'r') as f:
        	json_object = json.load(f)
		#print json.dumps(json_object)
    except ValueError:
        print("Incorrect File Content Format: JSON")
    ACL_array = json_object["ietf-access-control-list:access-lists"]["acl"]
    return ACL_array
	

def ACLtoRules(acl):
  if(acl==None):
      return(None,None)
  i = 0
  in_rules = []
  out_rules = []
  for ace in acl:
    if i < 2:
      for index in ace["aces"]['ace']:
	matches = index["matches"]
	#Confirm that matches has valid info for dest addr
        if("ietf-acldns:src-dnsname" not in matches["ipv4"] and \
            "ietf-acldns:dst-dnsname" not in matches["ipv4"]):
                continue
	if "ietf-acldns:src-dnsname" in matches["ipv4"]:
	        dnsName = ["ietf-acldns:src-dnsname", "source-port"]
	elif "ietf-acldns:dst-dnsname" in matches["ipv4"]:
        	dnsName = ["ietf-acldns:dst-dnsname", "destination-port"]
	if("tcp" in matches):
	        subport = matches["tcp"]
	        prot = "tcp"
	elif("udp" in matches):
        	subport = matches["udp"]
        	prot = "udp"
    	else:
        	print("Error in Matches")
	dport = str(subport[dnsName[1]]["port"])
	dstName = str(matches["ipv4"][dnsName[0]])
	from_or_to = 'from' if 'from' in index['name'] else 'to'

        if(from_or_to == 'to'):
            in_rules.append([prot, dport, dstName])
        else:
            out_rules.append([prot, dport, dstName])
      i = i + 1
  return(in_rules, out_rules)

def MUDtoRules(MUD):
    return ACLtoRules(mud_decode(MUD))

def fileToRules(f):
    return ACLtoRules(file_to_acl(f))

def ep_set(filename):
    outset = set()
    acl_array = mud_decode(filename)
    ipset = ACLtoRules(acl_array)
    for dstname in list(ipset):
	outset.add(dstname[2])
    #print(outset)
    return outset
#ep_set(filename)
