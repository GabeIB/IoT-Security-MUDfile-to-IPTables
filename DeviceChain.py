from subprocess import call
import dns.resolver

def better_call(command):
        try:
            call(command, shell=True)
        except Exception as e:
            print("error making iptables call: "+str(e))

class DeviceChain:
    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.chain_name = mac_addr
        self.chain_rules = [] #list to keep track of chain rules

    def buildChain(self, out_rules):
        #set up chain
        make_chain = 'iptables -N '+self.chain_name
        better_call(make_chain)
        #flush chain to ensure it's empty
        refresh_chain = 'iptables -F '+self.chain_name
        better_call(refresh_chain)
        #rout device traffic through this chain
        route = 'iptables -I iot_chain 1 -m mac --mac-source '+self.mac_addr+' -j '+self.chain_name
        better_call(route)

        #set up outbound device rules in device chain
        for rule in out_rules:
            protocol = rule[0]
            dport = rule[1]
            domain_name = rule[2]
            dns_answer = dns.resolver.query(domain_name)
            for ip in dns_answer:
                domain_ip = ip.address
                print("IPTABLES: domain = "+domain_name+" ip addr = "+str(domain_ip))
                make_rule = 'iptables -I '+self.chain_name+' 1 -p '+protocol+' --dport '+dport+' -d '+domain_ip+' -j ACCEPT'
                #print(make_rule)
                better_call(make_rule)
                self.chain_rules.insert(0, [domain_name, dport, protocol])
            make_rule = 'iptables -I '+self.chain_name+' 1 -p '+protocol+' --dport '+dport+' -d '+domain_name+' -j ACCEPT'
            better_call(make_rule) #done here in case ip address is given instead of domain name
            self.chain_rules.insert(0, [domain_name, dport, protocol])
            # This could be done more elegantly in the future.

        #drop device traffic that doesn't get accepted
        drop_else = 'iptables -A '+self.chain_name+' -j DROP'
        better_call(drop_else)

    def refreshDomain(self, domain):
        is_valid_domain = False
        dport = ""
        protocol = ""
        chain_num = 0
        l = len(self.chain_rules)
        for i in range(l):
            if self.chain_rules[chain_num][0] == domain:
                dport = self.chain_rules[chain_num][1]
                protocol = self.chain_rules[chain_num][2]
                is_valid_domain = True
                remove_rule = "iptables -D "+self.chain_name+" "+str(chain_num+1)
                better_call(remove_rule)
                del self.chain_rules[chain_num]
            else:
                chain_num+=1
        if(is_valid_domain):
            dns_response = dns.resolver.query(domain)
            for ip in dns_response:
                domain_ip = ip.address
                print("DNS UPDATE: domain = "+domain+" ip addr = "+str(domain_ip))
                make_rule = 'iptables -I '+self.chain_name+' 1 -p '+protocol+' --dport '+dport+' -d '+domain_ip+' -j ACCEPT'
                better_call(make_rule)
                self.chain_rules.insert(0, [domain, dport, protocol])
            make_rule = 'iptables -I '+self.chain_name+' 1 -p '+protocol+' --dport '+dport+' -d '+domain+' -j ACCEPT'
            better_call(make_rule) #done here in case ip address is given instead of domain name
            self.chain_rules.insert(0, [domain, dport, protocol])
                

