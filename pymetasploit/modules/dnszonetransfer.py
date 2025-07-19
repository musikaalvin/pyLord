import pyfiglet
from collections import OrderedDict
import dns.zone
import dns.query
import dns.resolver

MODULE_TYPE = "recon"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'DNS Zone Transfer',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Dumps credentials from Target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('DOMAIN', ('', True,'Enter target domain(e.g example.com)')),
            ('SERVER', ('', True,'Enter target dns server (e.g )ns1.example.com)'))
           
               
                ])
                }
    def logo(self):
    	title = 'DNS Zone Transfer'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> , then run")
   
    def dns_zone_transfer(self,domain, nameserver):
      zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
      for name, node in zone.nodes.items():
        print(f"{name}: {node}")
    
    
    def execute(self):
        self.logo()
        domain = self.info['Options']['DOMAIN'][0]
        nameserver = self.info['Options']['SERVER'][0]
        self.dns_zone_transfer(domain, nameserver)
        
        return f"[+] Tranfering dns zones from {domain}..."
    