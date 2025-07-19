import nmap
import pyfiglet
from collections import OrderedDict
MODULE_TYPE = "recon"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Nmap OS Fingerprinting',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'OS Fingerprinting with nmap.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('target IP (e.g., Ip address)', True, 'IP ADDRESS')),
                
               
                ])
                }
    def logo(self):
    	title = 'Nmap os details'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> set PORT <port> ,then run")
   
    def os_fingerprinting(self,target_ip):
      nm = nmap.PortScanner()
      nm.scan(target_ip, arguments='-O')
      for host in nm.all_hosts():
        print(f"Host: {host}")
        print(f"OS: {nm[host]['osclass'][0]['osfamily']}")
    
    def execute(self):
        target_ip = self.info['Options']['RHOST'][0]
        self.os_fingerprinting(target_ip)
        
        return "[+] Dumping data ..."
    