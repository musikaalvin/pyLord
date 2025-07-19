from scapy.all import sniff
from collections import OrderedDict
import pyfiglet
MODULE_TYPE = "auxiliary"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Network Sniffer',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Python  Network packet Sniffer',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Note':'This script is for educational purposes only',
            'Options': OrderedDict([
            (None, ('', False,'')),
            
               
                ])
                }
    def logo(self):
    	title = 'Network Sniffer'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: type run")
   
    def packet_callback(self,packet):
    	print(packet.summary())
    def network_sniffer(self):
      sniff(prn=packet_callback, count=10)
    
    
    def execute(self):
        self.logo()
        self.network_sniffer()
        
        
        
        return f"[+] Sniffing packets ..."
    