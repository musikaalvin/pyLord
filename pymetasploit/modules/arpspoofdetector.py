from scapy.all import sniff, ARP
import time,pyfiglet
from collections import OrderedDict

MODULE_TYPE = "defensive"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Arpspoofer detector',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos/Android',
            'architectures':'x86/64 bit processors',
            'Description': 'A simple python arpspoofer detector',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Note':'This script is for Protecting systems against common threats',
            'Options': OrderedDict([
            ('INTERFACE', ('wlan0', False,'wlan0/eth0 etc.')),
            
               
                ])
                }
    def logo(self):
    	title = 'Arpspoofer detector'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set INTERFACE <interface_name> ,then run")
   
    def detect_arp_spoofing(self,interface):
      print(f"[*] Monitoring {interface} for ARP spoofing...")
      def process_packet(packet):
        if packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP response
                print(f"[!] Possible ARP spoofing detected: {packet[ARP].psrc} is at {packet[ARP].hwsrc}")

      sniff(iface=interface, prn=process_packet, store=False)
    
    
    def execute(self):
        self.logo()
        interface = self.info['Options']['INTERFACE'][0]
        self.detect_arp_spoofing(interface)
        return f"[+] Listening on {interface} ..."
    