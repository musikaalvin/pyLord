#!/usr/bin/python
import pcapy
import pyfiglet
from collections import OrderedDict

MODULE_TYPE = "auxiliary"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'pyPcap',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos/Android',
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
    	title = 'pyPcap'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: type run")
        
    def execute(self):
        self.logo()
        devices = pcapy.findalldevs()
        print(devices)
        packets = pcapy.open_live("eth0", 1024, False, 100)
        dumper = packets.dump_open("/sdcard/msf/sniffed_packets.pcap")
        count = 1
        while count:
            try:
                packet = packets.next()
            except:
                continue
            else:
                print (packet)
                count = count + 1
                if count == 10:
                    break
        
        
        
        return f"[+] Capturing packets ..."
    