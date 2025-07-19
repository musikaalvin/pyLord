import ssl
import socket
from collections import OrderedDict

MODULE_TYPE = "recon"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'SSL Scanner',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Scans for ssl certs.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('target IP (e.g., Ip address)', True, 'IP ADDRESS')),
                ('PORT', ('', True, 'PORT')),
               
                ])
                }
    def logo(self):
    	title = 'ssl scanner'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> set PORT <port> ,then run")
   
    def ssl_scanner(self,target_ip, port):
    	context = ssl.create_default_context()
    	with socket.create_connection((target_ip, port)) as sock:
    	       with context.wrap_socket(sock, server_hostname=target_ip) as sock:
    	       	print(sock.version())
    
    def execute(self):
        self.logo()
        target_ip = self.info['Options']['RHOST'][0]
        port = self.info['Options']['PORT'][0]
        self.ssl_scanner(target_ip, port)
        
        return "[+] Scanning ..."
    