import socket
from collections import OrderedDict

MODULE_TYPE = "recon"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Bannergrabber',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Scans and captures banners.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('Enter target IP (e.g., Ip address)', True, 'HTTP SERVER IP')),
                ('PORT', ('', True, 'PORT')),
               
                ])
                }
    def logo(self):
    	title = ''
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> set PORT <port> ,then run")
   
    def banner_grabber(self,target_ip, port):
      s = socket.socket()
      s.connect((target_ip, port))
      banner = s.recv(1024)
      print(banner.decode())
      s.close()
    
    def execute(self):
        target_ip = self.info['Options']['RHOST'][0]
        port = self.info['Options']['PORT'][0]
        self.banner_grabber(target_ip, port)
        
        return "[+] Grabbing Banners ..."
    