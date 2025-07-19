import pyfiglet
from collections import OrderedDict
import http.server
import socketserver

MODULE_TYPE = "payload"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Http Server',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Hosts Target Storage',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('', False,'Enter IP')),
            ('PORT', ('', False,'Enter Port'))
           
               
                ])
                }
    def logo(self):
    	title = 'Http Server'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> | set PORT <port> , then run")
   
    Handler = http.server.SimpleHTTPRequestHandler
    def Host(self,host,PORT):
    	with socketserver.TCPServer((host, PORT), Handler) as httpd:
    		print("serving at port", PORT)
    		httpd.serve_forever()
    
    
    def execute(self):
        self.logo()
        host = self.info['Options']['RHOST'][0]
        self.Host(host,PORT)
        
        return f"[+] Hosting data ..."
    