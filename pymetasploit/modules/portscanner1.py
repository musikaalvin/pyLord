# MODULE_TYPE specifies the category (exploit, payload, auxiliary, encoder, cracker, postexploit, evade, nop, recon)
MODULE_TYPE = "auxiliary"
from collections import OrderedDict
import time
# Module class definition
class ModuleClass:
    def __init__(self):
        #self.scan = connScan(target,int(port))
        self.info = {
            'Name': 'simple port scanner',
            'Rank':'Fair',
            'Platform':'Windows/Linux',
            'Description': 'Scans for open ports on target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Options': OrderedDict([
                ('TARGET',('', True, 'Target IP')),
                ('PORTS', ('', True, 'Target Port')),
               
            ])
        }

    def help(self):
        print("Usage: set TARGET <IP> | set PORTS <PORT> <type> then run")

    def connScan(self,tgtHost, tgtPort):
    	
    	try:
    		connSkt = socket(AF_INET, SOCK_STREAM)
    		connSkt.connect((tgtHost, int(tgtPort)))
    		print ('[+]%d/tcp open'% tgtPort)
    		connSkt.close()
    	except:
    		print ('[-]%d/tcp closed'% tgtPort)
    def portScan(self,tgtHost, tgtPorts):
    	try:
    		tgtIP = gethostbyname(tgtHost)
    	except:
    		print ("[-] Cannot resolve '%s': Unknown host"%tgtHost)
    	return
    	
    	try:
    		tgtName = gethostbyaddr(tgtIP)
    		print ('\n[+] Scan Results for: ' + tgtName[0])
    	except:
    			print ('\n[+] Scan Results for: ' + tgtIP)
    			setdefaulttimeout(1)
    			for tgtPort in tgtPorts:
    				print ('Scanning port ' + tgtPort)
    				connScan(tgtHost, int(tgtPort))
    	
    
    def execute(self):
        target = self.info['Options']['TARGET'][0]
        port = self.info['Options']['PORTS'][0]
        
       

        time.sleep(0.2)
        print(f"[+] Scanning {target}:{port}  ...")
        time.sleep(0.2)
        print("[+] please wait a sec...")
        time.sleep(0.2)
        #self.scan(target,int(port))
        self.connScan(target,int(port))
        
        return "[OK] Scan successfull."
    