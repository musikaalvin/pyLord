import os,pyfiglet
from collections import OrderedDict

MODULE_TYPE = "evasion"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Sandbox Detector',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Sandbox detecting payload.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Note':'This script is for educational purposes only',
            'Options': OrderedDict([
            ('RHOST', ('Enter target IP', False,'')),
            
               
                ])
                }
    def logo(self):
    	title = 'Sandbox Detector'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> ,then run")
   
    def sandbox_detection(self,url=None):
      if os.path.exists("C:\\Windows\\System32\\drivers\\vmmouse.sys"):
        print("Sandbox detected!")
      else:
        print("No sandbox detected.")
    
    
    def execute(self):
        self.logo()
        url = self.info['Options']['RHOST'][0]
        self.sandbox_detection(url=None)
        
        
        
        return f"[+] Detecting Sandbox..."
    