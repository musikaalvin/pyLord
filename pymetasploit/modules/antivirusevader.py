import base64,pyfiglet
from collections import OrderedDict

MODULE_TYPE = "evasion"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Antivirus Evader',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Steganography  Payload Hider.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Note':'This script is for educational purposes only',
            'Options': OrderedDict([
            ('RHOST', ('Enter target IP', False,'')),
            
               
                ])
                }
    def logo(self):
    	title = 'Antivirus Evader'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set FILE <path/to/payload> ,then run")
   
    def anti_virus_evasion(self,file_path):
      with open(file_path, "rb") as f:
        encoded = base64.b64encode(f.read())
      with open("encoded_payload.txt", "wb") as f:
        f.write(encoded)
    
    
    def execute(self):
        self.logo()
        file_path = self.info['Options']['FILE'][0]
        self.anti_virus_evasion(file_path)
        
        
        
        return f"[+] Encoding payload..."
    