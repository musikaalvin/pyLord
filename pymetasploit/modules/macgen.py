MODULE_TYPE = "recon"
import random
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Random Mac Generator Lite',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Generates Random Mac Addresses with OUI',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('', ('', False, 'run')),
                
                ])
                }
    def help(self):
    	print("Usage:  type  run")
    	
    def Macgen(self,oui):
    	# Generate the last 3 bytes of the MAC address
    	last_bytes = [random.randint(0x00, 0xff) for _ in range(3)]
    	# Concatenate the OUI and the last 3 bytes to form the MAC address
    	mac_address = oui + ":" + ":".join('{:02x}'.format(byte) for byte in last_bytes)
    	return mac_address   
    
    def execute(self):
        TARGET_OUI = "00:50:C2"
        mac_with_oui = self.Macgen(TARGET_OUI)        
        return print(mac_with_oui)
    