from PIL import Image
from collections import OrderedDict
import pyfiglet

MODULE_TYPE = "evasion"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Payload hider',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Steganography  Payload Hider.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('FILE', (' ', True,'/path/to/image')),
            ('PAYLOAD', ('Evader.py', True, ''))
               
                ])
                }
    def logo(self):
    	title = 'Payload hider'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set FILE <path/to/imageFile> set PAYLOAD <your/payload> ,then run")
   
    from PIL import Image
    def steganography_evasion(self,image_path, payload):
      img = Image.open(image_path)
      encoded = img.copy()
      encoded.putdata([ord(c) for c in payload])
      encoded.save("payload_image.png")
    
    
    def execute(self):
        self.logo()
        image_path = self.info['Options']['FILE'][0]
        payload = self.info['Options']['PAYLOAD'][0]
        
        self.steganography_evasion(image_path, payload)
        
        return f"[+] Hiding {payload} in {image_path}  ..."
    