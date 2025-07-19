import pyfiglet
from collections import OrderedDict

MODULE_TYPE = "exploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Screenshot Grabber',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Persistence Module for payloads on Target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('', False,'Enter target IP')),
           
               
                ])
                }
    def logo(self):
    	title = 'Screenshot Grabber'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> , then run")
   
    from PIL import ImageGrab
    def screenshot_grabber(self,host=None):
      screenshot = ImageGrab.grab()
      screenshot.save("screenshot.png")
    
    
    def execute(self):
        self.logo()
        host = self.info['Options']['RHOST'][0]
        self.screenshot_grabber(host=None)
        
        return f"[+] Grabbing screenshots ..."
    