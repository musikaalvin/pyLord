MODULE_TYPE = "auxiliary"
import socket
import threading
from collections import OrderedDict
import pyfiglet
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'pyIntercepter',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Intercepts raw socket data between server and client',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('192.168.43.1', True, 'target ip')),
                ('LHOST', ('127.0.0.1', True, 'Your ip')),
                ('RPORT', ('', True, '(rport')),
                ('LPORT', ('', True, '(lport')),
                
                ])
                }
    def help(self):
        print("Usage: set RHOST <target_ip> | set RPORT<rport> | set LHOST <your_ip> | set LPORT<lport> then run")    	    
    def logo(self):
    	title = 'pyIntercepter'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    
    def forward(self,source, destination, direction):
      try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            # Print intercepted data with direction info
            print(f"[{direction}] {data}")
            destination.sendall(data)
      except Exception as e:
        print(f"Error in forwarding ({direction}): {e}")
      finally:
        source.close()
        destination.close()   
        
    def handle_client(self,client_socket,REMOTE_PORT,REMOTE_HOST):
      try:
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((REMOTE_HOST, REMOTE_PORT))
      except Exception as e:
        print(f"Could not connect to remote server: {e}")
        client_socket.close()
        return

    # Create threads for bidirectional data forwarding
      t1 = threading.Thread(target=self.forward, args=(client_socket, remote_socket, "Client -> Server"))
      t2 = threading.Thread(target=self.forward, args=(remote_socket, client_socket, "Server -> Client"))
      t1.start()
      t2.start()
      
    def main(self,LOCAL_HOST, LOCAL_PORT,REMOTE_PORT,REMOTE_HOST):
      server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      server.bind((LOCAL_HOST, LOCAL_PORT))
      server.listen(5)
      print(f"[*] Listening on {LOCAL_HOST}:{LOCAL_PORT}")
      print(f"[*] Forwarding traffic to {REMOTE_HOST}:{REMOTE_PORT}")

      while True:
        client_socket, addr = server.accept()
        print(f"[+] Accepted connection from {addr}")
        client_handler = threading.Thread(target=self.handle_client, args=(client_socket,REMOTE_PORT,REMOTE_HOST))
        client_handler.start()
        
    def execute(self):
        self.logo()
        REMOTE_PORT= self.info['Options']['RPORT'][0]
        REMOTE_HOST = self.info['Options']['RHOST'][0]
        LOCAL_PORT= self.info['Options']['LPORT'][0]
        LOCAL_HOST = self.info['Options']['LHOST'][0]
        
        self.main(LOCAL_HOST, LOCAL_PORT,REMOTE_PORT,REMOTE_HOST)
        
        return "[+] cracking credentials ..."
    