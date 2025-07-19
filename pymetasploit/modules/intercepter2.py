MODULE_TYPE = "auxiliary"
import socket
import datetime
from collections import OrderedDict
import pyfiglet
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'pyIntercepter2',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'TCP data interceptor using Pythons socket module that doesnt require root privileges (works for local traffic monitoring) ',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('SIZE', ('1024', False, 'MAX_DATA_SIZE')),
                ('LHOST', ('127.0.0.1', True, '#Localhost only')),
                ('TIME', ('10', False, 'TIMEOUT #Seconds')),
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
    
    def simple_tcp_interceptor(self,PORT,HOST,MAX_DATA_SIZE,TIMEOUT):
    # Create TCP socket
      listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
      try:
        listener.bind((HOST, PORT))
        listener.listen(1)
        print(f"🐻 Simple TCP Interceptor started on {HOST}:{PORT}")
        print("Press Ctrl+C to stop\n")
        
        while True:
            client_socket, addr = listener.accept()
            client_socket.settimeout(TIMEOUT)
            
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] Connection from: {addr[0]}:{addr[1]}")
            
            try:
                while True:
                    data = client_socket.recv(MAX_DATA_SIZE)
                    if not data:
                        break
                        
                    # Display received data
                    print(f"Received {len(data)} bytes:")
                    print(data.decode('utf-8', errors='replace') + "\n" + "-"*40)
                    
            except socket.timeout:
                print("Connection timed out")
            finally:
                client_socket.close()
                
      except KeyboardInterrupt:
        print("\nInterceptor stopped")
      finally:
        listener.close()
        
    def execute(self):
        self.logo()
        PORT= self.info['Options']['LPORT'][0]
        HOST = self.info['Options']['LHOST'][0]
        MAX_DATA_SIZE= self.info['Options']['SIZE'][0]
        TIMEOUT = self.info['Options']['TIME'][0]
        
        self.simple_tcp_interceptor(PORT,HOST,MAX_DATA_SIZE,TIMEOUT)
        
        return "[+] cracking credentials ..."
    