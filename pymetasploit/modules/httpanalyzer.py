import pyfiglet
from collections import OrderedDict
import requests

MODULE_TYPE = "recon"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'HTTP Header Analyzer',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Analyses http headers from Target url',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('URL', ('',True,'target_url')),
           
               
                ])
                }
    def logo(self):
    	title = 'Header Analyzer'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set URL <target_url> , then run")
   
    def http_header_analyzer(self,url):
      response = requests.get(url)
      for header, value in response.headers.items():
        print(f"{header}: {value}")
    
    
    def execute(self):
        self.logo()
        url = self.info['Options']['URL'][0]
        self.http_header_analyzer(url)
        
        return f"[+] Analyzing headers from {url} ..."
    