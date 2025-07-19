MODULE_TYPE = "auxiliary"
from fabric import Connection, task
import sys
from collections import OrderedDict
import pyfiglet
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'SSH+FTP Bruter ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Bruteforces wifi passwords given a wordlistFile',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                (None, ('', False, ''))
                ])
                }
    def help(self):
        print("Usage: set RHOST <ip> | set WORDLIST <path/to/file> | set SERVICE <ssh/ftp> then run")    	    
    def logo(self):
    	title = 'SSH+FTP Bruter'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    
    # Load credentials
    def load_hosts(self):
      hosts = []
      passwords = {}

      with open("/sdcard/msf/ftpcreds.txt", "r") as file:
        for line in file:
            host, passwd = line.strip().split(':')
            hosts.append(host)
            passwords[host] = passwd

      return hosts, passwords
        
    # Run remote command
    def run_command(self,conn, command):
      try:
        result = conn.sudo(command) if command.startswith("sudo") else conn.run(command)
        return result.stdout.strip()
      except Exception as e:
        return f"Error: {e}"
        
    # Check if hosts are online
    def check_hosts(self,hosts, passwords):
      running_hosts = {}

      for host in hosts:
        try:
            conn = Connection(host, connect_kwargs={"password": passwords[host]})
            result = conn.run("uptime", hide=True)
            running_hosts[host] = result.stdout.strip()
        except Exception:
            running_hosts[host] = "Host Down"

      return running_hosts
    
    # Get selected hosts
    def get_hosts(self,hosts):
      selected_hosts = []
      indices = input("[☆] Hosts (e.g., 0 1): ").split()

      for index in indices:
        try:
            selected_hosts.append(hosts[int(index)])
        except (ValueError, IndexError):
            print(f"Invalid host index: {index}")

      return selected_hosts
    
    # Menu function
    def menu(self):
      hosts, passwords = self.load_hosts()
      running_hosts = self.check_hosts(hosts, passwords)

      while True:
        print("\nMenu:")
        print("[0] List Hosts")
        print("[1] Run Command")
        print("[2] Open Shell")
        print("[3] Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == "0":
            print("\nAvailable Hosts:")
            for i, host in enumerate(hosts):
                status = running_hosts.get(host, "Unknown")
                print(f"[{i}] {host} - {status}")

        elif choice == "1":
            cmd = input("Command: ").strip()
            selected = self.get_hosts(hosts)

            for host in selected:
                conn = Connection(host, connect_kwargs={"password": passwords[host]})
                result = run_command(conn, cmd)
                print(f"\n[{host}]: {cmd}\n{'-'*10}\n{result}\n")

        elif choice == "2":
            host_index = input("Select Host Index: ").strip()

            try:
                host = hosts[int(host_index)]
                conn = Connection(host, connect_kwargs={"password": passwords[host]})
                conn.open()
            except (ValueError, IndexError):
                print("Invalid host index.")

        elif choice == "3":
            print("Exiting...")
            sys.exit(0)

        else:
            print("Invalid choice! Please select a valid option.")
            
    def execute(self):
        self.logo()
        self.menu()
        
        return "[+] Running ..."
    