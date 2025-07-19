import rich.traceback
# Install Rich's traceback handler
rich.traceback.install(theme=None,indent_guides = True,show_locals=True, extra_lines=3,max_frames=15,word_wrap=True)
import sys,click
import pyfiglet
from incremental import Version
from rich import print as rich_print
from prompt_toolkit.shortcuts import confirm
from rich.console import Console as rich_Console
from pymetasploit import *

rich_console = rich_Console()
__version__ = Version("pyMetasploit", 2025, 1, 0)
__all__ = ["__version__"]

attempts = 3

def logo():
    	title = 'Cred Login'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[90m{ascii_text}\033[0m")
    	else:
            print(title)
logo()

def Authorize(user,password):
        if user == 'pyLord' and password == 'kentwing':
            click.echo(f"Welcome, {user}!\n")
            if confirm("Do you want to proceed?"):
                console = FrameworkConsole()
                console.start()
            else:
                print("\033[1;31m⚠ Exiting program ...")
                exit(1)
    
            
            
        
        else:           
            rich_console.print("⚠ Access Denied !", style="bold red")
            return
            
if __name__ == "__main__":
    attempts = 3
    user = input('\nUser: ')
    for i in range(0,attempts):
      password = prompt("Enter password: ", is_password=True)
      Authorize(user,password)
      attempts = int(attempts) -1
      
      if attempts == 0:
        break
        sys.exit(0)