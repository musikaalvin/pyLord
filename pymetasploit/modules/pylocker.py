MODULE_TYPE = "nop"
from cryptography.fernet import Fernet
from time import sleep
from collections import OrderedDict
import pyfiglet,os

# colors
cyan = "\033[0;36m"
red = "\033[0;31m"
cyan = "\033[1;36m"
blue = "\033[1;34m"
green = "\033[1;32m"
yellow = "\033[1;33m"
white =  "\033[1;37m"
pink = "\033[1;35m"
purple = "\033[95m"

# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'pyLocker ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Encrypts/Decrypts Files',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([          
                ('OPT', ('', False, '(Choose an option: )'))              
                ])
                }
    def help(self):
        print("Usage: set OPT <1,2,3,4> then run")    	    
    def logo(self):
    	title = 'pyLocker'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    
    def generate_key(self):
      """Generates a new encryption key."""
      key = Fernet.generate_key()
      with open('/sdcard/ac/ENCRYPTED_DATA.key', 'wb') as key_file:
        key_file.write(key)
        
    def load_key(self):
      """Loads the encryption key from a file."""
      return open('/sdcard/ac/ENCRYPTED_DATA.key', 'rb').read()
    
    def encrypt_file(self,filename, key):
      """Encrypts a file using the given key."""
      fernet = Fernet(key)
      with open(filename, 'rb') as f:
        data = f.read()
      encrypted_data = fernet.encrypt(data)
      with open(filename + '.msk', 'wb') as f:
        f.write(encrypted_data)
        
    def decrypt_file(self,filename, key):
      """Decrypts a file using the given key."""
      fernet = Fernet(key)
      with open(filename, 'rb') as f:
        encrypted_data = f.read()
      decrypted_data = fernet.decrypt(encrypted_data)
      with open(filename[:-4], 'wb') as f:
        f.write(decrypted_data)
        
    def execute(self):
      
        #choice = self.info['Options']['OPT'][0]
        
      while True:
        sleep(0.2)
        self.logo()
        
        print(red+'['+yellow+'%'+red+']'+green+'Choose an option:')
        print(red+'['+white+'1.'+red+']'+cyan+' Generate new key')
        print(red+'['+white+'2.'+red+']'+cyan+' Encrypt file 🔐 ')
        print(red+'['+white+'3.'+red+']'+cyan+' Decrypt file 🔑 ')
        print(red+'['+white+'❌'+red+']'+cyan+' Exit')
        choice = input(red+'['+yellow+'?'+red+']'+green+'Enter your choice: ')

        if choice == '1':
            self.generate_key()
         
            print("New key generated successfully!")
            sleep(0.5)
        elif choice == '2':
            filename = input(red+'['+white+'1.'+red+']'+cyan+'Enter filename to encrypt: ')
            key = self.load_key()  # Load the key from file
            self.encrypt_file('/sdcard'+filename, key)
            sleep(0.1)
            print(red+'['+white+'$'+red+']'+cyan+' Encrypting :'+white+str(filename)+' ...')
            sleep(0.2)
            print(white+str(filename)+".msk"+purple+" encrypted successfully!")
            sleep(0.5)
        elif choice == '3':
            filename = input(red+'['+white+'$'+red+']'+cyan+'Enter filename to decrypt: ')
            key = self.load_key()  # Load the key from file
            self.decrypt_file('/sdcard/'+filename, key)
            sleep(0.1)
            print(red+'['+white+'$'+red+']'+cyan+' Decrypting :'+white+str(filename)+'.msk ...')
            sleep(0.2)
            print(white+str(filename)+""+purple+" decrypted successfully!")
            sleep(0.5)
        elif choice == 'x':
            print(red+'['+white+'$'+red+']'+yellow+'GOOD BYE! '+red+'exiting ...')
            return
        else:
            print(yellow+'['+red+'!'+yellow+']'+pink+'Invalid choice. Please try again.')
            sleep(0.5)
        
      return "[+] running ..."
    