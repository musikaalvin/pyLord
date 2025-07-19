from cryptography.fernet import Fernet
from time import sleep
from impt import *
import pyfiglet
from colors import *

def logo():
	#text = input("Enter the text: ")
	text = "KENT LOCKER"
	
	#font = input("Enter the font style (optional): ")    
	font = "standard"
	
	ascii_text = pyfiglet.figlet_format(text, font=font)
	print(ascii_text+"                                        v1.0 by alvin kent")
#count = -+1
def generate_key():
    """Generates a new encryption key."""
    key = Fernet.generate_key()
    with open('/sdcard/ac/ENCRYPTED_DATA.key', 'wb') as key_file:
        key_file.write(key)#.decode())
        #if os.path.isfile(key_file):
        #	pass

def load_key():
    """Loads the encryption key from a file."""
    return open('/sdcard/ac/ENCRYPTED_DATA.key', 'rb').read()

def encrypt_file(filename, key):
    """Encrypts a file using the given key."""
    fernet = Fernet(key)
    with open(filename, 'rb') as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(filename + '.msk', 'wb') as f:
        f.write(encrypted_data)

def decrypt_file(filename, key):
    """Decrypts a file using the given key."""
    fernet = Fernet(key)
    with open(filename, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(filename[:-4], 'wb') as f:
        f.write(decrypted_data)

if __name__ == "__main__":
    while True:
        os.system('clear')
        sleep(0.2)
        logo()
        print(red+'['+yellow+'%'+red+']'+green+'Choose an option:')
        print(red+'['+white+'1.'+red+']'+cyan+' Generate new key')
        print(red+'['+white+'2.'+red+']'+cyan+' Encrypt file 🔐 ')
        print(red+'['+white+'3.'+red+']'+cyan+' Decrypt file 🔑 ')
        print(red+'['+white+'❌'+red+']'+cyan+' Exit')
        choice = input(red+'['+yellow+'?'+red+']'+green+'Enter your choice: ')

        if choice == '1':
            generate_key()
         
            print("New key generated successfully!")
            sleep(0.5)
        elif choice == '2':
            filename = input(red+'['+white+'1.'+red+']'+cyan+'Enter filename to encrypt: ')
            key = load_key()  # Load the key from file
            encrypt_file('/sdcard'+filename, key)
            sleep(0.1)
            print(red+'['+white+'$'+red+']'+cyan+' Encrypting :'+white+str(filename)+' ...')
            sleep(0.2)
            print(white+str(filename)+".msk"+purple+" encrypted successfully!")
            sleep(0.5)
        elif choice == '3':
            filename = input(red+'['+white+'$'+red+']'+cyan+'Enter filename to decrypt: ')
            key = load_key()  # Load the key from file
            decrypt_file('/sdcard/'+filename, key)
            sleep(0.1)
            print(red+'['+white+'$'+red+']'+cyan+' Decrypting :'+white+str(filename)+'.msk ...')
            sleep(0.2)
            print(white+str(filename)+""+purple+" decrypted successfully!")
            sleep(0.5)
        elif choice == 'x':
            print(red+'['+white+'$'+red+']'+yellow+'GOOD BYE! '+red+'exiting ...')
            break
        else:
            print(yellow+'['+red+'!'+yellow+']'+pink+'Invalid choice. Please try again.')
            sleep(0.5)

