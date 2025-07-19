# MODULE_TYPE specifies the category (exploit, payload, auxiliary, encoder, cracker, postexploit, evade, nop, recon)
import hashlib
from collections import OrderedDict
MODULE_TYPE = "cracker"

# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'sha256_hasher',
            'Description': 'Hashes plain text to sha256 hash ',
            'Author': 'cyb3rH4ck3r',
            'Options': OrderedDict([
                ('TEXT', ('', True, 'Text/word to hash')),
                
            ])
        }

    def help(self):
        print("Usage: set TEXT <your_text> then run")

    def execute(self):
        text = self.info['Options']['TEXT'][0]
        

        file = hashlib.sha256(text.encode())
        output = file.hexdigest()
        print(f"[+] Hashing {text}...")
        
        return f"[+] {text} hashed successfully. OUTPUT : {output}"