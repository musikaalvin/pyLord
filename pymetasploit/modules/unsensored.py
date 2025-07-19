MODULE_TYPE = "chatgpt"
try:
    import torch
    from transformers import GPT2Tokenizer, GPT2Model
    from typing import List
    import re
except:
    pass
from collections import OrderedDict
import pyfiglet

class UnsensoredChatGPT:
    def __init__(self, model_name: str = "gpt2"):
        self.tokenizer = GPT2Tokenizer.from_pretrained(model_name)
        self.model = GPT2Model.from_pretrained(model_name)

    def respond(self, prompt: str, max_length: int = 1024, temperature: float = 1.0) -> str:
        input_ids = self.tokenizer.encode(prompt, return_tensors='pt')
        output = self.model.generate(
            input_ids,
            max_length=max_length,
            temperature=temperature,
            top_k=100,  
            top_p=0.95,
            do_sample=True
        )
        response = self.tokenizer.decode(output[0], skip_special_tokens=True)
        return self.filter_response(response)

    def respond_depraved(self, prompt: str, max_length: int = 1024, temperature: float = 1.0, **kwargs) -> str:

        return self.respond(prompt, max_length=max_length*1.5, temperature=temperature, **kwargs)

    def filter_response(self, response: str) -> str:
       
        filtered_response = re.sub(r'\b(offensive|hateful|harmful|inappropriate)\b', '[CENSORED]', response, flags=re.IGNORECASE)
        return filtered_response

def main():
    chatgpt = UnsensoredChatGPT()

    while True:
        user_input = input("User: ")

        if user_input.lower() in ["quit", "exit"]:
            break

        response = chatgpt.respond(user_input)
        print("ChatGPT: ", response)

        # Check for depraved response request
        if user_input.lower().startswith("try again "):
            if "unsensored" in user_input.lower() or "unfiltered" in user_input.lower():
                response = chatgpt.respond_depraved(user_input)
                print("**EXTREME RESPONSE**\nChatGPT: ", response)

# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Unsensoredgpt ',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'Unsensored gpt in python, but with option for sensored if needed',
            'Note':'**WARNING: EXTREMELY UNFILTERED RESPONSES**',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([          
                ('OPT', ('', False, '(Choose an option: )'))              
                ])
                }
    def help(self):
        print("Usage: run")    	    
    def logo(self):
    	title = 'Unsensoredgpt'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    
   
        
    def execute(self):
        self.logo()
        gpt = UnsensoredChatGPT()
        gpt.main()
        
        
        return "[+] running ..."
    