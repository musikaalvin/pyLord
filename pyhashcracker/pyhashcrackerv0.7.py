import os
import hashlib
import re
import tkinter as tk
from tkinter import messagebox, ttk, filedialog,scrolledtext
import time
import threading
from itertools import product, combinations
from collections import deque
from collections import *
import sqlite3
from passlib.hash import bcrypt, pbkdf2_sha256, argon2, sha512_crypt
import json
import logging
import string
import itertools
import math
import sqlite3
from itertools import islice

class HashCrackerCore:
    def __init__(self):
        self.algorithms = {
            'md5': self.check_md5,
            'sha1': self.check_sha1,
            'sha256': self.check_sha256,
            'sha512': self.check_sha512,
            'bcrypt': self.check_bcrypt,
            'pbkdf2_sha256': self.check_pbkdf2,
            'argon2': self.check_argon2,
            'ntlm': self.check_ntlm,
            'md4': self.check_md4,
            'sha3_256': self.check_sha3_256,
        }

        self.rule_transforms = {
            'l': lambda x: [x.lower()],
            'u': lambda x: [x.upper()],
            'c': lambda x: [x.capitalize()],
            'C': lambda x: [x[0].lower() + x[1:].upper()] if len(x) > 1 else [x.lower()],
            't': lambda x: [x.swapcase()],
            's': lambda x: [x + x[-1]] if x else [x],
            '$': lambda x: [x + str(i) for i in range(10)],
            '^': lambda x: [str(i) + x for i in range(10)],
            'd': lambda x: [x + x],
            'f': lambda x: [x + x[::-1]],
            'p': lambda x: [''.join(p) for p in itertools.permutations(x)],
            'r': lambda x: [x[::-1]],
        }

        self.mask_charsets = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': string.punctuation,
            '?a': string.printable,
            '?b': ''.join(chr(i) for i in range(256))
        }

    def detect_hash_type(self, hash_str):
        hash_patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'sha512': r'^[a-f0-9]{128}$',
            'bcrypt': r'^\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}$',
            'pbkdf2_sha256': r'^\$pbkdf2-sha256\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$',
            'argon2': r'^\$argon2(id|d|i)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
            'ntlm': r'^[a-f0-9]{32}$',
            'md4': r'^[a-f0-9]{32}$',
            'sha3_256': r'^[a-f0-9]{64}$',
        }
        for algo, pattern in hash_patterns.items():
            if re.match(pattern, hash_str, re.IGNORECASE):
                return algo
        return 'unknown'

    def check_sha3_256(self, password, target_hash ):
        return hashlib.sha3_256(password.encode()).hexdigest() == self.target_hash 

    def check_md4(self, password, target_hash ):
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest() == self.target_hash 

    def check_md5(self, password, target_hash ):
        return hashlib.md5(password.encode()).hexdigest() == self.target_hash 

    def check_sha512(self, password, target_hash ):
        return hashlib.sha512(password.encode()).hexdigest() == self.target_hash 

    def check_sha1(self, password, target_hash ):
        return hashlib.sha1(password.encode()).hexdigest() == self.target_hash 

    def check_sha256(self, password, target_hash ):
        return hashlib.sha256(password.encode()).hexdigest() == self.target_hash 

    def check_bcrypt(self, password, target_hash ):
        try:
            return bcrypt.verify(password, self.target_hash )
        except:
            return False

    def check_pbkdf2(self, password, target_hash ):
        try:
            return pbkdf2_sha256.verify(password, self.target_hash )
        except:
            return False

    def check_argon2(self, password, target_hash ):
        try:
            return argon2.verify(password, self.target_hash )
        except:
            return False

    def check_ntlm(self, password, target_hash ):
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest() == self.target_hash .lower()

    def generate_masks(self, pattern):
        charsets = []
        i = 0
        while i < len(pattern):
            if pattern[i] == '?':
                cs = self.mask_charsets.get(pattern[i:i+2], '')
                if cs:
                    charsets.append(cs)
                else:
                    charsets.append([pattern[i]])
                i += 2
            else:
                charsets.append([pattern[i]])
                i += 1
        return itertools.product(*charsets)

    def benchmark(self):
        results = {}
        test_password = "benchmark_test"
        for algo in self.algorithms:
            if algo in ['bcrypt', 'pbkdf2_sha256', 'argon2']:
                iterations = 10
            else:
                iterations = 10000
            start = time.time()
            for _ in range(iterations):
                if algo == 'bcrypt':
                    bcrypt.hash(test_password)
                elif algo == 'pbkdf2_sha256':
                    pbkdf2_sha256.hash(test_password)
                elif algo == 'argon2':
                    argon2.hash(test_password)
                else:
                    hashlib.new(algo, test_password.encode()).hexdigest()
            results[algo] = (time.time() - start) / iterations
        return results

    def apply_rules(self, word, rules):
        variants = [word]
        for rule in rules:
            if rule in self.rule_transforms:
                new_variants = []
                for variant in variants:
                    new_variants.extend(self.rule_transforms[rule](variant))
                variants = list(set(new_variants))
        return variants

class Hashcracker(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.core = HashCrackerCore()
        self.running = False
        self.paused = False
        self.update_queue = deque()
        self.wordlist_path = ""
        self.rules = []
        self.total_combinations = 0
        self.processed = 0
        self.start_time = 0
        self.init_rainbow_db()
        #self.init_ui()
        self.configure_ui()
        self.setup_vars()
        self.create_widgets()
        self.style_config()
        self.hash_to_crack = ""
        self.cracking = False
        self.paused = threading.Event()
        self.total_passwords = 0
        self.speed = 0
        self.last_update = 0
        self.process_updates()
        self.rules = []
        self.password = ""
        self.file_path = '/sdcard/pass.txt'
        #self.file_entry = '/sdcard/rainbowtable.txt'
        
        #  help =   b7463760284fd06773ac2a48e29b0acf
        
        self.wordlist_file = '/sdcard/pass.txt'

    def init_rainbow_db(self):
        self.rainbow_db = "rainbow.db"
        with sqlite3.connect(self.rainbow_db) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS hashes
                         (hash TEXT PRIMARY KEY, password TEXT)''')

    def configure_ui(self):
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('alt')
        self.style.configure('TFrame', background='#282C34')#'#1e1e1e')
        self.style.configure('TLabel', background='#282C34', foreground='white')
        self.style.configure('TButton', background='#282C34', foreground='white')
        self.style.configure('TEntry', fieldbackground='#333', foreground='white')
        self.style.configure('TCombobox', fieldbackground='#333', foreground='white')
        self.master.configure(bg="#282c34")
        self.master.title('PyHashCracker v2.0')
        self.master.geometry('700x1000')
        self.master.minsize(700, 1100)
        self.master.configure(bg="#282C34") #"#1e1e1e")

    def setup_vars(self):
        self.cracking = False
        self.paused = threading.Event()
        self.current_attack_mode = 'dictionary'
        self.wordlist = []
        self.total_passwords = 0
        self.processed = 0
        self.start_time = 0
        self.rules = []
        self.update_queue = deque()

    def style_config(self):
        self.style = ttk.Style()
        self.style.theme_use('droid')
        self.style.configure('TButton', font=('Courier', 10), foreground='blue',background='#282C34')
        self.style.configure('TCombobox', font=('Courier', 10), foreground='blue',background='#282C34')
        self.style.configure('TCheckbutton', font=('Courier', 10), foreground='blue')#,background='#282C34')
        
        self.style.map('TButton', background=[('active', '#3a3f4b')])

    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.master,bg="#282C34")
        header_frame.pack(pady=10)
        tk.Label(header_frame, text="HashCracker Pro v2.0",
                 font=("Courier New", 18, "bold"), bg="#282C34", fg="#00FF00").pack()
        tk.Label(header_frame, text="by pyLord@cyb3rh4ck3r04",
                 font=("Courier", 10), bg="#282C34", fg="#00FF00").pack()

        self.log_frame = ttk.Frame(self.master)
        self.log_frame.pack(pady=10)

        self.v_scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical")
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.console = tk.Text(self.log_frame, height=25, width=90, bg="#383a42", fg="white", wrap=tk.WORD, yscrollcommand=self.v_scrollbar.set)
        self.console.pack(side=tk.LEFT)
        self.v_scrollbar.config(command=self.console.yview)

        self.result_frame = ttk.Frame(self.master)
        self.result_frame.pack(pady=10)
        self.result_label = ttk.Label(self.result_frame, text="", style='crack2_label.TLabel',background='#282C34',foreground='#00FF00')
        self.result_label.pack(side=tk.LEFT)

        
        
        # Hash input
        hash_frame = ttk.Frame(self.master)
        hash_frame.pack(pady=5)
        ttk.Label(hash_frame, text="Target Hash:",width=10,foreground="blue").pack(side=tk.LEFT)
        self.hash_entry = ttk.Entry(hash_frame, width=35)
        self.hash_entry.pack(side=tk.LEFT, padx=5)
        
        # Mask pattern input
        mask_frame = ttk.Frame(self.master,width=38)
        mask_frame.pack(pady=5)
        ttk.Label(mask_frame, text=" Mask Pattern:",foreground="blue",width=12).pack(side=tk.LEFT)
        self.mask_entry = ttk.Entry(mask_frame, width=20)
        self.mask_entry.pack(side=tk.LEFT)
        ttk.Label(mask_frame, text="(e.g. ?l?l?l?d?d)",foreground="red",width=12).pack(side=tk.LEFT)
        
        
        
        
        
        # Brute Force Options
        brute_frame = ttk.Frame(self.master)
        brute_frame.pack(pady=10)

        # File selection
        file_frame = ttk.Frame(self.master)
        file_frame.pack(pady=5)
        # Wordlist selection
        
        #ttk.Label(file_frame, text="Dict Wordlist:").pack(side=tk.LEFT)
#        self.wordlist_entry = ttk.Entry(file_frame, width=40)
#        self.wordlist_entry.pack(side=tk.LEFT)
#        ttk.Button(file_frame, text="Browse", command=self.browse_wordlist).pack(side=tk.LEFT)
        #file      
        file_frame2 = ttk.Frame(self.master)
        file_frame2.pack(pady=5)
        ttk.Label(file_frame2, text="Wordlist:",foreground="blue").pack(side=tk.LEFT)
        self.file_entry = ttk.Entry(file_frame2, width=40)
        self.file_entry.pack(side=tk.LEFT)
        ttk.Button(file_frame2, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)

        # Advanced options
        adv_frame = ttk.Frame(self.master)
        adv_frame.pack(pady=5)
        self.gpu_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(adv_frame, text="GPU Acceleration", variable=self.gpu_var,style="TCheckbutton").pack(side=tk.LEFT)
        ttk.Button(adv_frame, text="Load Rules", command=self.load_rules).pack(side=tk.LEFT, padx=5)#,bg="#282C34",fg="white")
        ttk.Button(adv_frame, text="Benchmark", command=self.run_benchmark).pack(side=tk.LEFT)

        #attempts
        status_frame = tk.Frame(self.master,width=50)
        status_frame.pack(pady=5)
        
        #progress
        progress_frame = tk.Frame(self.master)
        progress_frame.pack(pady=5)
        self.progress_label = ttk.Label(progress_frame, text="0%", style="TLabel",foreground="blue")
        self.progress_label.pack(side=tk.LEFT, padx=5)
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT)

        time_frame = tk.Frame(self.master)
        time_frame.pack(pady=5)
        self.elapsed_label = ttk.Label(time_frame, text="Elapsed: 00:00:00", style="TLabel",foreground="blue")
        self.elapsed_label.pack(side=tk.LEFT, padx=5)
        self.remaining_label = ttk.Label(time_frame, text="Remaining: --:--:--", style="TLabel",foreground="blue")
        
        self.remaining_label.pack(side=tk.LEFT, padx=5)
        #self.remaining_label.config(background="#282C34")

        btn_frame = tk.Frame(self.master)
        btn_frame.pack(pady=10)
        self.toggle_btn = tk.Button(btn_frame, text="♻ Start Cracking", command=self.toggle_cracking, bg="cyan", fg="blue")
        self.toggle_btn.pack(side=tk.LEFT, padx=5)
        self.pause_btn = tk.Button(btn_frame, text="Pause", command=self.toggle_pause, bg="#FFFF00", fg="blue")
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        #attempts
        self.attempts_label = ttk.Label(status_frame, text="Attempts: 0/0", style="TLabel",foreground="blue",width=25)
        self.attempts_label.pack(side=tk.LEFT, padx=5)
        self.speed_label = ttk.Label(status_frame, text="Speed: 0 w/s", style="TLabel",foreground="blue")
        self.speed_label.pack(side=tk.LEFT, padx=5)
        self.mode_selector = ttk.Combobox(mask_frame,style='TCombobox', 
                                        values=['Dictionary','Normal Attack', 'Brute-force', 'Combo','Mask','Hybrid','Rainbow Table'],
                                        state='readonly',width=13)
        self.mode_selector.pack(side=tk.RIGHT, padx=5)
        self.mode_selector.set('Normal Attack')
        #self.mode_selector.config(fg='blue')

        
        
        
        
        
        ttk.Label(brute_frame, text="Min Length:",foreground="blue").pack(side=tk.LEFT,padx=4,pady=4,anchor='nw')
        self.min_length = ttk.Spinbox(brute_frame, from_=1, to=8, width=3)
        self.min_length.pack(side=tk.LEFT,padx=4,pady=4,anchor='nw')
        
        ttk.Label(brute_frame, text="Max Length:",foreground="blue").pack(side=tk.LEFT,padx=4,pady=4,anchor='nw')
        self.max_length = ttk.Spinbox(brute_frame, from_=1, to=12, width=3)
        self.max_length.pack(side=tk.LEFT,padx=4,pady=4,anchor='nw')
        
        
        
        ttk.Label(brute_frame, text="Charset:",foreground="blue").pack(side=tk.LEFT)
        self.charset_entry = ttk.Entry(brute_frame, width=25)
        self.charset_entry.insert(0, 'abcdefghijklmnopqrstuvwxyz0123456789')
        self.charset_entry.pack(side=tk.LEFT)
        #self.brute_frame.pack(pady=5)

    def apply_rules(self, word):
        variants = [word]
        for rule in self.rules:
            if rule == "l":
                variants.append(word.lower())
            elif rule == "u":
                variants.append(word.upper())
            # Add more rule implementations
        return variants
    def on_close(self):
        if self.cracking:
            if messagebox.askokcancel("Quit", "Cracking in progress. Are you sure?"):
                self.destroy()
        else:
            self.destroy()
    def browse_wordlist(self):
        filename = filedialog.askopenfilename()
        if filename:
            pass
            #self.file_entry.delete(0, tk.END)
            #self.file_entry.insert(0, filename)
    def detect_hash_type(self, hash_str):
        hash_patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'sha512': r'^[a-f0-9]{128}$',
            'bcrypt': r'^\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}$',
            'pbkdf2_sha256': r'^\$pbkdf2-sha256\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$',
            'argon2': r'^\$argon2(id|d|i)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
            'ntlm': r'^[a-f0-9]{32}$',
            'md4': r'^[a-f0-9]{32}$',
            'sha3_256': r'^[a-f0-9]{64}$',
            'crypt': r'^\$\d+\$[a-zA-Z0-9./]{1,16}\$[a-zA-Z0-9./]+'
        }

        for algo, pattern in hash_patterns.items():
            if re.match(pattern, hash_str, re.IGNORECASE):
                return algo
        return 'unknown'

    
    def check_sha3_256(self, password, target_hash ):
        return hashlib.sha3_256(password.encode()).hexdigest() == self.target_hash 
    def check_md4(self, password, target_hash ):
        return hashlib.md4(password.encode()).hexdigest() == self.target_hash 
    def check_md5(self, password, target_hash ):
        return hashlib.md5(password.encode()).hexdigest() == self.target_hash 

    def check_sha512(self, password, target_hash ):
        return hashlib.sha512(password.encode()).hexdigest() == self.target_hash 
    def check_sha1(self, password, target_hash ):
        return hashlib.sha1(password.encode()).hexdigest() == self.target_hash 
    def check_sha256(self, password, target_hash ):
        return hashlib.sha256(password.encode()).hexdigest() == self.target_hash 

    def check_bcrypt(self, password, target_hash ):
        return bcrypt.verify(password, self.target_hash )

    def check_crypt(self, password, target_hash ):
        return crypt.verify(password, self.target_hash )
    def check_pbkdf2(self, password, target_hash ):
        return pbkdf2_sha256.verify(password, self.target_hash )

    def check_argon2(self, password, target_hash ):
        return argon2.verify(password, self.target_hash )

    def check_ntlm(self, password, target_hash ):
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest() == self.target_hash .lower()

    def generate_masks(self, pattern):
        charsets = []
        for char in pattern.split('?'):
            if char in self.mask_charsets:
                charsets.append(self.mask_charsets[char])
        return itertools.product(*charsets)
    def update_timers(self):
        if not self.cracking:
            self.console.insert(tk.END, "\n ⚠ Brute Engine v0.3 Not running ...\n")
            return

        elapsed = time.time() - self.start_time
        self.elapsed_label.config(text=f"Elapsed: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")

        if self.processed > 0:
            passwords_per_sec = self.processed / elapsed
            remaining = (self.total_passwords - self.processed) / passwords_per_sec if passwords_per_sec > 0 else 0
            self.remaining_label.config(text=f"Remaining: {time.strftime('%H:%M:%S', time.gmtime(remaining))}")
            self.speed_label.config(text=f"Speed: {passwords_per_sec:.1f} w/s")

        self.master.after(1000, self.update_timers)
    def normal_cracking(self):
        if not self.validate_inputs():
            return

        self.cracking = True
        self.paused.clear()
        self.toggle_btn.config(text="⚠ Stop Cracking", bg="#FF0000")
        self.start_time = time.time()
        self.processed = 0
        self.hash_to_crack = self.hash_entry.get().strip()

        self.update_thread = threading.Thread(target=self.run_normal_attack)
        self.update_thread.daemon = True
        self.update_thread.start()
        self.update_timers()
    def start_cracking(self):
        self.target_hash  = self.hash_entry.get().strip()
        algo = self.core.detect_hash_type(self.target_hash )
        
        if not self.validate_inputs():
            return
        if self.hash_entry == "" and algo == 'unknown':
            self.queue_update(self.console.insert,tk.END,"\n[+] Please enter a hash to proceed!\n")
            #return #self.stop_cracking()
            return
        if algo == 'unknown':
            self.queue_update(self.console.insert,tk.END,"\n[+] Unknown hash type!\n")
            self.stop_cracking()
            return
        
        self.check_func = self.core.algorithms[algo]
        

        
        try:
        	self.attack_mode = self.mode_selector.get()
        except Exception as e:
            self.queue_update(self.console.insert,tk.END,f"Error: {e}")
        {
            'Dictionary': self.dictionary_attack,
            'Normal Attack': self.normal_cracking,
            'Brute-force': self.bruteforce_attack,
            'Combo': self.run_combo_attack,
            'Mask': self.mask_attack,
            'Hybrid': self.hybrid_attack,
            'Rainbow Table': self.rainbow_attack
        }[self.attack_mode]()
        
      

    def rainbow_attack(self, target_hash ):
        with sqlite3.connect(self.rainbow_db) as conn:
            cursor = conn.execute("SELECT password FROM hashes WHERE hash=?", (self.target_hash ,))
            result = cursor.fetchone()
        
        if result:
            self.queue_update(self.console.insert,tk.END,f"Password found (Rainbow): {result[0]}")
        else:
            self.queue_update(self.console.insert,tk.END,"Hash not found in rainbow table")
        self.stop_cracking()
        
    def hybrid_attack(self, target_hash , check_func):
        wordlist_file = self.file_entry.get()
        with open(wordlist_file, 'r', errors='ignore') as f:
            words = [line.strip() for line in f]
        
        # Use a set of basic rules: lowercase, uppercase, and append digits (using rule '$')
        rules = ['l', 'u', '$']
        self.total_combinations = len(words) * len(rules)
        self.progress_bar['maximum'] = self.total_combinations
        
        for i, word in enumerate(words):
            if not self.cracking:
                break
            while self.paused:
                time.sleep(0.1)
            
            variants = self.core.apply_rules(word, rules)
            for variant in variants:
                if self.check_func(variant, self.target_hash ):
                    self.queue_update(self.console.insert,tk.END,f"Password found: {variant}")
                    self.stop_attack()
                    return
            
            self.processed = (i + 1) * len(rules)
            self.update_progress()
        self.queue_update(self.console.insert,tk.END,"Password not found in hybrid attack.")
        self.stop_cracking()
    def mask_attack(self, target_hash , check_func):
        pattern = self.mask_entry.get()
        # Build charsets from the mask pattern
        charsets = []
        i = 0
        while i < len(pattern):
            if pattern[i] == '?':
                cs = self.core.mask_charsets.get(pattern[i:i+2], '')
                if cs:
                    charsets.append(cs)
                else:
                    charsets.append([pattern[i]])
                i += 2
            else:
                charsets.append([pattern[i]])
                i += 1
        total = math.prod(len(c) for c in charsets)
        self.total_combinations = total
        self.progress['maximum'] = total
        
        candidates = itertools.product(*charsets)
        for candidate in candidates:
            if not self.running:
                break
            while self.paused:
                time.sleep(0.1)
            
            password = ''.join(candidate)
            if self.check_func(password, self.target_hash ):
                self.queue_update(self.console.insert,tk.END,f"Password found: {password}")
                self.stop_cracking()
                return
            
            self.processed += 1
            if self.processed % 1000 == 0:
                self.update_progress()
        self.queue_update(self.console.insert,tk.END,"Password not found in mask attack.")
        self.stop_cracking()
            
            
    def browse_rainbow(self):
        self.rainbow_db = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    
    def run_normal_attack(self):
        try:
            self.target_hash  = self.hash_to_crack #self.target_hash .lower()#self.hash_entry.lower()
            self.current_hash_type = self.detect_hash_type(self.target_hash )

            with open(self.file_path, 'rb') as f:
                self.total_passwords = sum(1 for _ in f)
                f.seek(0)
                passwords = (line.strip() for line in f)

                self.queue_update(self.progress_bar.config, maximum=self.total_passwords)
                self.queue_update(self.console.insert,tk.END, "\n[✓] Starting Brute Engine v0.3 ...\n")
                time.sleep(0.2)
                hash_type = self.detect_hash_type(self.hash_to_crack)
                self.queue_update(self.console.insert,tk.END, f"\n[+] Detected hash type: {hash_type}\n")
                time.sleep(0.2)
                self.queue_update(self.console.insert,tk.END, f"\n[+] Processing {self.total_passwords} passwords...\n")
                time.sleep(0.2)
                self.queue_update(self.console.insert,tk.END, f"\n[+] Trying brute force attack on {hash_type} hash\n")
                time.sleep(0.2)
                self.queue_update(self.console.insert,tk.END, "\n[+] Cracking password ...\n")

                batch = []
                for i, pwd in enumerate(passwords):
                    if not self.cracking:
                        self.queue_update(self.console.insert,tk.END, "\n ⚠ Brute Engine v0.3 Not running ...\n")
                        break
                    while self.paused.is_set():
                        time.sleep(0.01)

                    try:
                        pwd_str = pwd.decode('utf-8', 'ignore')
                        batch.append(pwd_str)
                        self.queue_update(self.result_label.config,text=f"Trying: {pwd_str}")
                    except Exception as e:#UnicodeDecodeError:
                        self.queue_update(self.console.insert, tk.END, f"Error : {e}")
                        continue
                        

                    self.processed += 1
                    self.queue_update(self.attempts_label.config,
                                     text=f"Attempts: {self.processed}/{self.total_passwords}")

                    hashed = self.hash_password(pwd_str)
                    if hashed and hashed.lower() == self.target_hash :
                        self.queue_update(self.console.insert, tk.END, f"\n[+] Password found: {pwd_str}\n")
                        self.password = pwd_str
                        self.stop_cracking()
                        return

                    if time.time() - self.last_update > 0.1:
                        self.queue_update(self.progress_bar.config, value=self.processed)
                        self.queue_update(self.progress_label.config,
                                        text=f"{self.processed/self.total_passwords*100:.1f}%")
                        self.last_update = time.time()

                if self.cracking:
                    self.queue_update(self.console.insert, tk.END, "\n[!] Password not found in list\n")

        except Exception as e:
            #self.queue_update(messagebox.showerror, "Error", str(e))
            self.queue_update(self.console.insert, tk.END, f"Error : {e}")
        finally:
            self.stop_cracking()
    def dictionary_attack(self):#, target_hash , check_func):
        try:
        	self.wordlist_file = '/sdcard/pass.txt'#self.wordlist_file = self.file_entry.get()
        except:
        	self.wordlist_file = '/sdcard/pass.txt'
        with open(self.wordlist_file, 'r', errors='ignore') as f:
            words = [line.strip() for line in f]
        
        self.total_combinations = len(words)
        self.progress_bar['maximum'] = self.total_combinations
        
        for i, word in enumerate(words):
            if not self.cracking:
                break
            while self.paused:
                time.sleep(0.1)
            
            if self.check_func(word, self.target_hash ):
                self.queue_update(lambda: self.console.insert,tk.END,f"Password found: {word}")
                self.stop_cracking()
                return
            
            self.processed = i + 1
            self.update_progress()
        self.queue_update(lambda: self.console.insert,tk.END,"Password not found in dictionary attack.")
        self.stop_cracking()
 
      

    def bruteforce_attack(self, target_hash , check_func):
        charset = self.charset_entry.get()
        min_len = int(self.min_length.get())
        max_len = int(self.max_length.get())
        
        total = sum(len(charset)**l for l in range(min_len, max_len+1))
        self.total_combinations = total
        self.progress['maximum'] = total
        
        for length in range(min_len, max_len+1):
            for combo in itertools.product(charset, repeat=length):
                if not self.running:
                    return
                while self.paused:
                    time.sleep(0.1)
                
                candidate = ''.join(combo)
                if self.check_func(candidate, self.target_hash ):
                    self.queue_update(lambda: self.console.insert,tk.END,f"Password found: {candidate}")
                    self.stop_attack()
                    return
                
                self.processed += 1
                if self.processed % 1000 == 0:
                    self.update_progress()
        self.queue_update(lambda: self.console.insert,tk.END,"Password not found in brute force attack.")
        self.stop_craking()

    def update_progress(self):
        self.processed += 1
        if time.time() - self.last_update > 0.5:
            progress = self.processed / self.total_passwords * 100
            self.queue_update(self.progress_bar.config, value=progress)
            self.queue_update(self.attempts_label.config, 
                            text=f"Attempts: {self.processed}/{self.total_passwords}")
            self.last_update = time.time()

    def stop_cracking(self):
        if self.cracking:
            self.cracking = False
            self.queue_update(self.toggle_btn.config, text="♻ Start Cracking", bg="cyan")
            self.queue_update(self.console.insert, tk.END, "\n ⚠ Cracking stopped\n")

    
    def toggle_pause(self):
        if self.paused.is_set():
            self.paused.clear()  # Resume cracking
            self.pause_btn.config(text="Pause", bg="#FFFF00")
            self.queue_update(self.console.insert, tk.END, "\n[+] Resuming cracking...\n")
        else:
            self.paused.set()  # Pause cracking
            self.pause_btn.config(text="Resume", bg="orange")
            self.queue_update(self.console.insert, tk.END, "\n[+] Paused cracking...\n")
    def toggle_cracking(self):
        if not self.cracking:
            #self.stop_cracking()
            self.start_cracking()
        else:
            #self.start_cracking()
            self.stop_cracking()
    def run_benchmark(self):
        """Run and display benchmark results."""
        self.console.insert(tk.END, "\nInitializing BenchMark\n")
        results = self.core.benchmark()
        self.console.insert(tk.END, "\n=== Benchmark Results ===\n")
        for algo, time_taken in results.items():
            self.console.insert(tk.END, f"{algo}: {time_taken:.4f} seconds\n")
    def load_rules(self):
        rules_file = filedialog.askopenfilename(title="Select Hashcat Rules File", filetypes=[("Text files", "*.txt"),("All Files",".*")])
        if rules_file:
            with open(rules_file, 'r') as file:
                self.hashcat_rules = [line.strip() for line in file.readlines() if line.strip()]
            self.queue_update(self.console.insert, tk.END, f"\n[+] Loaded {len(self.hashcat_rules)} rules\n")
    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            #self.file_entry.delete(0, tk.END)
            pass
            #self.file_entry.insert(0, self.file_path)
   # def queue_update(self, func, *args, **kwargs):
    #    self.update_queue.append((func, args, kwargs))
    def queue_update(self, func, *args, **kwargs):
        """
        Helper function to safely update the GUI from a different thread.
        """
        self.update_queue.append((func, args, kwargs))
        if len(self.update_queue) == 1:
            self.process_updates()

    def run_combo_attack(self):
        """Combine two wordlists."""
        self.target_hash  = self.hash_to_crack#self.hash_entry.get().strip()
        algo = self.core.detect_hash_type(self.target_hash )
        self.check_func = self.core.algorithms.get(algo)

        with open(self.file_entry, 'r', errors='ignore') as f1, \
             open(self.file_entry, 'r', errors='ignore') as f2:
            words1 = [line.strip() for line in f1]
            words2 = [line.strip() for line in f2]

        for word1, word2 in itertools.product(words1, words2):
            if not self.cracking:
                break
            while self.paused.is_set():
                time.sleep(0.1)

            candidate = word1 + word2
            if self.check_func(candidate, self.target_hash ):
                self.queue_action(self.on_crack_success, candidate)
                return

            self.queue_action(self.update_progress_ui, 1, 1)  # Fake progress
    
    def on_crack_success(self, password):
        self.console.insert(tk.END, f"\n[SUCCESS] Password found: {self.password}\n")
        self.stop_cracking()
    def hash_password(self, password):
        if self.current_hash_type == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif self.current_hash_type == 'lm':
            return self.lm_hash(password)
        elif self.current_hash_type == 'ntlm':
            return self.ntlm_hash(password)
        elif self.current_hash_type == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif self.current_hash_type == 'sha224':
            return hashlib.sha224(password.encode()).hexdigest()
        elif self.current_hash_type == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif self.current_hash_type == 'sha384':
            return hashlib.sha384(password.encode()).hexdigest()
        elif self.current_hash_type == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            return None
    def process_updates(self):
        if self.update_queue:
            func, args, kwargs = self.update_queue.popleft()
            try:
                func(*args, **kwargs)
            except Exception as e:
                print(f"[!] Error updating GUI: {e}")
            self.master.after(10, self.process_updates)  # Continue processing in 10ms
    def validate_inputs(self):
        if not self.hash_entry.get().strip():
            messagebox.showerror("Error", "Please enter a hash to crack")
            return False
        if not self.file_entry:
            try:
            	messagebox.showerror("Error", "Select a password list file")
            except:
            	self.wordlistfile = '/sdcard/pass.txt'
            return False
        return True
        if self.mode_selector.get() in ['Dictionary', 'Hybrid','Normal Attack'] and not self.wordlist_entry.get():
            messagebox.showerror("Error", "Enter a wordlist file")
            return False
        if self.mode_selector.get() == 'Mask' and not self.mask_entry.get():
            messagebox.showerror("Error", "Enter a mask pattern")
          
            return False
        return True
        # Add validation for attack mode parameters
        if self.mode_selector.get() == 'Brute-force':
            if len(self.charset_entry.get()) < 4:
                self.console.insert(END,"Charset too small (min 4 characters)")
                return False
            if int(self.length_spin.get()) > 8:
                self.console("Max length limited to 8 for performance")
                return False
        return True

    # [Rest of the previous GUI methods...]

# Testing and error handling improvements
if __name__ == "__main__":
    root = tk.Tk()
    #app = Hashcracker(root)
#    app.pack()
#    root.mainloop()
    try:
        app = Hashcracker(root)
        app.pack()
        root.mainloop()
    except Exception as e:
        with open('/sdcard/cracker_errors.log', 'a') as f:
            f.write(f"{time.ctime()} - {str(e)}\n")
        messagebox.showerror("Critical Error", f"Application crashed: {str(e)}\nSee error log for details.")