import os
import hashlib
import re
import tkinter as tk
from tkinter import messagebox, ttk, filedialog, scrolledtext
import time
import threading
import itertools
import string
from collections import deque
import sqlite3
from passlib.hash import bcrypt, pbkdf2_sha256, argon2
import json
import logging

# --- CORE HASHING AND ATTACK LOGIC ---

class HashCrackerCore:
    """
    Handles all non-GUI logic, including hash identification, checking,
    and password candidate generation for various attack modes.
    """
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
            'l': lambda w: [w.lower()],
            'u': lambda w: [w.upper()],
            'c': lambda w: [w.capitalize()],
            'C': lambda w: [w[0].lower() + w[1:].upper() if len(w) > 1 else w.lower()],
            't': lambda w: [w.swapcase()],
            'd': lambda w: [w + w],
            'r': lambda w: [w[::-1]],
            '$': lambda w: [w + str(i) for i in range(10)],
            '^': lambda w: [str(i) + w for i in range(10)],
        }

        self.mask_charsets = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': string.punctuation,
            '?a': string.ascii_letters + string.digits + string.punctuation,
            '?b': ''.join(chr(i) for i in range(256))
        }

    def detect_hash_type(self, hash_str):
        """Detects hash type using regex patterns."""
        hash_patterns = {
            'md5': r'^[a-f0-9]{32}$',
            'sha1': r'^[a-f0-9]{40}$',
            'sha256': r'^[a-f0-9]{64}$',
            'sha512': r'^[a-f0-9]{128}$',
            'bcrypt': r'^\$2[aby]?\$\d+\$[./A-Za-z0-9]{53}$',
            'pbkdf2_sha256': r'^\$pbkdf2-sha256\$(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$',
            'argon2': r'^\$argon2(id|d|i)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$',
            'ntlm': r'^[a-f0-9]{32}$', # Shares pattern with MD5, context is key
            'md4': r'^[a-f0-9]{32}$', # Shares pattern with MD5
            'sha3_256': r'^[a-f0-9]{64}$',
        }
        # NTLM/MD4/MD5 can be ambiguous. MD5 is the default for a 32-char hex string.
        # User should know if they are cracking NTLM.
        detected = []
        for algo, pattern in hash_patterns.items():
            if re.match(pattern, hash_str, re.IGNORECASE):
                detected.append(algo)
        
        if 'md5' in detected and 'ntlm' in detected and 'md4' in detected:
             return 'md5/ntlm/md4'
        if 'sha256' in detected and 'sha3_256' in detected:
             return 'sha256/sha3_256'
        if detected:
            return detected[0]
            
        return 'unknown'

    # --- Hashing Functions ---
    def check_hash(self, password, target_hash, algo):
        """Generic hash checker."""
        if algo not in self.algorithms:
            return False
        return self.algorithms[algo](password, target_hash)

    def check_md5(self, password, target_hash):
        return hashlib.md5(password.encode()).hexdigest().lower() == target_hash.lower()

    def check_sha1(self, password, target_hash):
        return hashlib.sha1(password.encode()).hexdigest().lower() == target_hash.lower()

    def check_sha256(self, password, target_hash):
        return hashlib.sha256(password.encode()).hexdigest().lower() == target_hash.lower()

    def check_sha512(self, password, target_hash):
        return hashlib.sha512(password.encode()).hexdigest().lower() == target_hash.lower()

    def check_sha3_256(self, password, target_hash):
        return hashlib.sha3_256(password.encode()).hexdigest().lower() == target_hash.lower()
        
    def check_ntlm(self, password, target_hash):
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest().lower() == target_hash.lower()

    def check_md4(self, password, target_hash):
        # Note: This is standard MD4. NTLM is MD4 on a UTF-16LE string.
        return hashlib.new('md4', password.encode()).hexdigest().lower() == target_hash.lower()

    def check_bcrypt(self, password, target_hash):
        try:
            return bcrypt.verify(password, target_hash)
        except Exception:
            return False

    def check_pbkdf2(self, password, target_hash):
        try:
            return pbkdf2_sha256.verify(password, target_hash)
        except Exception:
            return False

    def check_argon2(self, password, target_hash):
        try:
            return argon2.verify(password, target_hash)
        except Exception:
            return False

    def apply_rules(self, word, rules):
        """Applies a list of transformation rules to a word."""
        variants = {word}
        for rule in rules:
            if rule in self.rule_transforms:
                new_variants = set()
                for variant in variants:
                    new_variants.update(self.rule_transforms[rule](variant))
                variants.update(new_variants)
        return list(variants)

    def generate_from_mask(self, mask):
        """Generates password candidates from a mask pattern."""
        charsets = []
        i = 0
        while i < len(mask):
            if mask[i:i+2] in self.mask_charsets:
                charsets.append(self.mask_charsets[mask[i:i+2]])
                i += 2
            else:
                charsets.append(mask[i])
                i += 1
        return (''.join(p) for p in itertools.product(*charsets))

    def get_mask_cardinality(self, mask):
        """Calculates the total number of combinations for a given mask."""
        total = 1
        i = 0
        while i < len(mask):
            if mask[i:i+2] in self.mask_charsets:
                total *= len(self.mask_charsets[mask[i:i+2]])
                i += 2
            else:
                i += 1
        return total
        
    def benchmark(self):
        """Benchmarks the performance of different hashing algorithms."""
        results = {}
        test_password = "password123"
        self.console_log("Starting benchmark... This may take a moment.")
        for algo_name in self.algorithms:
            if algo_name in ['bcrypt', 'pbkdf2_sha256', 'argon2']:
                iterations = 10
            else:
                iterations = 10000
            
            start_time = time.time()
            try:
                # Use a dummy hash for verification-based functions
                if algo_name == 'bcrypt':
                    dummy_hash = bcrypt.hash(test_password)
                    for _ in range(iterations): self.check_bcrypt(test_password, dummy_hash)
                elif algo_name == 'pbkdf2_sha256':
                    dummy_hash = pbkdf2_sha256.hash(test_password)
                    for _ in range(iterations): self.check_pbkdf2(test_password, dummy_hash)
                elif algo_name == 'argon2':
                    dummy_hash = argon2.hash(test_password)
                    for _ in range(iterations): self.check_argon2(test_password, dummy_hash)
                else:
                    # For standard hashes
                    dummy_hash = hashlib.new(algo_name.replace('sha3_','sha3-'), test_password.encode()).hexdigest()
                    for _ in range(iterations): self.check_hash(test_password, dummy_hash, algo_name)
                
                end_time = time.time()
                hps = iterations / (end_time - start_time)
                results[algo_name] = f"{hps:,.2f} H/s"
            except Exception as e:
                results[algo_name] = f"Error: {e}"
        
        self.console_log("--- Benchmark Results ---")
        for algo, speed in results.items():
            self.console_log(f"{algo.upper():<15}: {speed}")
        self.console_log("------------------------")

# --- GUI and APPLICATION LOGIC ---

class Hashcracker(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.core = HashCrackerCore()
        self.cracking_thread = None
        self.running = False
        self.paused = threading.Event()

        # State variables
        self.wordlist1_path = ""
        self.wordlist2_path = ""
        self.rules_path = ""
        self.rules = []
        self.total_passwords = 0
        self.processed_count = 0
        self.start_time = 0
        self.last_update_time = 0
        self.last_processed_count = 0
        
        self.init_rainbow_db()
        self.configure_ui()
        self.create_widgets()
        
        # Start a queue processor for thread-safe UI updates
        self.update_queue = deque()
        self.process_updates()

    def configure_ui(self):
        self.master.title('PyHashCracker Pro - The Ultimate Cracking Tool')
        self.master.geometry('700x1100')
        self.master.minsize(700, 1100)
        self.master.configure(bg="#282C34")
        
        self.style = ttk.Style()
        self.style.theme_use('alt')
        self.style.configure('TFrame', background='#282C34')
        self.style.configure('TLabel', background='#282C34', foreground='white', font=('Courier', 10))
        self.style.configure('TButton', background='#3a3f4b', foreground='white', font=('Courier', 10, 'bold'))
        self.style.map('TButton', background=[('active', '#4a4f5b')])
        self.style.configure('TEntry', fieldbackground='#333333', foreground='white', insertbackground='white')
        self.style.configure('TCombobox', fieldbackground='#333333', foreground='white', selectbackground='#4a4f5b')
        self.style.configure('TCheckbutton', background='#282C34', foreground='white', font=('Courier', 10))
        self.style.configure('Horizontal.TProgressbar', background='cyan')
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self.master, bg="#282C34")
        header_frame.pack(pady=10)
        tk.Label(header_frame, text="PyHashCracker Pro", font=("Courier New", 18, "bold"), bg="#282C34", fg="#00FF00").pack()
        tk.Label(header_frame, text="by pyLord@cyb3rh4ck3r04", font=("Courier", 10), bg="#282C34", fg="#00FF00").pack()

        # Console Output
        log_frame = ttk.Frame(self.master)
        log_frame.pack(pady=10, padx=10, fill='x')
        self.console = scrolledtext.ScrolledText(log_frame, height=20, width=80, bg="#1e1e1e", fg="cyan", wrap=tk.WORD, font=("Courier", 9))
        self.console.pack(expand=True, fill='both')
        self.console_log("Welcome to PyHashCracker Pro. Select an attack mode and provide inputs.")

        # Result Label
        self.result_label = ttk.Label(self.master, text="", font=("Courier", 14, "bold"), foreground='lime')
        self.result_label.pack(pady=5)
        
        # --- Input Frames ---
        input_area = ttk.Frame(self.master)
        input_area.pack(pady=10, padx=10, fill='x')

        # Hash Input
        hash_frame = ttk.Frame(input_area)
        hash_frame.pack(fill='x', pady=5)
        ttk.Label(hash_frame, text="Target Hash:".ljust(15), font=('Courier', 10, 'bold')).pack(side=tk.LEFT)
        self.hash_entry = ttk.Entry(hash_frame)
        self.hash_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=5)
        self.hash_type_label = ttk.Label(hash_frame, text="Type: (auto-detect)", width=20)
        self.hash_type_label.pack(side=tk.LEFT)
        self.hash_entry.bind('<KeyRelease>', self.auto_detect_hash)

        # Wordlist Input
        file_frame = ttk.Frame(input_area)
        file_frame.pack(fill='x', pady=5)
        ttk.Label(file_frame, text="Wordlist File:".ljust(15), font=('Courier', 10, 'bold')).pack(side=tk.LEFT)
        self.file_entry = ttk.Entry(file_frame)
        self.file_entry.pack(side=tk.LEFT, expand=True, fill='x', padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_wordlist).pack(side=tk.LEFT)
        
        # Attack Mode and Mask
        mode_frame = ttk.Frame(input_area)
        mode_frame.pack(fill='x', pady=5)
        ttk.Label(mode_frame, text="Attack Mode:".ljust(15), font=('Courier', 10, 'bold')).pack(side=tk.LEFT)
        self.mode_selector = ttk.Combobox(mode_frame, values=['Dictionary', 'Normal Attack', 'Brute-force', 'Combo', 'Mask', 'Hybrid', 'Rainbow Table'], state='readonly', width=15)
        self.mode_selector.pack(side=tk.LEFT, padx=5)
        self.mode_selector.set('Normal Attack')
        
        self.mask_label = ttk.Label(mode_frame, text="Mask Pattern:", font=('Courier', 10, 'bold'))
        self.mask_label.pack(side=tk.LEFT, padx=(10, 5))
        self.mask_entry = ttk.Entry(mode_frame)
        self.mask_entry.pack(side=tk.LEFT, expand=True, fill='x')
        self.mask_entry.insert(0, 'e.g. Pass?d?d?d')
        
        # Brute-force options
        brute_frame = ttk.Frame(input_area)
        brute_frame.pack(fill='x', pady=5)
        ttk.Label(brute_frame, text="Brute-force:".ljust(15), font=('Courier', 10, 'bold')).pack(side=tk.LEFT)
        ttk.Label(brute_frame, text="Min:").pack(side=tk.LEFT)
        self.min_length = ttk.Spinbox(brute_frame, from_=1, to=16, width=3)
        self.min_length.pack(side=tk.LEFT, padx=(0, 5))
        self.min_length.set(1)
        ttk.Label(brute_frame, text="Max:").pack(side=tk.LEFT)
        self.max_length = ttk.Spinbox(brute_frame, from_=1, to=16, width=3)
        self.max_length.pack(side=tk.LEFT, padx=(0,10))
        self.max_length.set(8)
        ttk.Label(brute_frame, text="Charset:").pack(side=tk.LEFT)
        self.charset_entry = ttk.Entry(brute_frame)
        self.charset_entry.insert(0, string.ascii_lowercase + string.digits)
        self.charset_entry.pack(side=tk.LEFT, expand=True, fill='x')

        # Advanced options
        adv_frame = ttk.Frame(input_area)
        adv_frame.pack(fill='x', pady=10)
        ttk.Button(adv_frame, text="Load Rules", command=self.load_rules).pack(side=tk.LEFT, padx=5)
        ttk.Button(adv_frame, text="Generate Rainbow DB", command=self.generate_rainbow_table_popup).pack(side=tk.LEFT, padx=5)
        ttk.Button(adv_frame, text="Benchmark", command=self.run_benchmark).pack(side=tk.LEFT, padx=5)
        self.gpu_var = tk.BooleanVar(value=False)
        gpu_check = ttk.Checkbutton(adv_frame, text="GPU Acceleration (Not Implemented)", variable=self.gpu_var, state='disabled')
        gpu_check.pack(side=tk.LEFT, padx=5)
        
        # --- Status and Progress ---
        status_area = ttk.Frame(self.master)
        status_area.pack(pady=10, padx=10, fill='x')
        
        self.progress_bar = ttk.Progressbar(status_area, orient=tk.HORIZONTAL, length=300, mode='determinate', style='Horizontal.TProgressbar')
        self.progress_bar.pack(fill='x', pady=5)
        
        info_frame = ttk.Frame(status_area)
        info_frame.pack(fill='x')
        
        self.attempts_label = ttk.Label(info_frame, text="Attempts: 0 / 0", width=30)
        self.attempts_label.pack(side=tk.LEFT, expand=True, fill='x')
        self.speed_label = ttk.Label(info_frame, text="Speed: 0 p/s", width=20)
        self.speed_label.pack(side=tk.LEFT, expand=True, fill='x')
        self.elapsed_label = ttk.Label(info_frame, text="Elapsed: 00:00:00", width=20)
        self.elapsed_label.pack(side=tk.LEFT, expand=True, fill='x')
        self.remaining_label = ttk.Label(info_frame, text="Remaining: --:--:--", width=20)
        self.remaining_label.pack(side=tk.LEFT, expand=True, fill='x')
        
        # --- Control Buttons ---
        btn_frame = tk.Frame(self.master, bg="#282C34")
        btn_frame.pack(pady=20)
        self.toggle_btn = tk.Button(btn_frame, text="▶ START CRACKING", command=self.toggle_cracking, bg="#008000", fg="white", font=('Courier', 12, 'bold'), relief='raised', width=20)
        self.toggle_btn.pack(side=tk.LEFT, padx=10)
        self.pause_btn = tk.Button(btn_frame, text="❚❚ PAUSE", command=self.toggle_pause, bg="#FFA500", fg="white", font=('Courier', 12, 'bold'), relief='raised', width=20, state='disabled')
        self.pause_btn.pack(side=tk.LEFT, padx=10)

    # --- UI Event Handlers ---
    
    def auto_detect_hash(self, event=None):
        h = self.hash_entry.get().strip()
        algo = self.core.detect_hash_type(h)
        self.hash_type_label.config(text=f"Type: {algo}")

    def browse_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist File")
        if path:
            self.wordlist1_path = path
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, path)
            self.console_log(f"Loaded wordlist: {os.path.basename(path)}")

    def load_rules(self):
        path = filedialog.askopenfilename(title="Select Rules File")
        if path:
            self.rules_path = path
            try:
                with open(path, 'r') as f:
                    # Filter out empty lines and comments
                    self.rules = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.console_log(f"Loaded {len(self.rules)} rules from {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load rules file: {e}")

    # --- Cracking Control ---

    def toggle_cracking(self):
        if self.running:
            self.stop_cracking()
        else:
            self.start_cracking()

    def toggle_pause(self):
        if self.paused.is_set():
            self.paused.clear()
            self.console_log("▶ Resuming attack...")
            self.pause_btn.config(text="❚❚ PAUSE", bg="#FFA500")
        else:
            self.paused.set()
            self.console_log("❚❚ Paused attack. Press Resume to continue.")
            self.pause_btn.config(text="▶ RESUME", bg="#008000")

    def validate_inputs(self, mode):
        """Validates required inputs for the selected attack mode."""
        self.target_hash = self.hash_entry.get().strip()
        if not self.target_hash:
            messagebox.showerror("Input Error", "Target Hash cannot be empty.")
            return False
        
        self.algo = self.core.detect_hash_type(self.target_hash)
        if self.algo == 'unknown':
            messagebox.showwarning("Input Error", "Could not determine hash type. Cracking may fail.")
        
        if mode in ['Dictionary', 'Normal Attack', 'Hybrid', 'Combo']:
            self.wordlist1_path = self.file_entry.get()
            if not self.wordlist1_path or not os.path.exists(self.wordlist1_path):
                messagebox.showerror("Input Error", "A valid wordlist file is required for this mode.")
                return False
        
        if mode == 'Mask' or mode == 'Hybrid':
            if not self.mask_entry.get():
                messagebox.showerror("Input Error", "A mask pattern is required for this mode.")
                return False
        
        return True

    def start_cracking(self):
        mode = self.mode_selector.get()
        if not self.validate_inputs(mode):
            return

        self.running = True
        self.paused.clear()
        
        # Reset UI and state
        self.result_label.config(text="")
        self.processed_count = 0
        self.total_passwords = 0
        self.progress_bar['value'] = 0
        self.toggle_btn.config(text="⏹ STOP CRACKING", bg="#FF0000")
        self.pause_btn.config(state='normal', text="❚❚ PAUSE", bg="#FFA500")
        self.console_log(f"\n--- Starting {mode} Attack on hash ---")
        self.console_log(f"Hash: {self.target_hash[:40]}...")
        self.console_log(f"Algorithm: {self.algo.upper()}")
        
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.last_processed_count = 0
        
        # Dispatch to the correct attack thread
        if mode == 'Dictionary':
            target_func = self._dictionary_attack
        elif mode == 'Normal Attack':
             target_func = self._normal_attack # Wordlist + Rules
        elif mode == 'Brute-force':
            target_func = self._brute_force_attack
        elif mode == 'Mask':
            target_func = self._mask_attack
        elif mode == 'Rainbow Table':
            target_func = self._rainbow_table_attack
        elif mode == 'Combo':
            self.wordlist2_path = filedialog.askopenfilename(title="Select SECOND Wordlist for Combo Attack")
            if not self.wordlist2_path:
                self.stop_cracking()
                return
            target_func = self._combo_attack
        elif mode == 'Hybrid':
            target_func = self._hybrid_attack
        else:
            self.stop_cracking()
            return
            
        self.cracking_thread = threading.Thread(target=target_func, daemon=True)
        self.cracking_thread.start()

    def stop_cracking(self, reason=""):
        self.running = False
        if self.cracking_thread and self.cracking_thread.is_alive():
            # Give the thread a moment to stop gracefully
            self.cracking_thread.join(timeout=0.1)
            
        self.toggle_btn.config(text="▶ START CRACKING", bg="#008000")
        self.pause_btn.config(state='disabled', text="❚❚ PAUSE")
        self.progress_bar['value'] = 0
        
        if "FOUND" not in reason:
            self.console_log(f"--- Attack Stopped. {reason} ---")

    # --- Core Attack Implementations (run in threads) ---

    def _dictionary_attack(self):
        try:
            with open(self.wordlist1_path, 'r', errors='ignore') as f:
                self.total_passwords = sum(1 for _ in f)
                f.seek(0)
                for line in f:
                    if not self.running: break
                    self.paused.wait()
                    password = line.strip()
                    self.check_and_report(password)
        except Exception as e:
            self.queue_update(('log', f"ERROR: Could not read wordlist. {e}"))
        self.finish_attack()

    def _normal_attack(self): # Wordlist + Rules
        if not self.rules:
             # If no rules loaded, it's just a dictionary attack
             self._dictionary_attack()
             return
        try:
            with open(self.wordlist1_path, 'r', errors='ignore') as f:
                 words = [line.strip() for line in f]
                 # Estimate total (this can be inaccurate but gives some progress)
                 self.total_passwords = len(words) * len(self.rules) 
            
            for word in words:
                if not self.running: break
                variants = self.core.apply_rules(word, self.rules)
                for variant in variants:
                    if not self.running: break
                    self.paused.wait()
                    self.check_and_report(variant, is_rule_attack=True) # Don't increment processed here
                self.processed_count += 1 # Increment once per base word
        except Exception as e:
            self.queue_update(('log', f"ERROR: Could not process wordlist/rules. {e}"))
        self.finish_attack()

    def _brute_force_attack(self):
        charset = self.charset_entry.get()
        min_len = int(self.min_length.get())
        max_len = int(self.max_length.get())
        
        # Calculate total
        try:
            self.total_passwords = sum(len(charset) ** l for l in range(min_len, max_len + 1))
        except OverflowError:
            self.total_passwords = float('inf') # Too large to calculate

        for length in range(min_len, max_len + 1):
            if not self.running: break
            product_iter = itertools.product(charset, repeat=length)
            for combination in product_iter:
                if not self.running: break
                self.paused.wait()
                password = "".join(combination)
                self.check_and_report(password)
        self.finish_attack()
        
    def _mask_attack(self):
        mask = self.mask_entry.get()
        self.total_passwords = self.core.get_mask_cardinality(mask)
        
        try:
            candidate_generator = self.core.generate_from_mask(mask)
            for password in candidate_generator:
                if not self.running: break
                self.paused.wait()
                self.check_and_report(password)
        except Exception as e:
            self.queue_update(('log', f"ERROR: Invalid mask pattern. {e}"))
            
        self.finish_attack()

    def _combo_attack(self):
        try:
            with open(self.wordlist1_path, 'r', errors='ignore') as f1:
                words1 = [line.strip() for line in f1]
            with open(self.wordlist2_path, 'r', errors='ignore') as f2:
                words2 = [line.strip() for line in f2]
            
            self.total_passwords = len(words1) * len(words2)
            self.queue_update(('log', f"Combining {len(words1)} words with {len(words2)} words..."))

            for w1 in words1:
                if not self.running: break
                for w2 in words2:
                    if not self.running: break
                    self.paused.wait()
                    self.check_and_report(w1 + w2)
        except Exception as e:
            self.queue_update(('log', f"ERROR: Could not read wordlists. {e}"))
        self.finish_attack()
        
    def _hybrid_attack(self):
        mask = self.mask_entry.get()
        wordlist_path = self.file_entry.get()

        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                words = [line.strip() for line in f]
            
            mask_cardinality = self.core.get_mask_cardinality(mask)
            self.total_passwords = len(words) * mask_cardinality * 2 # Appending and prepending
            self.queue_update(('log', "Starting hybrid attack..."))

            candidate_generator = self.core.generate_from_mask(mask)
            # This can be slow, re-creating the generator is inefficient but simpler
            for word in words:
                 if not self.running: break
                 # Append mask
                 for suffix in self.core.generate_from_mask(mask):
                     if not self.running: break
                     self.paused.wait()
                     self.check_and_report(word + suffix)
                 # Prepend mask
                 for prefix in self.core.generate_from_mask(mask):
                     if not self.running: break
                     self.paused.wait()
                     self.check_and_report(prefix + word)

        except Exception as e:
            self.queue_update(('log', f"ERROR: Hybrid attack failed. {e}"))
        self.finish_attack()

    def _rainbow_table_attack(self):
        self.total_passwords = 1
        self.processed_count = 1
        self.queue_update(('log', "Querying Rainbow Table..."))
        try:
            with sqlite3.connect(self.rainbow_db) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password FROM hashes WHERE hash=?", (self.target_hash,))
                result = cursor.fetchone()
                if result:
                    self.password_found(result[0])
        except Exception as e:
             self.queue_update(('log', f"ERROR: Rainbow DB query failed: {e}"))
        self.finish_attack()
        
    # --- Helper Functions for Threads ---

    def check_and_report(self, password, is_rule_attack=False):
        """The core check loop for most attacks."""
        if self.core.check_hash(password, self.target_hash, self.algo):
            self.password_found(password)
        if not is_rule_attack:
            self.processed_count += 1

    def password_found(self, password):
        self.queue_update(('found', password))
        self.running = False # Signal thread to stop

    def finish_attack(self):
        """Called by threads when they complete an attack."""
        if self.running:
            # If still running, it means password was not found
            self.queue_update(('not_found', None))
        self.queue_update(('stop', None))

    # --- Thread-Safe UI Updating ---

    def queue_update(self, message):
        """Adds a message to the queue for the main thread to process."""
        self.update_queue.append(message)
    
    def process_updates(self):
        """Processes messages from the queue to update the UI safely."""
        while self.update_queue:
            msg_type, value = self.update_queue.popleft()
            
            if msg_type == 'log':
                self.console_log(value)
            elif msg_type == 'found':
                self.result_label.config(text=f"✔ PASSWORD FOUND: {value}", foreground="lime")
                self.console_log(f"--- !!! SUCCESS !!! ---")
                self.console_log(f"Password: {value}")
                self.console_log(f"Hash: {self.target_hash}")
                self.stop_cracking(reason="FOUND")
            elif msg_type == 'not_found':
                 self.result_label.config(text="❌ PASSWORD NOT FOUND", foreground="red")
                 self.console_log("--- Attack finished. Password not found. ---")
            elif msg_type == 'stop':
                if self.running: # If it wasn't stopped by 'found'
                    self.stop_cracking()
        
        # Update periodic labels
        if self.running:
            self.update_status_labels()

        self.master.after(100, self.process_updates)

    def update_status_labels(self):
        now = time.time()
        elapsed = now - self.start_time
        self.elapsed_label.config(text=f"Elapsed: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")

        # Calculate speed
        if now - self.last_update_time >= 1: # Update speed every second
            processed_since_last = self.processed_count - self.last_processed_count
            speed = processed_since_last / (now - self.last_update_time)
            self.speed_label.config(text=f"Speed: {speed:,.0f} p/s")
            self.last_update_time = now
            self.last_processed_count = self.processed_count
            
            # Update ETR
            if speed > 0 and self.total_passwords > 0:
                remaining_count = self.total_passwords - self.processed_count
                if remaining_count > 0:
                    eta = remaining_count / speed
                    self.remaining_label.config(text=f"Remaining: {time.strftime('%H:%M:%S', time.gmtime(eta))}")
                else:
                    self.remaining_label.config(text="Remaining: 00:00:00")
            else:
                 self.remaining_label.config(text="Remaining: --:--:--")

        # Update progress bar and attempts
        if self.total_passwords > 0:
            progress = (self.processed_count / self.total_passwords) * 100
            self.progress_bar['value'] = progress
            self.attempts_label.config(text=f"Attempts: {self.processed_count:,} / {self.total_passwords:,} ({progress:.2f}%)")
        else:
            self.attempts_label.config(text=f"Attempts: {self.processed_count:,} / ∞")


    def console_log(self, message):
        timestamp = time.strftime('%H:%M:%S')
        self.console.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console.see(tk.END)
    
    # --- Rainbow Table and Benchmark ---
    
    def init_rainbow_db(self):
        self.rainbow_db = "rainbow_table.db"
        try:
            with sqlite3.connect(self.rainbow_db) as conn:
                conn.execute('''CREATE TABLE IF NOT EXISTS hashes
                             (hash TEXT PRIMARY KEY, password TEXT)''')
                conn.execute('CREATE INDEX IF NOT EXISTS hash_index ON hashes (hash)')
        except Exception as e:
            self.console_log(f"Error initializing database: {e}")

    def generate_rainbow_table_popup(self):
        """UI to get parameters for generating a rainbow table."""
        wordlist = filedialog.askopenfilename(title="Select Wordlist to Generate Rainbow Table From")
        if not wordlist: return

        # Create a popup window
        popup = tk.Toplevel(self.master)
        popup.title("Generate Rainbow Table")
        popup.geometry("350x150")
        popup.configure(bg="#282C34")
        
        ttk.Label(popup, text="Select Algorithm for the Table:", background="#282C34", foreground="white").pack(pady=5)
        
        algo_var = tk.StringVar()
        algo_box = ttk.Combobox(popup, textvariable=algo_var, values=list(self.core.algorithms.keys()))
        algo_box.pack(pady=5)
        algo_box.set('md5')

        def start_generation():
            algo = algo_var.get()
            popup.destroy()
            # Run generation in a thread to not freeze the UI
            gen_thread = threading.Thread(
                target=self._generate_rainbow_table_thread, 
                args=(wordlist, algo), 
                daemon=True)
            gen_thread.start()

        ttk.Button(popup, text="Start Generation", command=start_generation).pack(pady=10)

    def _generate_rainbow_table_thread(self, wordlist_path, algo):
        self.queue_update(('log', f"Starting Rainbow Table generation for '{algo}'..."))
        
        count = 0
        try:
            # Get total for progress bar
            with open(wordlist_path, 'r', errors='ignore') as f:
                 total = sum(1 for _ in f)

            with sqlite3.connect(self.rainbow_db) as conn:
                cursor = conn.cursor()
                with open(wordlist_path, 'r', errors='ignore') as f:
                    for line in f:
                        password = line.strip()
                        if not password: continue
                        
                        hasher = getattr(hashlib, algo.replace('-', '_'), None)
                        if not hasher: # For NTLM etc.
                           if algo == 'ntlm':
                               hashed_value = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
                           else:
                               continue # Skip unsupported
                        else:
                           hashed_value = hasher(password.encode()).hexdigest()

                        # Using INSERT OR IGNORE to avoid errors on duplicates
                        cursor.execute("INSERT OR IGNORE INTO hashes (password, hash) VALUES (?, ?)", (password, hashed_value))
                        count += 1
                        if count % 1000 == 0:
                            self.queue_update(('log', f"Generated {count}/{total} hashes..."))
            conn.commit()
            self.queue_update(('log', f"✔ Successfully generated and stored {count} hashes in '{self.rainbow_db}'."))
        except Exception as e:
            self.queue_update(('log', f"ERROR during Rainbow Table generation: {e}"))

    def run_benchmark(self):
        self.core.console_log = self.console_log # Pass logger to core
        bench_thread = threading.Thread(target=self.core.benchmark, daemon=True)
        bench_thread.start()


if __name__ == '__main__':
    root = tk.Tk()
    app = Hashcracker(master=root)
    app.pack(fill="both", expand=True)
    root.mainloop()
