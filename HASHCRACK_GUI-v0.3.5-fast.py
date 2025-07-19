import os
import hashlib
import sys
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import time
import binascii
import threading
#from Crypto.Cipher import DES # For LM hash

class HashCracker(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.title('SecureHashCracker')
        self.master.geometry('700x900')
        self.file_path = ''
        self.cracking = False
        self.paused = threading.Event()
        self.start_time = 0
        self.total_passwords = 0
        self.processed = 0
        self.current_hash_type = ''
        self.setup_ui()
        self.configure_styles()

    def setup_ui(self):
        # UI setup with improved layout
        self.main_frame = ttk.Frame(self.master)
        self.main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # Hash input section
        hash_frame = ttk.LabelFrame(self.main_frame, text="Hash Input")
        hash_frame.pack(fill=tk.X, pady=5)
        ttk.Label(hash_frame, text="Target Hash:").pack(side=tk.LEFT, padx=5)
        self.hash_entry = ttk.Entry(hash_frame, width=50)
        self.hash_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # File selection
        file_frame = ttk.LabelFrame(self.main_frame, text="Password List")
        file_frame.pack(fill=tk.X, pady=5)
        self.file_entry = ttk.Entry(file_frame)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)

        # Progress indicators
        progress_frame = ttk.LabelFrame(self.main_frame, text="Progress")
        progress_frame.pack(fill=tk.X, pady=5)
        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=2)
        self.stats_label = ttk.Label(progress_frame, text="Ready")
        self.stats_label.pack(pady=2)
        self.status_label = ttk.Label(progress_frame, text="Status :")
        self.status_label.pack(pady=2)

        # Results console
        console_frame = ttk.LabelFrame(self.main_frame, text="Activity Log")
        console_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.console = tk.Text(console_frame, bg='#1e1e1e', fg='#dcdcdc', insertbackground='white')
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        # Control buttons
        btn_frame = ttk.Frame(self.main_frame)
        btn_frame.pack(pady=10)
        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.toggle_cracking)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.pause_btn = ttk.Button(btn_frame, text="Pause", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)

    def configure_styles(self):
        style = ttk.Style()
        style.configure('TFrame', background='#2d2d2d')
        style.configure('TLabel', background='#2d2d2d', foreground='#dcdcdc')
        style.configure('TButton', font=('Segoe UI', 10), padding=5)
        style.configure('TEntry', fieldbackground='#3c3c3c')

    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, self.file_path)

    def toggle_cracking(self):
        if self.cracking:
            self.stop_cracking()
        else:
            self.start_cracking()

    def start_cracking(self):
        if not self.validate_inputs():
            return
            
        self.cracking = True
        self.start_btn.config(text="Stop")
        self.pause_btn.config(state=tk.NORMAL)
        self.start_time = time.time()
        threading.Thread(target=self.crack_process, daemon=True).start()
        #self.update_progress()

    def validate_inputs(self):
        if not self.hash_entry.get().strip():
            messagebox.showerror("Error", "Please enter a hash to crack")
            return False
        if not self.file_path:
            messagebox.showerror("Error", "Select a password list file")
            return False
        return True

    def stop_cracking(self):
        self.cracking = False
        self.start_btn.config(text="Start")
        self.pause_btn.config(state=tk.DISABLED)
        self.log("Cracking stopped by user")

    def toggle_pause(self):
        if self.paused.is_set():
            self.paused.clear()
            self.pause_btn.config(text="Pause")
            self.log("Resuming...")
        else:
            self.paused.set()
            self.pause_btn.config(text="Resume")
            self.log("Paused...")

    def update_progress(self):
        if not self.cracking:
            return
            
        elapsed = time.time() - self.start_time
        self.progress['value'] = (self.processed / self.total_passwords) * 100
        speed = self.processed / elapsed if elapsed > 0 else 0
        self.status_label.config(
            text=f"Processed: {self.processed}/{self.total_passwords} | "
                 f"Speed: {speed:.1f} p/s | "
                 f"Elapsed: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}"
        )
        self.master.after(1000, self.update_progress)

    def detect_hash_type(self, hash_str):
        hash_len = len(hash_str)
        if hash_len == 32:
            if all(c in '0123456789abcdef' for c in hash_str):
                return 'md5'
            return 'ntlm' if hash_str.isupper() else 'lm'
        return {
            40: 'sha1',
            64: 'sha256',
            128: 'sha512'
        }.get(hash_len, 'unknown')

    def lm_hash(self, password):
        # Proper LM hash implementation using DES
        password = password.upper()[:14].ljust(14, '\0')
        key = password[:7].encode('ascii') + password[7:].encode('ascii')
        cipher1 = DES.new(key[:7], DES.MODE_ECB)
        cipher2 = DES.new(key[7:], DES.MODE_ECB)
              
        return binascii.hexlify(cipher1.encrypt(b'\0' * 8) + cipher2.encrypt(b'\0' * 8)).decode()

    def ntlm_hash(self, password):
        # Proper NTLM hash implementation using MD4
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

    def crack_process(self):
        
        try:
            with open(self.file_path, 'rb') as file:
                passwords = file.readlines()
                self.current_hash_type = self.detect_hash_type(self.hash_entry.get())
                self.total_passwords = len(passwords)
                self.progress['maximum'] = self.total_passwords
                self.log(f"Starting brute force attack on {self.current_hash_type} hash")

                self.update_progress()
                for i, password in enumerate(passwords):
                    if not self.cracking:
                        break
                    while self.paused.is_set():
                        time.sleep(0.1)

                    password = password.strip()
                    try:
                        password_str = password.decode('utf-8')
                    except UnicodeDecodeError:
                        password_str = str(password)

                    hashed = self.hash_password(password_str)
                    if hashed == self.hash_entry.get():
                        self.log(f"Password found: {password_str}")
                        self.stop_cracking()
                        break

                    self.processed = i + 1
                    self.progress['value'] = self.processed
                    self.stats_label.config(text=f"Trying: {password_str}")
                    #self.update_progress()

                if not self.cracking:
                    self.log("Cracking stopped by user")
                else:
                    self.log("Password not found")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def hash_password(self, password):
        if self.current_hash_type == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif self.current_hash_type == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif self.current_hash_type == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        elif self.current_hash_type == 'sha512':
            return hashlib.sha512(password.encode()).hexdigest()
        elif self.current_hash_type == 'lm':
            return self.lm_hash(password)
        elif self.current_hash_type == 'ntlm':
            return self.ntlm_hash(password)
        else:
            return None

    def log(self, message):
        self.console.insert(tk.END, message + '\n')
        self.console.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCracker(root)
    app.pack(fill=tk.BOTH, expand=True)
    root.mainloop()