import os
import hashlib
import re
import sys
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from tkinter import *
from tkinter.ttk import *
import time
from time import sleep
import binascii
import threading
from collections import deque
from pyDes import des, CBC  # Required for LM hashes

class Hashcracker(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.configure(bg="#282c34")
        self.master.title('#HASH_CRACKER#')
        self.master.maxsize(700, 1200)
        self.file_path = '/sdcard/pass.txt'#self.file_path = '/sdcard/kentsoft/kent_tool-multisystems/core/rockyou.txt'
        #p@$$w0rd ->  b7463760284fd06773ac2a48e29b0acf      
        # scroller -   0fa3c3177da5beaeac9ea53571bebc7b
        self.style = ttk.Style()
        self.style.theme_use('droid')
        self.cracking = False
        self.paused = threading.Event()
        self.start_time = 0
        self.total_passwords = 0
        self.processed = 0
        self.speed = 0
        self.hash_to_crack = ""
        self.create_widgets()
        self.update_queue = deque()
        self.current_hash_type = ''
        self.last_update = 0
        self.process_updates()
        self.update_thread = None

        # Style configurations
        self.style.configure('browse_button.TButton', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')
        self.style.configure('crack_button.TButton', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')
        self.style.configure('name_label.TLabel', font=('Jokerman', 10),
                           foreground='cyan', background='#282c34')
        self.style.configure('crack2_label.TLabel', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')
        self.style.configure('crack_label2.TLabel', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')

    def create_widgets(self):
        headline = tk.Label(self.master, text="Tool by pyLord@cyb3rh4ck3r04",
                          font=("Courier New", 16, "bold"), bg="#111111", fg="#00FF00")
        headline.pack(pady=10)

        self.log_frame = Frame(self.master)
        self.log_frame.pack(pady=10)

        self.v_scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical")
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text = Text(self.log_frame, height=25, width=90, bg="#383a42", fg="white", wrap=WORD, yscrollcommand=self.v_scrollbar.set)
        self.log_text.pack(side=tk.LEFT)
        self.v_scrollbar.config(command=self.log_text.yview)

        self.result_frame = Frame(self.master)
        self.result_frame.pack(pady=10)
        self.result_label = ttk.Label(self.result_frame, text="", style='crack2_label.TLabel')
        self.result_label.pack(side=tk.LEFT)

        hash_frame = Frame(self.master)
        hash_frame.pack(pady=5)
        hash_label = ttk.Label(hash_frame, text="Hash to Crack:", style='crack_label.TLabel',background="#111111", foreground="#00FF00")
        hash_label.pack(side=tk.LEFT, padx=5)
        self.hash_entry = ttk.Entry(hash_frame, width=30)
        self.hash_entry.pack(side=tk.LEFT, padx=5)

        file_frame = Frame(self.master)
        file_frame.pack(pady=5)
        file_label = ttk.Label(file_frame, text="Password File:", style='crack_label.TLabel',background="#111111", foreground="#00FF00")
        file_label.pack(side=tk.LEFT, padx=5)
        self.file_entry = ttk.Entry(file_frame, width=30)
        self.file_entry.pack(side=tk.LEFT, padx=5)
        file_btn = tk.Button(file_frame, text="Browse", bg="#00FF00", fg="black",
                                  font=("Courier New", 10), command=self.browse_file)
        file_btn.pack(side=tk.LEFT, padx=5)

        progress_frame = Frame(self.master)
        progress_frame.pack(pady=5)
        self.progress_label = ttk.Label(progress_frame, text="0%", style='crack_label.TLabel')
        self.progress_label.pack(side=tk.LEFT, padx=5)
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT)

        time_frame = Frame(self.master)
        time_frame.pack(pady=5)
        self.elapsed_label = ttk.Label(time_frame, text="Elapsed: 00:00:00", style='crack_label.TLabel')
        self.elapsed_label.pack(side=tk.LEFT, padx=5)
        self.remaining_label = ttk.Label(time_frame, text="Remaining: --:--:--", style='crack_label.TLabel')
        self.remaining_label.pack(side=tk.LEFT, padx=5)

        btn_frame = Frame(self.master)
        btn_frame.pack(pady=10)
        self.toggle_btn = tk.Button(btn_frame, text="♻ Start Cracking", command=self.toggle_cracking, bg="cyan", fg="black")
        self.toggle_btn.pack(side=tk.LEFT, padx=5)
        self.pause_btn = tk.Button(btn_frame, text="Pause", command=self.toggle_pause, bg="#FFFF00", fg="black")
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        status_frame = Frame(self.master)
        status_frame.pack(pady=5)
        self.attempts_label = ttk.Label(status_frame, text="Attempts: 0/0", style='crack_label.TLabel')
        self.attempts_label.pack(side=tk.LEFT, padx=5)
        self.speed_label = ttk.Label(status_frame, text="Speed: 0 w/s", style='crack_label.TLabel')
        self.speed_label.pack(side=tk.LEFT, padx=5)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, self.file_path)

    def toggle_cracking(self):
        if self.cracking:
            self.stop_cracking()
        else:
            self.start_cracking()

    def update_timers(self):
        if not self.cracking:
            self.log_text.insert(END, "\n ⚠ Brute Engine v0.3 Not running ...\n")
            return

        elapsed = time.time() - self.start_time
        self.elapsed_label.config(text=f"Elapsed: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")

        if self.processed > 0:
            passwords_per_sec = self.processed / elapsed
            remaining = (self.total_passwords - self.processed) / passwords_per_sec if passwords_per_sec > 0 else 0
            self.remaining_label.config(text=f"Remaining: {time.strftime('%H:%M:%S', time.gmtime(remaining))}")
            self.speed_label.config(text=f"Speed: {passwords_per_sec:.1f} w/s")

        self.master.after(1000, self.update_timers)

    def validate_inputs(self):
        if not self.hash_entry.get().strip():
            messagebox.showerror("Error", "Please enter a hash to crack")
            return False
        if not self.file_path:
            messagebox.showerror("Error", "Select a password list file")
            return False
        return True

    def start_cracking(self):
        if not self.validate_inputs():
            return
            
        self.cracking = True
        self.paused.clear()
        self.toggle_btn.config(text="⚠ Stop Cracking", bg="#FF0000")
        self.start_time = time.time()
        self.processed = 0
        self.hash_to_crack = self.hash_entry.get().strip()
        
        self.update_thread = threading.Thread(target=self.crack_process)
        self.update_thread.daemon = True
        self.update_thread.start()       
        self.update_timers()

    def crack_process(self):
        try:
            target_hash = self.hash_to_crack.lower()
            self.current_hash_type = self.detect_hash_type(target_hash)
            
            with open(self.file_path, 'rb') as f:
                self.total_passwords = sum(1 for _ in f)
                f.seek(0)
                passwords = (line.strip() for line in f)

                self.queue_update(self.progress_bar.config, maximum=self.total_passwords)
                self.queue_update(self.log_text.insert, END,"\n[✓] Starting Brute Engine v0.3 ...\n")
                sleep(0.2)
                hash_type = self.detect_hash_type(self.hash_to_crack)
                self.queue_update(self.log_text.insert, END,f"\n[+] Detected hash type: {hash_type}\n")
                sleep(0.2)
                self.queue_update(self.log_text.insert, END, f"\n[+] Processing {self.total_passwords} passwords...\n")
                sleep(0.2)
                self.queue_update(self.log_text.insert, END,f"\n[+] Trying brute force attack on {hash_type} hash\n")
                sleep(0.2)
                self.queue_update(self.log_text.insert, END,"\n[+] Cracking password ...\n")

                for i, pwd in enumerate(passwords):
                    if not self.cracking:
                        self.queue_update(self.log_text.insert,END, "\n ⚠ Brute Engine v0.3 Not running ...\n")
                        break
                    while self.paused.is_set(): 
                        time.sleep(0.01)
                    
                    try:
                        pwd_str = pwd.decode('utf-8', 'ignore')
                        self.result_label.config(text=f"Trying: {pwd_str}")
                    except UnicodeDecodeError:
                        continue

                    self.processed += 1
                    self.queue_update(self.attempts_label.config, 
                                     text=f"Attempts: {self.processed}/{self.total_passwords}")
                    
                    hashed = self.hash_password(pwd_str)
                    if hashed and hashed.lower() == target_hash:
                        self.queue_update(self.log_text.insert, END, f"\n[+] Password found: {pwd_str}\n")
                        self.stop_cracking()
                        return

                    if time.time() - self.last_update > 0.1:
                        self.queue_update(self.progress_bar.config, value=self.processed)
                        self.queue_update(self.progress_label.config, 
                                        text=f"{self.processed/self.total_passwords*100:.1f}%")
                        self.last_update = time.time()

                if self.cracking:
                    self.queue_update(self.log_text.insert, END, "\n[!] Password not found in list\n")

        except Exception as e:
            self.queue_update(messagebox.showerror, "Error", str(e))
        finally:
            self.stop_cracking()

    def queue_update(self, func, *args, **kwargs):
        self.update_queue.append((func, args, kwargs))
        
    def process_updates(self):
        while self.update_queue:
            func, args, kwargs = self.update_queue.popleft()
            try:
                func(*args, **kwargs)
            except Exception as e:
                print(f"Update error: {str(e)}")
        self.master.after(100, self.process_updates)

    def stop_cracking(self):
        if self.cracking:
            self.cracking = False
            self.queue_update(self.toggle_btn.config, text="♻ Start Cracking", bg="cyan")
            self.queue_update(self.log_text.insert, END, "\n ⚠ Cracking stopped\n")

    def toggle_pause(self):
        if self.paused.is_set():
            self.paused.clear()
            self.pause_btn.config(text="Pause", bg="#FFFF00", fg="black")
            self.log_text.insert(END, "\n[+] Cracking resuming ....\n")
        else:
            self.paused.set()
            self.pause_btn.config(text="Resume", bg="#FFFF00", fg="black")
            self.log_text.insert(END, "\n[+] Cracking paused ....\n")

    def detect_hash_type(self, hash_str):
        length = len(hash_str)
        
        # Check for LM hash first (must be 32 uppercase hex characters)
        if length == 32:
            if hash_str.isupper() and re.fullmatch(r'^[A-F0-9]{32}$', hash_str):
                return 'lm'
        
        # Convert to lowercase for other checks
        lower_hash = hash_str.lower()
        
        if length == 32:
            if re.fullmatch(r'^[0-9a-f]{32}$', lower_hash):
                return 'md5'
            else:
                return 'ntlm'
        
        # Check other hash types based on length
        return {
            40: 'sha1',
            56: 'sha224',
            64: 'sha256',
            96: 'sha384',
            128: 'sha512'
        }.get(length, 'unknown')

    def lm_hash(self, password):
        try:
            password = password.upper()[:14].ljust(14, '\0')
            key1 = password[:7].encode('ascii')
            key2 = password[7:].encode('ascii')

            cipher1 = des(key1, CBC, b"\0\0\0\0\0\0\0\0")
            cipher2 = des(key2, CBC, b"\0\0\0\0\0\0\0\0")

            return (cipher1.encrypt(b"KGS!@#$%") +
                    cipher2.encrypt(b"KGS!@#$%")).hex().upper()
        except UnicodeEncodeError:
            return None

    def ntlm_hash(self, password):
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

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

if __name__ == "__main__":
    root = tk.Tk()
    app = Hashcracker(root)
    app.pack()
    root.mainloop()