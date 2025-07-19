import os
import hashlib
import sys
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from tkinter import *
from tkinter.ttk import *
import time
from time import sleep 
import binascii
import threading
#from hashlib import md4 as md4_hash  # Fixed MD4 import

class Hashcracker(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.configure(bg="#282c34")
        self.master.title('#HASH_CRACKER#')
        self.master.maxsize(700, 1200)
        self.file_path = '/sdcard/pass.txt'
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
        # GUI elements setup
        headline = tk.Label(self.master, text="Tool by pyLord@cyb3rh4ck3r04",
                          font=("Courier New", 16, "bold"), bg="#111111", fg="#00FF00")
        headline.pack(pady=10)

        # Log frame with scrollbar
        self.log_frame = Frame(self.master)
        self.log_frame.pack(pady=10)

        self.v_scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical")
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text = Text(self.log_frame, height=25, width=90, bg="#383a42", fg="white", wrap=WORD, yscrollcommand=self.v_scrollbar.set)
        self.log_text.pack(side=tk.LEFT)
        self.v_scrollbar.config(command=self.log_text.yview)

        # Result display
        self.result_frame = Frame(self.master)
        self.result_frame.pack(pady=10)
        self.result_label = ttk.Label(self.result_frame, text="", style='crack2_label.TLabel')
        self.result_label.pack(side=tk.LEFT)
        
        # Hash Input Frame
        hash_frame = Frame(self.master)
        hash_frame.pack(pady=5)
        hash_label = ttk.Label(hash_frame, text="Hash to Crack:", style='crack_label.TLabel',background="#111111", foreground="#00FF00")
        hash_label.pack(side=tk.LEFT, padx=5)
        self.hash_entry = ttk.Entry(hash_frame, width=30)
        self.hash_entry.pack(side=tk.LEFT, padx=5)

        # File Selection Frame
        file_frame = Frame(self.master)
        file_frame.pack(pady=5)
        file_label = ttk.Label(file_frame, text="Password File:", style='crack_label.TLabel',background="#111111", foreground="#00FF00")
        file_label.pack(side=tk.LEFT, padx=5)
        self.file_entry = ttk.Entry(file_frame, width=30)
        self.file_entry.pack(side=tk.LEFT, padx=5)
        file_btn = tk.Button(file_frame, text="Browse", bg="#00FF00", fg="black",
                                  font=("Courier New", 10), command=self.browse_file)
        file_btn.pack(side=tk.LEFT, padx=5)

        # Progress Frame
        progress_frame = Frame(self.master)
        progress_frame.pack(pady=5)
        self.progress_label = ttk.Label(progress_frame, text="0%", style='crack_label.TLabel')
        self.progress_label.pack(side=tk.LEFT, padx=5)
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT)

        # Time tracking labels
        time_frame = Frame(self.master)
        time_frame.pack(pady=5)
        self.elapsed_label = ttk.Label(time_frame, text="Elapsed: 00:00:00", style='crack_label.TLabel')
        self.elapsed_label.pack(side=tk.LEFT, padx=5)
        self.remaining_label = ttk.Label(time_frame, text="Remaining: --:--:--", style='crack_label.TLabel')
        self.remaining_label.pack(side=tk.LEFT, padx=5)

        # Control Buttons
        btn_frame = Frame(self.master)
        btn_frame.pack(pady=10)
        self.toggle_btn = tk.Button(btn_frame, text="♻ Start Cracking", command=self.toggle_cracking, bg="cyan", fg="black")
        self.toggle_btn.pack(side=tk.LEFT, padx=5)
        self.pause_btn = tk.Button(btn_frame, text="Pause", command=self.toggle_pause, bg="#FFFF00", fg="black")
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        # Speed and Progress Info
        status_frame = Frame(self.master)
        status_frame.pack(pady=5)
        self.attempts_label = ttk.Label(status_frame, text="Attempts: 0/0", style='crack_label.TLabel')
        self.attempts_label.pack(side=tk.LEFT, padx=5)
        self.speed_label = ttk.Label(status_frame, text="Speed: 0 w/s", style='crack_label.TLabel')
        self.speed_label.pack(side=tk.LEFT, padx=5)

        

    def browse_file(self):
        style = ttk.Style()
        #style.theme_use('alt')
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
            return

        elapsed = time.time() - self.start_time
        self.elapsed_label.config(text=f"Elapsed: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}")

        if self.processed > 0:
            self.speed = elapsed / self.processed
            remaining = (self.total_passwords - self.processed) * self.speed
            self.remaining_label.config(text=f"Remaining: {time.strftime('%H:%M:%S', time.gmtime(remaining))}")
            self.speed_label.config(text=f"Speed: {self.processed/elapsed:.1f} w/s")

        self.master.after(1000, self.update_timers)

    def start_cracking(self):
        if not self.validate_inputs():
            return
            
        self.cracking = True
        self.toggle_btn.config(text="Stop Cracking", bg="#FF0000")
        self.start_time = time.time()
        self.processed = 0
        self.hash_to_crack = self.hash_entry.get()
        threading.Thread(target=self.crack_process).start()
        self.update_timers()

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
        self.toggle_btn.config(text="♻ Start Cracking", bg="cyan")
        self.log_text.insert(END, "\n ⚠ Cracking stopped ...\n")

    def toggle_pause(self):
        if self.paused.is_set():
            self.paused.clear()
            self.pause_btn.config(text="Pause", bg="#FFFF00", fg="black")
            self.log_text.insert(END, "\n[+] Cracking resuming ....\n")
            #self.log_text.insert(END, "Cracking paused.\n")
        else:
            self.paused.set()
            self.pause_btn.config(text="Resume", bg="#FFFF00", fg="black")
            #self.log_text.insert(END, "Cracking resumed.\n")
            self.log_text.insert(END, "\n[+] Cracking paused.\n")

    

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
                self.progress_bar['maximum'] = self.total_passwords
                
                self.attempts_label.config(text=f"Attempts: 0/{self.total_passwords}")
                self.log_text.insert(END, "\n[✓] Starting Brute Engine v0.3 ...\n")
                sleep(0.4)
                hash_type = self.detect_hash_type(self.hash_to_crack)
                self.log_text.insert(END, f"\n[+] Detected hash type: {hash_type}\n")
                sleep(0.4)
                self.log_text.insert(END,f"\n[+] Trying brute force attack on {self.current_hash_type} hash\n")
                sleep(0.4)
                self.log_text.insert(END, "\n[+] Cracking password ...\n")
                

                
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
                        self.log_text.insert(END,f"\n[+] Password found: {password_str}\n")
                        self.stop_cracking()
                        break

                    self.processed = i + 1
                    self.progress_bar['value'] = self.processed
                    self.result_label.config(text=f"Trying: {password_str}")
                    self.progress_label.config(text=f"{self.processed/self.total_passwords*100:.1f}%")
                    self.attempts_label.config(text=f"Attempts: {self.processed}/{self.total_passwords}")
                    #self.update_progress()

                if not self.cracking:
                    self.log_text.insert(END, "\n ⚠ Brute Engine v0.3 Not running ...\n")
                else:
                    self.log_text.insert(END,"Password not found")

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

if __name__ == "__main__":
    root = tk.Tk()
    app = Hashcracker(root)
    app.pack()
    root.mainloop()
    
    """
#EXAMPLES

#worldcup ->    ae06a7916eca000de400e9320a539574

sha-1:     bd234ba4276433f0e5fc7a8fa2d18274fa711567

 md5 :       0d0de813c1105498e3435dd2fbf7fa26

sha-256:    bf9b5951c550f519c08a4515282f5dc69e0a9e55152d5d316570436b9fa101dc 

sha-512:     da6377cdc1ef8d67d0eaf652f3c4c92a13c1afbbb65febf813062905a9b54231d9790d81cb44de8c27ca05e7506839141d355a16fe253a895ef8c482f1cb6332

"""