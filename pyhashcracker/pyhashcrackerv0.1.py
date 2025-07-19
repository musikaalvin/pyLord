import os
import hashlib
import sys
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
from tkinter import *
from tkinter.ttk import *
from time import sleep
import binascii
from hashlib import*# md4  # For proper NTLM hash

class Hashcracker(tk.Frame):  # Changed to Frame inheritance
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.master.configure(bg="#282c34")
        self.master.title('#HASH_CRACKER#')
        self.master.maxsize(700, 1000)
        self.style = ttk.Style()
        self.style.theme_use('classic')
        self.style.configure('browse_button.TButton', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')
        self.style.configure('crack_button.TButton', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')
        self.style.configure('name_label.TLabel', font=('Jokerman', 10),
                           foreground='cyan', background='#282c34')
        self.style.configure('crack_label.TLabel', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')
        self.style.configure('crack_label2.TLabel', font=('Jokerman', 10),
                           foreground='lime', background='#282c34')

        # Hash input section
        ttk.Label(self.master, text="          Hash to Crack:", style='crack_label.TLabel').pack()
        self.hash_to_crack_entry = Entry(self.master, width=30)
        self.hash_to_crack_entry.pack()

        # Buttons
        ttk.Button(self.master, style='browse_button.TButton', text="Browse", command=self.browse_file).pack()
        ttk.Button(self.master, style='crack_button.TButton', text="CRACK HASH", command=self.crack_hash).pack()

        # Log frame with scrollbar
        self.log_frame = Frame(self.master)
        self.log_frame.pack(pady=10)

        self.v_scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical")
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text = Text(self.log_frame, height=25, width=90, bg="#383a42", fg="white", wrap=WORD, yscrollcommand=self.v_scrollbar.set)
        self.log_text.pack(side=tk.LEFT)
        self.v_scrollbar.config(command=self.log_text.yview)

        # Progress bar
        self.progress_frame = Frame(self.master)
        self.progress_frame.pack(pady=10)

        ttk.Label(self.progress_frame, text="Progress:", style='crack_label.TLabel').pack(side=tk.LEFT)
        self.progress_bar = ttk.Progressbar(self.progress_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT)

        # Result display
        self.result_frame = Frame(self.master)
        self.result_frame.pack(pady=10)
        self.result_label = ttk.Label(self.result_frame, text="Password:", style='crack_label.TLabel')
        self.result_label.pack(side=tk.LEFT)

        self.password_file = None

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.log_text.insert(END, f"\n[+] Selected file: {file_path}\n")
            self.password_file = file_path

    def detect_hash_type(self, hash_to_crack):
        hash_length = len(hash_to_crack)
        if hash_length == 32:
            if all(c in '0123456789abcdef' for c in hash_to_crack):
                return "MD5"
            return "NTLM" if hash_to_crack.isupper() else "LM"
        elif hash_length == 40:
            return "SHA-1"
        elif hash_length == 64:
            return "SHA-256"
        else:
            return "Unknown"

    def crack_hash(self):
        self.hash_to_crack = self.hash_to_crack_entry.get()
        if not self.hash_to_crack:
            messagebox.showerror("Error", "Please enter a hash to crack.")
            return

        self.log_text.insert(END, "\n[✓] Loaded hashes ...\n")
        sleep(0.4)

        hash_type = self.detect_hash_type(self.hash_to_crack)
        self.log_text.insert(END, f"\n[+] Detected hash type: {hash_type}\n")

        self.log_text.insert(END, "\n[+] Cracking password ...\n")
        sleep(0.4)

        if not self.password_file:
            messagebox.showerror("Error", "No password file selected!")
            return

        try:
            with open(self.password_file, 'rb') as file:
                hashes = file.readlines()
        except Exception as e:
            messagebox.showerror("Error", f"File error: {str(e)}")
            return

        total_passwords = len(hashes)
        self.progress_bar['maximum'] = total_passwords
        found = False

        for i, password in enumerate(hashes):
            password = password.strip()
            try:
                password_str = password.decode('utf-8')
            except UnicodeDecodeError:
                password_str = str(password)

            sleep(0.01)
            hashed_password2 = hashlib.md5(password).hexdigest()
            hashed_password = hashlib.sha1(password).hexdigest()
            hashed_password3 = hashlib.sha256(password).hexdigest()
            hashed_password4 = self.lm_hash(password)
            hashed_password5 = self.ntlm_hash(password)

            #self.log_text.insert(END, f'\n[~] Trying: {password_str}\n')
            self.result_label.config(text=f'[~] Trying: {password_str}')
            self.progress_bar['value'] = i + 1
            self.progress_bar.update()

            if (hash_type == "MD5" and hashed_password2 == self.hash_to_crack) or \
               (hash_type == "SHA-1" and hashed_password == self.hash_to_crack) or \
               (hash_type == "SHA-256" and hashed_password3 == self.hash_to_crack) or \
               (hash_type == "LM" and hashed_password4 == self.hash_to_crack) or \
               (hash_type == "NTLM" and hashed_password5 == self.hash_to_crack):
                #self.result_label.config(text=f"[√] Found Password: {password_str}")
                self.log_text.insert(END, f"\n[√] Found Password: {password_str}\n")
                found = True
                break

        if not found:
            #self.result_label.config(text="[√] Password not found.")
            self.log_text.insert(END, "\n[√] Password not found.\n")

    def lm_hash(self, password):
        # LM hash implementation
        password = password.decode('utf-8').upper()
        password = password.ljust(14, '\x00')[:14]
        password = password[:7] + password[7:]
        return binascii.hexlify(hashlib.md5(password[:7].encode()).digest() + hashlib.md5(password[7:].encode()).digest()).decode()

    def ntlm_hash(self, password):
        # NTLM hash implementation
        return '####'#md4(password).hexdigest()

# Single Tk instance creation
if __name__ == "__main__":
    root = tk.Tk()
    app = Hashcracker(root)
    root.mainloop()