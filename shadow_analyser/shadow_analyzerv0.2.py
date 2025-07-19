#!/usr/bin/env python3

import os, sys, re, json, csv, time, argparse, threading, logging, subprocess, getpass, hashlib, base64, glob, math, random, string, signal
from datetime import datetime
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests, yaml, shutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from flask import Flask, request, render_template_string, redirect, url_for
import jinja2  # Needed for custom Jinja loader

# =============================
# Setup Logging & Console Theme
# =============================
logging.basicConfig(
    filename='/sdcard/kentsoft/msf/logs/ultimate_shadow_analyzer_ultimate.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s:%(message)s'
)

# Default theme; later updated based on settings.
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green"
})
console = Console(theme=custom_theme)

# =============================
# Prompt with Timeout (Unix only)
# =============================
def prompt_with_timeout(prompt_text, timeout, default):
    def handler(signum, frame):
        raise TimeoutError
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        result = input(prompt_text)
        signal.alarm(0)
        return result if result else default
    except TimeoutError:
        console.print(f"[info]No input within {timeout} seconds, using default: {default}[/]")
        return default

def simple_prompt(message, is_password=False, default=None, timeout=None):
    if timeout and not is_password:
        try:
            return prompt_with_timeout(message, timeout, default)
        except Exception:
            pass
    if is_password:
        try:
            return getpass.getpass(message)
        except Exception:
            return default
    else:
        try:
            return input(message)
        except Exception:
            return default

# =============================
# Encryption/Decryption Helpers
# =============================
def encrypt_report(data, password):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    key = password.encode('utf-8').ljust(32, b'\0')[:32]
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return "ENCRYPTED:" + cipher.iv.hex() + ct_bytes.hex()

def decrypt_report(encrypted_data, password):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    try:
        encrypted_data = encrypted_data.strip()
        if encrypted_data.startswith("ENCRYPTED:"):
            encrypted_data = encrypted_data[len("ENCRYPTED:"):]
        iv = bytes.fromhex(encrypted_data[:32])
        ct = bytes.fromhex(encrypted_data[32:])
        key = password.encode('utf-8').ljust(32, b'\0')[:32]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return None

# =============================
# Other Helper Functions
# =============================
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"

def calculate_entropy(hash_str):
    unique_chars = set(hash_str)
    if not unique_chars:
        return 0
    entropy = len(hash_str) * math.log2(len(unique_chars))
    return round(entropy, 2)

def ai_hash_guess(hash_str):
    return "Predicted complexity: High" if len(hash_str) > 40 else "Predicted complexity: Low"

def generate_random_password(length=12, use_special=True):
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += "!@#$%^&*()-_=+"
    return ''.join(random.choice(chars) for _ in range(length))

def build_dictionary_from_text(seed_text, min_len=4):
    words = set(re.findall(r'\b\w+\b', seed_text))
    return [word for word in words if len(word) >= min_len]

# =============================
# Data Classes & Hash Detection
# =============================
@dataclass
class HashInfo:
    hash_type: str
    algorithm: str
    hashcat_mode: int = None
    john_format: str = None
    is_weak: bool = False

class HashDetector:
    HASH_PATTERNS = [
        (r'^\$1\$', HashInfo('MD5 (CRYPT)', 'md5', 500, 'md5crypt', True)),
        (r'^\$2[abyx]\$', HashInfo('Bcrypt', 'bcrypt', 3200, 'bcrypt')),
        (r'^\$5\$', HashInfo('SHA-256 (CRYPT)', 'sha256', 7400, 'sha256crypt')),
        (r'^\$6\$', HashInfo('SHA-512 (CRYPT)', 'sha512', 1800, 'sha512crypt')),
        (r'^\$y\$[^$]+\$[^$]+\$[^$]+$', HashInfo('Yescrypt (CRYPT)', 'yescrypt', 41500, 'yescrypt')),
        (r'^\$argon2id\$.*', HashInfo('Argon2id', 'argon2', 12300, 'argon2id')),
        # Raw hash patterns:
        (r'^[a-fA-F0-9]{32}$', HashInfo('MD5 (RAW)', 'md5', 0, 'raw-md5', True)),
        (r'^[a-fA-F0-9]{40}$', HashInfo('SHA-1 (RAW)', 'sha1', 100, 'raw-sha1', True)),
        (r'^[a-fA-F0-9]{64}$', HashInfo('SHA-256 (RAW)', 'sha256', 1400, 'raw-sha256')),
        (r'^\$NT\$[A-Fa-f0-9]{32}$', HashInfo('NTLM (Windows)', 'ntlm', 1000, 'nt')),
        (r'^pbkdf2_sha256\$\d+\$', HashInfo('PBKDF2-SHA256', 'pbkdf2', 1000)),
        (r'^[a-fA-F0-9]{96}$', HashInfo('SHA-384 (RAW)', 'sha384', 1080, 'raw-sha384')),
        (r'^[a-fA-F0-9]{128}$', HashInfo('SHA-512 (RAW)', 'sha512', 1700, 'raw-sha512', False)),
    ]
    
    @classmethod
    def detect(cls, hash_str):
        for pattern, info in cls.HASH_PATTERNS:
            if re.match(pattern, hash_str):
                return info
        return HashInfo('UNKNOWN', 'unknown')

# =============================
# Cracking Functions for Raw Hashes
# =============================
def crack_hash_entry(entry, wordlist):
    hash_val = entry['hash'].lower()
    algo = entry['algorithm']
    try:
        h = getattr(hashlib, algo)
    except AttributeError:
        return None
    for word in wordlist:
        word = word.strip()
        if not word:
            continue
        if h(word.encode('utf-8')).hexdigest() == hash_val:
            return word
    return None

# =============================
# Bar Chart Generation (ASCII & HTML)
# =============================
def generate_ascii_bar_chart(stats, width=40):
    total = stats.get('total', 0)
    if total == 0:
        return "No data available."
    lines = []
    for label, count in stats.items():
        if label == "total":
            continue
        percent = (count / total) * 100
        bar_length = int((count / total) * width)
        bar = "█" * bar_length + "-" * (width - bar_length)
        lines.append(f"{label:20s} | {bar} | {percent:5.1f}% ({count})")
    return "\n".join(lines)

def generate_html_bar_chart(stats, width=300):
    total = stats.get('total', 0)
    if total == 0:
        return "<p>No data available.</p>"
    lines = ['<div style="font-family: monospace;">']
    for label, count in stats.items():
        if label == "total":
            continue
        percent = (count / total) * 100
        bar_width = int((count / total) * width)
        lines.append(f'<div>{label:20s} | <span style="display:inline-block;background:#4CAF50;width:{bar_width}px;">&nbsp;</span> {percent:5.1f}% ({count})</div>')
    lines.append("</div>")
    return "\n".join(lines)

# =============================
# Ultimate Shadow Analyzer Class (Ultimate)
# =============================
class UltimateShadowAnalyzer:
    def __init__(self, mode="cli"):
        self.results = []
        self.stats = {}
        self.file_path = None
        self.mode = mode  # "cli" or "web"
        self.lock = threading.Lock()
        self.start_time = None
        self.settings_file = "/sdcard/kentsof t/msf/logs/ultimate_shadow_analyzer_settings.json"
        # Default settings
        self.settings = {"threads": 10, "crack_timeout": 60, "prompt_timeout": 30, "ui_theme": "light"}
        self.load_settings()
        self.apply_theme()

    def load_settings(self):
        if os.path.isfile(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    loaded = json.load(f)
                self.settings.update(loaded)
            except Exception as e:
                console.print(f"[warning]Could not load settings: {e}[/]")

    def save_settings(self):
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            console.print(f"[warning]Could not save settings: {e}[/]")

    def apply_theme(self):
        # Update CLI theme based on ui_theme setting
        theme_choice = self.settings.get("ui_theme", "light")
        if theme_choice == "dark":
            new_theme = Theme({
                "info": "cyan",
                "warning": "magenta",
                "danger": "bold red",
                "success": "bold green"
            })
        else:
            new_theme = Theme({
                "info": "dim cyan",
                "warning": "magenta",
                "danger": "bold red",
                "success": "bold green"
            })
        global console
        console = Console(theme=new_theme)

    # ---------------------------
    # CLI Main Menu
    # ---------------------------
    def cli_menu(self):
        console.clear()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(Panel.fit(
            f"[bold green]Ultimate Shadow Analyzer Ultimate[/]\nCurrent Time: {now}\nChoose an option:",
            border_style="green"
        ), justify="center")
        console.print("1. Dump password file from OS")
        console.print("2. Provide file manually for analysis")
        console.print("3. Analyze and display file (auto-detect hashes)")
        console.print("4. Crack hashes with external wordlist (with progress)")
        console.print("5. Export/Display results (with ASCII chart)")
        console.print("6. Advanced Tools")
        console.print("7. Launch web interface")
        console.print("8. View Saved Outputs")
        console.print("9. Settings")
        console.print("10. Remote Dump (download file from URL)")
        console.print("0. Exit")
        choice = simple_prompt("Enter option number: ", default="0", timeout=self.settings.get("prompt_timeout"))
        return choice.strip()

    def run_cli(self):
        while True:
            choice = self.cli_menu()
            if choice == "1":
                self.dump_password_file()
            elif choice in ["2", "3"]:
                self.get_file_path()
                self.parse_file_multithreaded()
                self.perform_advanced_analysis()
                self.display_results()
            elif choice == "4":
                self.get_file_path_if_empty()
                self.parse_file_multithreaded()
                self.perform_advanced_analysis()
                self.display_results()
                self.crack_hashes_menu()
            elif choice == "5":
                self.export_and_visualize()
            elif choice == "6":
                self.advanced_tools_menu()
            elif choice == "7":
                console.print("[info]Launching web interface...[/]")
                self.run_web()
            elif choice == "8":
                self.view_saved_outputs()
            elif choice == "9":
                self.settings_menu()
            elif choice == "10":
                self.remote_dump()
            elif choice == "0":
                console.print("[info]Exiting tool.[/]")
                sys.exit(0)
            else:
                console.print("[danger]Invalid option. Please try again.[/]")
            simple_prompt("Press Enter to continue...", default="", timeout=self.settings.get("prompt_timeout"))

    def get_file_path_if_empty(self):
        if not self.file_path:
            self.get_file_path()

    def get_file_path(self):
        while True:
            path = simple_prompt('Enter shadow/SAM/master file path: ', default="sample.txt", timeout=self.settings.get("prompt_timeout")).strip()
            if not path:
                console.print("[danger]File path cannot be empty.[/]")
            elif not os.path.isfile(path):
                console.print("[danger]File not found.[/]")
            else:
                self.file_path = path
                break

    # ---------------------------
    # Dump/Extract Functions
    # ---------------------------
    def dump_password_file(self):
        console.print("Select OS to dump password file:")
        console.print("1. Windows SAM")
        console.print("2. macOS master.passwd")
        console.print("3. Linux shadow")
        os_choice = simple_prompt("Enter option number: ", default="3", timeout=self.settings.get("prompt_timeout")).strip()
        if os_choice == "1":
            self.extract_windows_sam()
        elif os_choice == "2":
            self.extract_macos_passwords()
        elif os_choice == "3":
            self.extract_linux_shadow()
        else:
            console.print("[danger]Invalid OS option.[/]")
    
    def extract_windows_sam(self):
        console.print("[warning]Extracting Windows SAM file...[/]")
        dump_sam = "sam_dump.reg"
        try:                  
            subprocess.run(["reg", "save", "HKLM\\SAM", dump_sam, "/y"], check=True)      
            self.file_path = dump_sam
            console.print("[success]Windows SAM extracted successfully.[/]")
        except Exception as e:
            console.print(f"[danger]Error extracting SAM: {e}[/]")
    
    def extract_macos_passwords(self):
        console.print("[warning]Extracting macOS password hashes...[/]")
        passwd_file = "/etc/master.passwd"
        if not os.path.exists(passwd_file):
            console.print("[danger]File not found![/]")
            return
        self.file_path = passwd_file
        console.print("[success]macOS passwords extracted successfully.[/]")
    
    def extract_linux_shadow(self):
        console.print("[warning]Extracting Linux shadow file...[/]")
        shadow_file = "/etc/shadow"
        if not os.path.exists(shadow_file):
            console.print("[danger]File not found![/]")
            return
        self.file_path = shadow_file
        console.print("[success]Linux shadow file loaded successfully.[/]")
    
    # ---------------------------
    # Parsing Functions
    # ---------------------------
    def parse_file_multithreaded(self):
        self.results = []
        self.stats = {}
        self.start_time = time.time()
        console.print("[info]Parsing file...[/]")
        try:
            if "sam" in self.file_path.lower():
                self.parse_sam_file()
                console.print("[info]SAM file parsing complete.[/]")
                return
            else:
                with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
        except Exception as e:
            console.print(f"[danger]Error reading file: {e}[/]")
            return

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Processing lines...", total=len(lines))
            with ThreadPoolExecutor(max_workers=self.settings.get("threads", 8)) as executor:
                futures = [executor.submit(self.process_line, line) for line in lines]
                for _ in as_completed(futures):
                    progress.advance(task)
        console.print("[info]Parsing complete.[/]")
    
    def parse_sam_file(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            lines = content.splitlines()
            for line in lines:
                if ":" not in line:
                    continue
                parts = line.split(':')
                if len(parts) < 4:
                    continue
                username = parts[0]
                lm_hash = parts[2]
                nt_hash = parts[3]
                # If NT hash is valid, use it; otherwise, use LM hash with dedicated handling.
                if nt_hash and nt_hash.lower() != "aad3b435b51404eeaad3b435b51404ee":
                    fake_line = f"{username}:{nt_hash}"
                    self.process_line(fake_line)
                elif lm_hash:
                    entry = {
                        'username': username,
                        'hash': lm_hash,
                        'type': "LM Hash",
                        'algorithm': "lm",
                        'hashcat': 3000,
                        'john': "lm",
                        'weak': True,
                        'entropy': calculate_entropy(lm_hash),
                        'ai_guess': "Predicted: Very Weak"
                    }
                    entry['pwned'] = self.check_pwned_password(lm_hash)
                    with self.lock:
                        self.results.append(entry)
                        self.stats["LM Hash"] = self.stats.get("LM Hash", 0) + 1
        except Exception as e:
            console.print(f"[danger]Error parsing SAM file: {e}[/]")

    def process_line(self, line):
        line = line.strip()
        if not line or line.startswith('#'):
            return
        parts = line.split(':')
        if len(parts) < 2:
            return
        username = parts[0]
        password_hash = parts[1]
        if password_hash in ('*', '!', '!!', ''):
            with self.lock:
                self.stats['locked'] = self.stats.get('locked', 0) + 1
            return
        hash_info = HashDetector.detect(password_hash)
        entry = {
            'username': username,
            'hash': password_hash,
            'type': hash_info.hash_type,
            'algorithm': hash_info.algorithm,
            'hashcat': hash_info.hashcat_mode,
            'john': hash_info.john_format,
            'weak': hash_info.is_weak,
            'entropy': calculate_entropy(password_hash),
            'ai_guess': ai_hash_guess(password_hash)
        }
        entry['pwned'] = self.check_pwned_password(password_hash)
        with self.lock:
            self.results.append(entry)
            self.stats[hash_info.hash_type] = self.stats.get(hash_info.hash_type, 0) + 1

    def check_pwned_password(self, hash_str):
        if not hash_str or len(hash_str) < 5:
            return "N/A"
        try:
            hash_prefix = hash_str[:5]
            response = requests.get(HIBP_API_URL + hash_prefix)
            if response.status_code == 200:
                return "⚠️ Yes" if hash_str.upper() in response.text.upper() else "✅ No"
            else:
                return "N/A"
        except Exception as e:
            logging.error("Error checking HIBP: " + str(e))
            return "N/A"
    
    def perform_advanced_analysis(self):
        self.stats['total'] = len(self.results)
    
    def display_results(self):
        table = Table(title="Ultimate Analysis Results", show_lines=True)
        table.add_column("User", style="cyan")
        table.add_column("Hash Type", style="magenta")
        table.add_column("Algorithm", style="green")
        table.add_column("Entropy")
        table.add_column("AI Guess")
        table.add_column("Pwned?")
        table.add_column("Cracked?")
        for entry in self.results:
            cracked = entry.get('cracked', 'N/A')
            table.add_row(
                entry['username'],
                entry['type'],
                entry['algorithm'],
                str(entry['entropy']),
                entry['ai_guess'],
                entry['pwned'],
                str(cracked)
            )
        console.print(table)
        stats_panel = "\n".join([f"{k}: {v}" for k, v in self.stats.items()])
        console.print(Panel(stats_panel, title="Statistics"))
        elapsed = time.time() - self.start_time if self.start_time else 0
        console.print(f"[info]Elapsed Time: {elapsed:.2f} seconds[/]")

    # ---------------------------
    # Cracking Functions
    # ---------------------------
    def crack_hashes_menu(self):
        console.print("Choose cracking mode:")
        console.print("1. Memory-friendly dictionary attack with progress")
        console.print("2. Skip cracking")
        choice = simple_prompt("Enter option number: ", default="2", timeout=self.settings.get("prompt_timeout")).strip()
        if choice == "1":
            wordlist_path = simple_prompt("Enter wordlist file path: ", default="wordlist.txt", timeout=self.settings.get("prompt_timeout")).strip()
            if not os.path.isfile(wordlist_path):
                console.print("[danger]Wordlist file not found.[/]")
                return
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = f.readlines()
            total_entries = len([e for e in self.results if e['algorithm'] in ['md5','sha1','sha256','sha384']])
            if total_entries == 0:
                console.print("[warning]No supported hash algorithms found for cracking.[/]")
                return
            console.print("[info]Starting cracking process...[/]")
            with Progress(
                "[progress.description]{task.description}",
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeElapsedColumn(),
                TimeRemainingColumn()
            ) as progress:
                task = progress.add_task("Cracking hashes", total=total_entries)
                with ThreadPoolExecutor(max_workers=self.settings.get("threads", 8)) as executor:
                    futures = {}
                    for entry in self.results:
                        if entry['algorithm'] in ['md5','sha1','sha256','sha384']:
                            futures[executor.submit(crack_hash_entry, entry, wordlist)] = entry
                    for future in as_completed(futures):
                        res = future.result()
                        entry = futures[future]
                        entry['cracked'] = res if res else "Not cracked"
                        progress.advance(task)
            console.print("[success]Cracking attempt finished.[/]")
            self.display_results()
        else:
            console.print("Skipping cracking.")
    
    # ---------------------------
    # Export & Visualization
    # ---------------------------
    def export_and_visualize(self):
        console.print("Select export/visualization format:")
        console.print("1. JSON export")
        console.print("2. CSV export")
        console.print("3. YAML export")
        console.print("4. PDF export")
        console.print("5. Encrypted export")
        console.print("6. Graphical summary (ASCII bar chart)")
        choice = simple_prompt("Enter option number: ", default="6", timeout=self.settings.get("prompt_timeout")).strip()
        fmt = None
        if choice == "1":
            fmt = "json"
        elif choice == "2":
            fmt = "csv"
        elif choice == "3":
            fmt = "yaml"
        elif choice == "4":
            fmt = "pdf"
        elif choice == "5":
            fmt = "encrypted"
        elif choice == "6":
            chart = generate_ascii_bar_chart(self.stats)
            console.print(Panel(chart, title="ASCII Bar Chart Summary"))
            return
        else:
            console.print("[danger]Invalid export option.[/]")
            return
        filename = f"/sdcard/msf/logs/ultimate_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt if fmt!='encrypted' else 'txt'}"
        data_str = ""
        try:
            if fmt == "json":
                data_str = json.dumps(self.results, indent=2)
                with open(filename, 'w') as f:
                    f.write(data_str)
            elif fmt == "csv":
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                    writer.writeheader()
                    writer.writerows(self.results)
            elif fmt == "yaml":
                data_str = yaml.dump(self.results)
                with open(filename, 'w') as f:
                    f.write(data_str)
            elif fmt == "pdf":
                from reportlab.lib.pagesizes import letter
                from reportlab.pdfgen import canvas
                c = canvas.Canvas(filename, pagesize=letter)
                width, height = letter
                y = height - 50
                c.setFont("Helvetica", 10)
                for entry in self.results:
                    line = f"{entry['username']} | {entry['type']} | {entry['algorithm']} | {entry['entropy']} | {entry['pwned']}"
                    c.drawString(50, y, line)
                    y -= 15
                    if y < 50:
                        c.showPage()
                        y = height - 50
                c.save()
            elif fmt == "encrypted":
                data_str = json.dumps(self.results, indent=2)
                pwd = simple_prompt("Enter encryption password: ", is_password=True, default="password", timeout=self.settings.get("prompt_timeout"))
                encrypted = encrypt_report(data_str, pwd)
                with open(filename, 'w') as f:
                    f.write(encrypted)
            console.print(f"[success]Exported results to {filename}[/]")
        except Exception as e:
            console.print(f"[danger]Error exporting results: {e}[/]")
    
    # ---------------------------
    # View & Open Saved Outputs
    # ---------------------------
    def view_saved_outputs(self):
        console.print("[info]Scanning for saved output files...[/]")
        files = glob.glob("/sdcard/msf/logs/ultimate_analysis_*.*")
        if not files:
            console.print("[warning]No saved output files found.[/]")
            return
        table = Table(title="Saved Output Files")
        table.add_column("Index", style="cyan")
        table.add_column("Filename", style="cyan")
        table.add_column("Size (KB)", style="green")
        table.add_column("Last Modified", style="magenta")
        for idx, f in enumerate(files):
            size = os.path.getsize(f) // 1024
            mtime = datetime.fromtimestamp(os.path.getmtime(f)).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(str(idx), f, str(size), mtime)
        console.print(table)
        choice = simple_prompt("Enter the index of the file to open (or press Enter to return): ", default="", timeout=self.settings.get("prompt_timeout")).strip()
        if choice.isdigit():
            idx = int(choice)
            if 0 <= idx < len(files):
                self.open_saved_file(files[idx])
            else:
                console.print("[danger]Invalid index.[/]")
    
    def open_saved_file(self, filename):
        try:
            with open(filename, 'r') as f:
                content = f.read().strip()
            if content.startswith("ENCRYPTED:"):
                pwd = simple_prompt("File is encrypted. Enter decryption password: ", is_password=True, default="password", timeout=self.settings.get("prompt_timeout"))
                decrypted = decrypt_report(content, pwd)
                if decrypted is None:
                    console.print("[danger]Decryption failed. Incorrect password?[/]")
                    return
                content = decrypted
            console.print(Panel(content, title=f"Contents of {filename}", expand=True))
        except Exception as e:
            console.print(f"[danger]Error opening file: {e}[/]")
    
    # ---------------------------
    # Settings Menu
    # ---------------------------
    def settings_menu(self):
        console.print(Panel.fit("Settings", style="bold green"))
        console.print(f"1. Number of Threads: {self.settings.get('threads',8)}")
        console.print(f"2. Crack Timeout (sec): {self.settings.get('crack_timeout',60)}")
        console.print(f"3. Prompt Timeout (sec): {self.settings.get('prompt_timeout',10)}")
        console.print(f"4. UI Theme: {self.settings.get('ui_theme','light')}")
        console.print("5. Back to Main Menu")
        choice = simple_prompt("Enter option number to change (or 5 to return): ", default="5", timeout=self.settings.get("prompt_timeout")).strip()
        if choice == "1":
            new_val = simple_prompt("Enter new thread count: ", default="8", timeout=self.settings.get("prompt_timeout")).strip()
            self.settings['threads'] = int(new_val) if new_val.isdigit() else 8
        elif choice == "2":
            new_val = simple_prompt("Enter new cracking timeout (in seconds): ", default="60", timeout=self.settings.get("prompt_timeout")).strip()
            self.settings['crack_timeout'] = int(new_val) if new_val.isdigit() else 60
        elif choice == "3":
            new_val = simple_prompt("Enter new prompt timeout (in seconds): ", default="10", timeout=self.settings.get("prompt_timeout")).strip()
            self.settings['prompt_timeout'] = int(new_val) if new_val.isdigit() else 10
        elif choice == "4":
            console.print("Choose UI Theme:")
            console.print("1. Light")
            console.print("2. Dark")
            theme_choice = simple_prompt("Enter option number: ", default="1", timeout=self.settings.get("prompt_timeout")).strip()
            self.settings['ui_theme'] = "dark" if theme_choice == "2" else "light"
            self.apply_theme()
        elif choice == "5":
            return
        else:
            console.print("[danger]Invalid option.[/]")
        self.save_settings()
    
    # ---------------------------
    # Advanced Tools Menu
    # ---------------------------
    def advanced_tools_menu(self):
        console.print(Panel.fit("Advanced Tools", style="bold green"))
        console.print("1. Password Generator")
        console.print("2. Dictionary Builder")
        console.print("3. Benchmark Hashing Speed")
        console.print("4. Hash Complexity Analyzer")
        console.print("5. Back to Main Menu")
        choice = simple_prompt("Enter option number: ", default="5", timeout=self.settings.get("prompt_timeout")).strip()
        if choice == "1":
            self.password_generator_tool()
        elif choice == "2":
            self.dictionary_builder_tool()
        elif choice == "3":
            self.benchmark_hashing_speed()
        elif choice == "4":
            self.hash_complexity_analyzer_tool()
        elif choice == "5":
            return
        else:
            console.print("[danger]Invalid option.[/]")
    
    def password_generator_tool(self):
        length = simple_prompt("Enter desired password length: ", default="12", timeout=self.settings.get("prompt_timeout")).strip()
        use_special = simple_prompt("Use special characters? (y/n): ", default="y", timeout=self.settings.get("prompt_timeout")).strip().lower() == "y"
        try:
            length = int(length)
        except:
            length = 12
        password = generate_random_password(length=length, use_special=use_special)
        console.print(f"[success]Generated Password:[/] {password}")
    
    def dictionary_builder_tool(self):
        seed_text = simple_prompt("Paste some seed text for dictionary generation:\n", default="", timeout=self.settings.get("prompt_timeout"))
        if not seed_text:
            console.print("[warning]No text provided.[/]")
            return
        dictionary = build_dictionary_from_text(seed_text)
        console.print("[success]Dictionary Words Generated:[/]")
        for word in dictionary:
            console.print(word)
    
    def benchmark_hashing_speed(self):
        console.print("[info]Benchmarking hashing speed...[/]")
        test_string = "benchmark_test"
        iterations = 100000
        start = time.time()
        for _ in range(iterations):
            hashlib.sha256(test_string.encode('utf-8')).hexdigest()
        elapsed = time.time() - start
        console.print(f"[success]SHA-256: {iterations} iterations in {elapsed:.2f} seconds ({iterations/elapsed:.2f} hashes/sec)[/]")
    
    def hash_complexity_analyzer_tool(self):
        console.print("[info]Analyzing hash complexities...[/]")
        for entry in self.results:
            entropy = calculate_entropy(entry['hash'])
            guess = ai_hash_guess(entry['hash'])
            console.print(f"User: {entry['username']} | Entropy: {entropy} | {guess}")

    # ---------------------------
    # Remote Dump Tool
    # ---------------------------
    def remote_dump(self):
        console.print("[info]Remote Dump: Provide a URL to download a SAM/Shadow file[/]")
        url = simple_prompt("Enter the remote file URL: ", default="", timeout=self.settings.get("prompt_timeout")).strip()
        if not url:
            console.print("[danger]No URL provided.[/]")
            return
        try:
            response = requests.get(url)
            if response.status_code == 200:
                filename = f"remote_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                console.print(f"[success]Downloaded remote file and saved as {filename}[/]")
                self.file_path = filename
            else:
                console.print(f"[danger]Failed to download file. Status Code: {response.status_code}[/]")
        except Exception as e:
            console.print(f"[danger]Error during remote dump: {e}[/]")
    
    # ---------------------------
    # Web Interface (Advanced)
    # ---------------------------
    def run_web(self):
        app = Flask(__name__)
        analyzer = self

        # Adjust base template based on UI theme setting
        theme_class = "bg-dark text-white" if self.settings.get("ui_theme","light") == "dark" else "bg-light"
        base_template = f"""
        <!doctype html>
        <html lang="en">
          <head>
            <title>Ultimate Shadow Analyzer Advanced</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
          </head>
          <body class="{theme_class}">
            <div class="container mt-4">
              {{% block content %}}{{% endblock %}}
            </div>
          </body>
        </html>
        """
        
        @app.route("/", methods=["GET", "POST"])
        def index():
            if request.method == "POST":
                if 'file' in request.files:
                    file = request.files.get("file")
                    if file:
                        content = file.read().decode("utf-8", errors="ignore")
                        analyzer.results = []
                        for line in content.splitlines():
                            analyzer.process_line(line)
                        analyzer.perform_advanced_analysis()
                        return redirect(url_for("results"))
            return render_template_string(
                "{% extends 'base.html' %}{% block content %}"
                "<h1 class='mb-4'>Ultimate Shadow Analyzer Advanced</h1>"
                "<form method='post' enctype='multipart/form-data'>"
                "  <div class='mb-3'>"
                "    <label for='file' class='form-label'>Select file for analysis:</label>"
                "    <input class='form-control' type='file' name='file' id='file'>"
                "  </div>"
                "  <button type='submit' class='btn btn-primary'>Analyze</button>"
                "</form>"
                "<br>"
                "<a href='{{ url_for('advanced_tools') }}' class='btn btn-secondary'>Advanced Tools</a> &nbsp;"
                "<a href='{{ url_for('results') }}' class='btn btn-secondary'>View Results</a>"
                "{% endblock %}",
            )
        
        @app.route("/advanced_tools")
        def advanced_tools():
            return render_template_string(
                "{% extends 'base.html' %}{% block content %}"
                "<h1>Advanced Tools</h1>"
                "<a href='{{ url_for('password_generator') }}' class='btn btn-primary mb-2'>Password Generator</a> "
                "<a href='{{ url_for('dictionary_builder') }}' class='btn btn-primary mb-2'>Dictionary Builder</a> "
                "<a href='{{ url_for('benchmark') }}' class='btn btn-primary mb-2'>Benchmark Hashing</a> "
                "<a href='{{ url_for('hash_analyzer') }}' class='btn btn-primary mb-2'>Hash Analyzer</a> "
                "<br><br><a href='{{ url_for('index') }}' class='btn btn-secondary'>Back to Home</a>"
                "{% endblock %}"
            )
        
        @app.route("/password_generator")
        def password_generator():
            generated = generate_random_password()
            return render_template_string(
                "{% extends 'base.html' %}{% block content %}"
                "<h1>Password Generator</h1>"
                "<p>Generated Password: <strong>{{ password }}</strong></p>"
                "<a href='{{ url_for('advanced_tools') }}' class='btn btn-secondary'>Back</a>"
                "{% endblock %}",
                password=generated
            )
        
        @app.route("/dictionary_builder", methods=["GET", "POST"])
        def dictionary_builder():
            if request.method == "POST":
                seed_text = request.form.get("seed_text", "")
                dictionary = build_dictionary_from_text(seed_text)
                return render_template_string(
                    "{% extends 'base.html' %}{% block content %}"
                    "<h1>Dictionary Builder</h1>"
                    "<h3>Generated Dictionary:</h3>"
                    "<ul>{% for word in dictionary %}<li>{{ word }}</li>{% endfor %}</ul>"
                    "<a href='{{ url_for('dictionary_builder') }}' class='btn btn-secondary'>Back</a>"
                    "{% endblock %}",
                    dictionary=dictionary
                )
            return render_template_string(
                "{% extends 'base.html' %}{% block content %}"
                "<h1>Dictionary Builder</h1>"
                "<form method='post'>"
                "  <div class='mb-3'>"
                "    <label for='seed_text' class='form-label'>Enter seed text:</label>"
                "    <textarea class='form-control' name='seed_text' id='seed_text' rows='5'></textarea>"
                "  </div>"
                "  <button type='submit' class='btn btn-primary'>Generate Dictionary</button>"
                "</form>"
                "<br><a href='{{ url_for('advanced_tools') }}' class='btn btn-secondary'>Back</a>"
                "{% endblock %}"
            )
        
        @app.route("/benchmark")
        def benchmark():
            test_string = "benchmark_test"
            iterations = 100000
            start_time = time.time()
            for _ in range(iterations):
                hashlib.sha256(test_string.encode('utf-8')).hexdigest()
            elapsed = time.time() - start_time
            rate = iterations / elapsed
            return render_template_string(
                "{% extends 'base.html' %}{% block content %}"
                "<h1>Benchmark Hashing Speed</h1>"
                "<p>SHA-256: {{ iterations }} iterations in {{ elapsed|round(2) }} seconds</p>"
                "<p>Rate: {{ rate|round(2) }} hashes/second</p>"
                "<a href='{{ url_for('advanced_tools') }}' class='btn btn-secondary'>Back</a>"
                "{% endblock %}",
                iterations=iterations, elapsed=elapsed, rate=rate
            )
        
        @app.route("/hash_analyzer")
        def hash_analyzer():
            analysis = []
            for entry in analyzer.results:
                entropy = calculate_entropy(entry['hash'])
                guess = ai_hash_guess(entry['hash'])
                analysis.append(f"User: {entry['username']} | Entropy: {entropy} | {guess}")
            return render_template_string(
                "{% extends 'base.html' %}{% block content %}"
                "<h1>Hash Complexity Analyzer</h1>"
                "<ul>{% for line in analysis %}<li>{{ line }}</li>{% endfor %}</ul>"
                "<a href='{{ url_for('advanced_tools') }}' class='btn btn-secondary'>Back</a>"
                "{% endblock %}",
                analysis=analysis
            )
        
        @app.route("/results")
        def results():
            table_html = "<table class='table table-bordered table-striped'><thead class='table-dark'><tr><th>User</th><th>Hash Type</th><th>Algorithm</th><th>Entropy</th><th>Pwned?</th><th>Cracked?</th></tr></thead><tbody>"
            for entry in analyzer.results:
                table_html += f"<tr><td>{entry['username']}</td><td>{entry['type']}</td><td>{entry['algorithm']}</td><td>{entry.get('entropy','')}</td><td>{entry.get('pwned','')}</td><td>{entry.get('cracked','N/A')}</td></tr>"
            table_html += "</tbody></table>"
            chart_html = generate_html_bar_chart(analyzer.stats)
            return render_template_string(
                "{% extends 'base.html' %}{% block content %}"
                "<h1>Analysis Results</h1>"
                "{{ table|safe }}"
                "<br><h2>Bar Chart Summary</h2>"
                "{{ chart|safe }}"
                "<br><br><a href='{{ url_for('index') }}' class='btn btn-primary'>Back to Home</a>"
                "{% endblock %}",
                table=table_html, chart=chart_html
            )
        
        # Use a DictLoader to load our base template
        app.jinja_loader = jinja2.DictLoader({'base.html': base_template})
        console.print("[info]Launching web server...[/]")
        app.run(debug=True)
    
    def run(self):
        if self.mode == "web":
            self.run_web()
        else:
            self.run_cli()

# =============================
# Main Entrypoint
# =============================
def main():
    parser = argparse.ArgumentParser(description="Ultimate Shadow Analyzer Ultimate")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli", help="Run mode: cli or web")
    args = parser.parse_args()
    if not sys.stdin.isatty():
        console.print("[info]Non-interactive environment detected, launching web mode.[/]")
        args.mode = "web"
    analyzer = UltimateShadowAnalyzer(mode=args.mode)
    analyzer.run()

if __name__ == '__main__':
    main()