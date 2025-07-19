#!/usr/bin/env python
"""
pyCoder_IDE v2.3
An enhanced Python IDE built with Tkinter featuring syntax highlighting,
live code execution, debugging, Git integration, plugin support, and more.
This version fixes the live-run functionality and the Ctrl+A (select-all) shortcut.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, colorchooser, scrolledtext
import subprocess, os, threading, queue, time, re, sys, io, code, cProfile, pstats, webbrowser

# Optional modules
try:
    import debugpy
except ImportError:
    debugpy = None
try:
    import pylint.lint
except ImportError:
    pylint = None
try:
    import psutil
except ImportError:
    psutil = None
try:
    from chatterbot import ChatBot
    from chatterbot.trainers import ChatterBotCorpusTrainer
except ImportError:
    ChatBot, ChatterBotCorpusTrainer = None, None
try:
    import openai
except ImportError:
    openai = None
try:
    import git
except ImportError:
    git = None
try:
    from tkterminal import Terminal
except ImportError:
    Terminal = None

import jedi
from pygments import lex
from pygments.lexers import PythonLexer, HtmlLexer, JavascriptLexer, PhpLexer, CssLexer, BashLexer
from pygments.styles import get_style_by_name

# ----------------- Utility Classes & Functions ------------------

class StdoutRedirector(io.StringIO):
    """Redirects stdout/stderr to a Tkinter Text widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def write(self, s):
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, s)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")

    def flush(self):
        pass

def get_lexer_for_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".py":
        return PythonLexer()
    elif ext in [".html", ".htm"]:
        return HtmlLexer()
    elif ext == ".js":
        return JavascriptLexer()
    elif ext == ".php":
        return PhpLexer()
    elif ext == ".css":
        return CssLexer()
    elif ext in [".sh", ".bash"]:
        return BashLexer()
    else:
        return PythonLexer()  # fallback

# ----------------- Dialogs ------------------

class SearchReplaceDialog(tk.Toplevel):
    def __init__(self, parent, editor):
        super().__init__(parent)
        self.title("Find and Replace")
        self.editor = editor
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text="Find:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.find_entry = tk.Entry(self, width=30)
        self.find_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(self, text="Replace:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.replace_entry = tk.Entry(self, width=30)
        self.replace_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = tk.Frame(self)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5)
        tk.Button(btn_frame, text="Find Next", command=self.find_next).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Replace", command=self.replace_one).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Replace All", command=self.replace_all).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Close", command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.find_entry.focus_set()
        self.last_found = None

    def find_next(self):
        search_term = self.find_entry.get()
        if not search_term:
            return
        start_pos = self.editor.text.index(tk.INSERT)
        pos = self.editor.text.search(search_term, start_pos, stopindex=tk.END)
        if not pos:
            messagebox.showinfo("Search", "No further matches found.")
            return
        end_pos = f"{pos}+{len(search_term)}c"
        self.editor.text.tag_remove("found", "1.0", tk.END)
        self.editor.text.tag_add("found", pos, end_pos)
        self.editor.text.tag_config("found", background="grey")
        self.editor.text.mark_set("insert", end_pos)
        self.editor.text.see(pos)
        self.last_found = (pos, end_pos)

    def replace_one(self):
        if self.last_found:
            pos, end_pos = self.last_found
            self.editor.text.delete(pos, end_pos)
            self.editor.text.insert(pos, self.replace_entry.get())
            self.editor.text.tag_remove("found", "1.0", tk.END)
            self.last_found = None
            self.find_next()

    def replace_all(self):
        search_term = self.find_entry.get()
        replace_term = self.replace_entry.get()
        if not search_term:
            return
        count = 0
        pos = "1.0"
        while True:
            pos = self.editor.text.search(search_term, pos, stopindex=tk.END)
            if not pos:
                break
            end_pos = f"{pos}+{len(search_term)}c"
            self.editor.text.delete(pos, end_pos)
            self.editor.text.insert(pos, replace_term)
            pos = f"{pos}+{len(replace_term)}c"
            count += 1
        messagebox.showinfo("Replace All", f"Replaced {count} occurrences.")

# ----------------- Panels ------------------

class CodeAssistantPanel(tk.Frame):
    def __init__(self, master, ide, **kwargs):
        super().__init__(master, **kwargs)
        self.ide = ide
        self.mode = tk.StringVar(value="Offline")
        tk.Label(self, text="Assistant Mode:").pack(pady=(5, 0))
        self.mode_combo = ttk.Combobox(self, textvariable=self.mode,
                                       values=["Offline", "Online"], state="readonly", width=12)
        self.mode_combo.pack(pady=(0, 5))
        self.update_button = ttk.Button(self, text="Update Suggestions", command=self.update_suggestions)
        self.update_button.pack(pady=(0, 5))
        self.suggestions_list = tk.Listbox(self, height=15, bg='#282C34', fg='white')
        self.suggestions_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, side=tk.LEFT)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.suggestions_list.yview)
        self.suggestions_list.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.configure(bg="#282C34")
        self.suggestions_list.configure(bg="#282C34", fg="white")

    def update_suggestions(self):
        self.suggestions_list.delete(0, tk.END)
        mode = self.mode.get()
        if mode == "Offline":
            try:
                import jedi
            except ImportError:
                self.suggestions_list.insert(tk.END, "Jedi not installed!")
                return
            if self.ide.current_editor:
                code_text = self.ide.current_editor.text.get("1.0", tk.END)
                cursor_index = self.ide.current_editor.text.index(tk.INSERT)
                try:
                    line, column = map(int, cursor_index.split('.'))
                except Exception:
                    line, column = 1, 0
                try:
                    script = jedi.Script(code_text, path=self.ide.current_editor.file_path)
                    completions = script.complete(line, column)
                    if completions:
                        for comp in completions:
                            self.suggestions_list.insert(tk.END, comp.name)
                    else:
                        self.suggestions_list.insert(tk.END, "No completions.")
                except Exception as e:
                    self.suggestions_list.insert(tk.END, f"Error: {e}")
            else:
                self.suggestions_list.insert(tk.END, "No active editor.")
        elif mode == "Online":
            prompt = "Provide coding suggestions for the current context."
            try:
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=50
                )
                suggestion = response.choices[0].message.content.strip()
                self.suggestions_list.insert(tk.END, suggestion)
            except Exception as e:
                self.suggestions_list.insert(tk.END, f"Online error: {e}")
        else:
            self.suggestions_list.insert(tk.END, "Unknown mode.")

class ChatBotPanel(tk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.mode = tk.StringVar(value="Offline")
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(top_frame, text="Chat Bot Mode:").pack(side=tk.LEFT)
        self.mode_combo = ttk.Combobox(top_frame, textvariable=self.mode,
                                       values=["Offline", "Online"], state="readonly", width=10)
        self.mode_combo.pack(side=tk.LEFT, padx=5)
        self.chat_display = tk.Text(self, height=15, state="disabled", bg="#1E1E1E", fg="white")
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        bottom_frame = ttk.Frame(self)
        bottom_frame.pack(fill=tk.X, padx=5, pady=5)
        self.entry = ttk.Entry(bottom_frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        send_btn = ttk.Button(bottom_frame, text="Send", command=self.send_message)
        send_btn.pack(side=tk.LEFT, padx=5)
        self.bind_events()
        self.offline_bot = None

    def bind_events(self):
        self.entry.bind("<Return>", lambda e: self.send_message())

    def send_message(self):
        msg = self.entry.get().strip()
        if not msg:
            return
        self.append_text(f"You: {msg}\n")
        self.entry.delete(0, tk.END)
        if self.mode.get() == "Online":
            if openai:
                try:
                    response = openai.ChatCompletion.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": msg}],
                        max_tokens=100
                    )
                    bot_response = response.choices[0].message.content.strip()
                except Exception as e:
                    bot_response = f"Online error: {e}"
            else:
                bot_response = "OpenAI API not installed!"
        else:
            bot_response = self.get_offline_response(msg)
        self.after(500, lambda: self.append_text(f"Bot: {bot_response}\n"))

    def get_offline_response(self, msg):
        if ChatBot and ChatterBotCorpusTrainer:
            if not self.offline_bot:
                self.offline_bot = ChatBot("OfflineBot")
                trainer = ChatterBotCorpusTrainer(self.offline_bot)
                trainer.train("chatterbot.corpus.english")
            return str(self.offline_bot.get_response(msg))
        return "Offline chatbot not installed!"

    def append_text(self, text):
        self.chat_display.config(state="normal")
        self.chat_display.insert(tk.END, text)
        self.chat_display.config(state="disabled")
        self.chat_display.see(tk.END)

class CodeEditor(tk.Frame):
    def __init__(self, master, file_path=None, font_family="Courier New", font_size=10,
                 fg="white", bg="#1E1E1E"):
        super().__init__(master)
        self.file_path = file_path
        self.font_family = font_family
        self.font_size = font_size
        self.fg = fg
        self.bg = bg
        self._update_pending = None  # for throttling updates

        # Vertical scrollbar
        self.v_scrollbar = ttk.Scrollbar(self, orient="vertical")
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        # Horizontal scrollbar
        self.h_scrollbar = ttk.Scrollbar(self, orient="horizontal")
        self.h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        # Line numbers canvas
        self.linenumbers = tk.Canvas(self, width=40, bg="#2b2b2b", highlightthickness=0)
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        # Text widget
        # Text widget with no wrapping, and horizontal scrollbar support
        self.text = tk.Text(self,padx="4", pady="4",selectforeground="gray",selectborderwidth="2",insertofftime="110",insertborderwidth="20",insertwidth=4,highlightthickness="1.3", highlightbackground="lime",borderwidth=10,cursor="",relief = "sunken",undo=True, wrap="none",tabs="2",
                            yscrollcommand=self.on_scroll ,xscrollcommand=self.h_scrollbar.set,
                            bg=self.bg, fg=self.fg, insertbackground=self.fg,
                            font=(self.font_family, self.font_size), height=180, width=150)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        #self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.v_scrollbar.config(command=self.yview)
        self.h_scrollbar.config(command=self.text.xview)
        # Bind Ctrl+A to select all in this editor
        self.text.bind("<Control-a>", self.select_all)
        self.text.bind("<KeyRelease>", self.schedule_update)
        self.text.bind("<ButtonRelease>", lambda e: self.winfo_toplevel().update_status(e))
        self.text.bind("<MouseWheel>", lambda e: self._update_line_numbers())
        self.text.bind("<Return>", self.auto_indent)
        self.setup_tags()
        self.folds = {}  # for code folding
        self.linenumbers.bind("<Button-1>", self.on_linenumber_click)

    def select_all(self, event=None):
        self.text.tag_add("sel", "1.0", "end")
        return "break"

    def schedule_update(self, event=None):
        if self._update_pending:
            self.after_cancel(self._update_pending)
        self._update_pending = self.after(100, self.delayed_update)

    def delayed_update(self):
        self._update_line_numbers()
        self.highlight_syntax()
        self.detect_folds()
        self.highlight_current_line()
        top = self.winfo_toplevel()
        if hasattr(top, "code_assistant"):
            top.code_assistant.update_suggestions()
        self._update_pending = None

    def on_scroll(self, *args):
        self.v_scrollbar.set(*args)
        self.text.yview_moveto(args[0])
        self._update_line_numbers()

    def yview(self, *args):
        self.text.yview(*args)
        self._update_line_numbers()

    def setup_tags(self):
        style = get_style_by_name("monokai")
        for token, opts in style:
            tag_opts = {}
            if opts.get("color"):
                tag_opts["foreground"] = f"#{opts['color']}"
            if opts.get("bgcolor"):
                tag_opts["background"] = f"#{opts['bgcolor']}"
            self.text.tag_configure(str(token), **tag_opts)

    def highlight_syntax(self):
        content = self.text.get("1.0", tk.END)
        for tag in self.text.tag_names():
            if tag not in ("found",):
                self.text.tag_remove(tag, "1.0", tk.END)
        lexer = get_lexer_for_file(self.file_path) if self.file_path else PythonLexer()
        self.text.mark_set("range_start", "1.0")
        for token, txt in lex(content, lexer):
            self.text.mark_set("range_end", f"range_start + {len(txt)}c")
            self.text.tag_add(str(token), "range_start", "range_end")
            self.text.mark_set("range_start", "range_end")
        self.text.tag_remove("syntax_error", "1.0", tk.END)
        if self.file_path and self.file_path.endswith(".py"):
            try:
                compile(content, self.file_path, 'exec')
            except SyntaxError as e:
                lineno = e.lineno
                start = f"{lineno}.0"
                end = f"{lineno}.end"
                self.text.tag_add("syntax_error", start, end)
                self.text.tag_config("syntax_error", background="red")

    def detect_folds(self):
        self.folds.clear()
        lines = self.text.get("1.0", tk.END).split("\n")
        stack = []
        for i, line in enumerate(lines, start=1):
            if line.rstrip().endswith(":"):
                self.folds[str(i)] = {"folded": False, "start": i, "end": None}
                stack.append((i, len(line) - len(line.lstrip())))
            else:
                if stack:
                    cur_indent = len(line) - len(line.lstrip())
                    while stack and cur_indent <= stack[-1][1]:
                        fold_line, _ = stack.pop()
                        self.folds[str(fold_line)]["end"] = i
        last_line = len(lines)
        for key in self.folds:
            if self.folds[key]["end"] is None:
                self.folds[key]["end"] = last_line

    def auto_indent(self, event):
        line_start = self.text.get("insert linestart", "insert")
        indent = re.match(r"\s*", line_start).group()
        if line_start.rstrip().endswith(":"):
            indent += "    "
        self.text.insert("insert", "\n" + indent)
        return "break"

    def highlight_current_line(self):
        self.text.tag_remove("current_line", "1.0", tk.END)
        cur_line = self.text.index("insert linestart")
        line_end = self.text.index("insert lineend")
        self.text.tag_add("current_line", cur_line, line_end)
        self.text.tag_config("current_line", background="#333333")
    def _update_line_numbers(self):
        self.linenumbers.delete("all")
        current_line = self.text.index(tk.INSERT).split('.')[0]
        i = self.text.index("@0,0")
        while True:
            dline = self.text.dlineinfo(i)
            if dline is None:
                break
            y = dline[1]
            line_num = str(i).split(".")[0]
            font_opts = (self.font_family, self.font_size, "bold") if line_num == current_line else (self.font_family, self.font_size)
            fill_color = "white" if line_num == current_line else "grey"
            self.linenumbers.create_text(38, y, anchor="ne", text=line_num, fill=fill_color, font=font_opts)
            line_text = self.text.get(f"{line_num}.0", f"{line_num}.end")
            m = re.match(r"( *)", line_text)
            if m:
                indent_count = len(m.group(0))
                if indent_count > 0:
                    self.linenumbers.create_text(5, y, anchor="nw", text="·" * (indent_count // 4),
                                                 fill="#A9A9A9", font=(self.font_family, self.font_size))
            if line_text.strip().endswith(":"):
                next_line = str(int(line_num) + 1)
                next_text = self.text.get(f"{next_line}.0", f"{next_line}.end")
                base_indent = len(m.group(0))
                m2 = re.match(r"( *)", next_text)
                next_indent = len(m2.group(0)) if m2 else 0
                if next_indent > base_indent:
                    fold_state = self.folds.get(line_num, {"folded": False})
                    marker = "+" if fold_state.get("folded") else "–"
                    self.linenumbers.create_text(20, y, anchor="center", text=marker,
                                                 fill="yellow", font=(self.font_family, self.font_size, "bold"))
            i = self.text.index(f"{i}+1line")

    def on_linenumber_click(self, event):
        clicked_index = self.text.index(f"@0,{event.y}")
        line_num = clicked_index.split('.')[0]
        line_text = self.text.get(f"{line_num}.0", f"{line_num}.end")
        if not line_text.strip().endswith(":"):
            return
        fold_info = self.folds.get(line_num)
        if fold_info and fold_info.get("folded"):
            self.unfold_block(line_num)
        else:
            self.fold_block(line_num)
        self._update_line_numbers()

    def get_fold_block_range(self, line_num):
        total_lines = int(self.text.index("end-1c").split('.')[0])
        start = int(line_num) + 1
        base_line_text = self.text.get(f"{line_num}.0", f"{line_num}.end")
        base_indent = len(re.match(r"( *)", base_line_text).group(0))
        end = start
        while end <= total_lines:
            line_text = self.text.get(f"{end}.0", f"{end}.end")
            indent = len(re.match(r"( *)", line_text).group(0))
            if indent > base_indent:
                end += 1
            else:
                break
        return (str(start), str(end))

    def fold_block(self, line_num):
        start, end = self.get_fold_block_range(line_num)
        tag = f"fold_{line_num}"
        self.text.tag_add(tag, f"{start}.0", f"{end}.0")
        self.text.tag_configure(tag, elide=True)
        self.folds[line_num] = {"folded": True, "range": (start, end), "tag": tag}

    def unfold_block(self, line_num):
        fold_info = self.folds.get(line_num)
        if fold_info:
            tag = fold_info.get("tag")
            self.text.tag_remove(tag, "1.0", tk.END)
            self.folds[line_num]["folded"] = False

    def update_indentation_style(self):
        lines = self.text.get("1.0", tk.END).split("\n")
        self.text.delete("1.0", tk.END)
        for line in lines:
            formatted_line = re.sub(r"^(\s+)", lambda m: "." * len(m.group(0)), line)
            self.text.insert(tk.END, formatted_line + "\n")

# ----------------- Terminal & Interpreter Panels ------------------

class TerminalWindow(tk.Toplevel):
    def __init__(self, master, command):
        super().__init__(master)
        self.title("Terminal")
        self.geometry("700x300")
        self.terminal = tk.Text(self, state='disabled', fg='lime', bg='black')
        self.terminal.pack(fill=tk.BOTH, expand=True)
        self.command = command
        try:
            self.process = subprocess.Popen(command,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            text=True,
                                            bufsize=1)
        except Exception as e:
            messagebox.showerror("Process Error", str(e))
            self.destroy()
            return
        self.queue = queue.Queue()
        self.thread = threading.Thread(target=self.read_output)
        self.thread.daemon = True
        self.thread.start()
        self.after(100, self.update_text)

    def read_output(self):
        logo = (
            """
       .--.  
      |o o |
      |\\_/ |
     //   \\ \\  
    ( |    | )  
    /'\\_  _/`\\  
    \\___)(___/
    pyCoder_IDE v2.3 By mskalvin
    pyLord@cyb3rh4ck3r04\n
            """
        )
        self.queue.put(f"{logo}\n")
        for line in self.process.stdout:
            self.queue.put(line)
        for line in self.process.stderr:
            self.queue.put(line)

    def update_text(self):
        try:
            while True:
                line = self.queue.get_nowait()
                self.terminal.config(state="normal")
                self.terminal.insert(tk.END, line)
                self.terminal.config(state="disabled")
                self.terminal.see(tk.END)
        except queue.Empty:
            pass
        if self.process.poll() is None or not self.queue.empty():
            self.after(100, self.update_text)

class PythonInterpreterPanel(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.text = scrolledtext.ScrolledText(self, font=("Courier", 10),height=63,width=10, bg='black',fg='lime')
        self.text.pack(expand=True, fill=tk.BOTH)
        self.prompt = ">>> "
        self.text.insert(tk.END, self.prompt)
        self.text.bind("<Return>", self.on_return)
        self.history = []

    def on_return(self, event):
        content = self.text.get("1.0", tk.END)
        parts = content.split(self.prompt)
        if len(parts) < 2:
            return "break"
        command = parts[-1].strip()
        self.history.append(command)
        try:
            result = eval(command, globals())
            if result is not None:
                self.text.insert(tk.END, "\n" + str(result))
        except Exception as e:
            try:
                exec(command, globals())
            except Exception as ex:
                self.text.insert(tk.END, "\n" + str(ex))
        self.text.insert(tk.END, "\n" + self.prompt)
        self.text.see(tk.END)
        return "break"

# ----------------- Main IDE Application ------------------

class FullVSIDE(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("pyCoder_IDE v2.3")
        self.geometry("900x900")
        self.editor_font_family = "AndroidClock"
        self.editor_font_size = 10
        self.editor_fg = "white"
        self.editor_bg = "#1E1E1E"
        self.theme = "dark"
        self.current_editor = None
        self.live_running = False  # for live execution mode
        self.create_widgets()
        self.bind_shortcuts()
        self.update_resource_usage()
        self.console_frame = ttk.Frame(self, height=150)
        self.console_frame.pack(fill=tk.BOTH, side=tk.BOTTOM)

    def create_widgets(self):
        self.create_menu()
        self.create_toolbar()
        self.create_status_bar()
        self.create_main_panes()
        self.new_file()
    def bind_shortcuts(self):
        self.bind("<Control-s>", lambda _: self.save_file())
        self.bind("<Control-o>", lambda _: self.open_file())
        self.bind("<Control-n>", lambda _: self.new_file())
        self.bind("<Control-x>", lambda _: self.close_current_tab())
        self.bind("<Control-r>", lambda _: self.run_file())
        self.bind("<Control-g>", lambda _: self.goto_line())
        self.bind("<Control-space>", lambda _: self.autocomplete())
        self.bind("<F5>", lambda _: self.run_file())
        self.bind("<Control-f>", lambda e: self.search_replace())
        # Global Ctrl+A for select-all
        self.bind("<Control-a>", self.select_all)
        self.bind("<KeyRelease>", self.update_status)

    def manage_plugins(self):
        plugin_dir = os.path.join(os.getcwd(), "plugins")
        if not os.path.isdir(plugin_dir):
            messagebox.showinfo("Plugins", "No plugins directory found.")
            return
        plugins = [f for f in os.listdir(plugin_dir) if f.endswith(".py")]
        if not plugins:
            messagebox.showinfo("Plugins", "No plugin files found in the plugins directory.")
            return
        plugin_window = tk.Toplevel(self)
        plugin_window.title("Plugins")
        tk.Label(plugin_window, text="Available Plugins:").pack(pady=5)
        listbox = tk.Listbox(plugin_window, width=50)
        listbox.pack(padx=10, pady=10)
        for plugin in plugins:
            listbox.insert(tk.END, plugin)
        def run_selected_plugin():
            selection = listbox.curselection()
            if selection:
                plugin_file = listbox.get(selection[0])
                plugin_path = os.path.join(plugin_dir, plugin_file)
                try:
                    import importlib.util
                    spec = importlib.util.spec_from_file_location("plugin_module", plugin_path)
                    plugin_module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(plugin_module)
                    if hasattr(plugin_module, "run"):
                        plugin_module.run(self)
                        messagebox.showinfo("Plugin", f"Plugin '{plugin_file}' executed.")
                    else:
                        messagebox.showwarning("Plugin", f"Plugin '{plugin_file}' has no run() function.")
                except Exception as e:
                    messagebox.showerror("Plugin Error", str(e))
        ttk.Button(plugin_window, text="Run Plugin", command=run_selected_plugin).pack(pady=5)
    def open_terminal_shell(self):
        dialog = tk.Toplevel(self)
        dialog.title("Select Terminal Shell")
        tk.Label(dialog, text="Choose a shell:").pack(padx=10, pady=10)
        shell_var = tk.StringVar(value="bash")
        shell_combo = ttk.Combobox(dialog, textvariable=shell_var, values=["bash", "zsh", "fish"], state="readonly")
        shell_combo.pack(padx=10, pady=10)
        def launch_shell():
            shell = shell_var.get()
            command = [shell]
            try:
                TerminalWindow(self, command)
            except Exception as e:
                messagebox.showerror("Terminal Error", str(e))
            dialog.destroy()
        ttk.Button(dialog, text="Open Terminal", command=launch_shell).pack(padx=10, pady=10)
    def go_to_definition(self):
        try:
            index = self.current_editor.text.index(tk.INSERT)
            word = self.current_editor.text.get(f"{index} wordstart", f"{index} wordend")
            content = self.current_editor.text.get("1.0", tk.END)
            search_str = f"def {word}("
            pos = content.find(search_str)
            if pos != -1:
                line = content.count("\n", 0, pos) + 1
                self.current_editor.text.see(f"{line}.0")
                self.current_editor.text.mark_set(tk.INSERT, f"{line}.0")
                self.current_editor.text.focus()
            else:
                messagebox.showinfo("Go To Definition", f"Definition for '{word}' not found.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    def select_all(self, event=None):
        if self.current_editor:
            self.current_editor.text.tag_add("sel", "1.0", "end")
        return "break"

    def create_menu(self):
        menubar = tk.Menu(self)
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New File", accelerator="Ctrl+N", command=self.new_file)
        file_menu.add_command(label="Open File", accelerator="Ctrl+O", command=self.open_file)
        file_menu.add_command(label="Save File", accelerator="Ctrl+S", command=self.save_file)
        file_menu.add_command(label="Save File As", command=self.save_file_as)
        file_menu.add_command(label="Open Project", command=self.open_project)
        file_menu.add_separator()
        file_menu.add_command(label="Close Tab", accelerator="Ctrl+W", command=self.close_current_tab)
        file_menu.add_command(label="Visit Site", command=lambda: messagebox.showinfo('SITE', 'http://www.kentsoft.com'))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", accelerator="Alt+F4", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        # Edit Menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Undo", accelerator="Ctrl+Z",
                              command=lambda: self.current_editor.text.event_generate("<<Undo>>"))
        edit_menu.add_command(label="Redo", accelerator="Ctrl+Y",
                              command=lambda: self.current_editor.text.event_generate("<<Redo>>"))
        edit_menu.add_command(label="Cut", accelerator="Ctrl+X",
                              command=lambda: self.current_editor.text.event_generate("<<Cut>>"))
        edit_menu.add_command(label="Copy", accelerator="Ctrl+C",
                              command=lambda: self.current_editor.text.event_generate("<<Copy>>"))
        edit_menu.add_command(label="Paste", accelerator="Ctrl+V",
                              command=lambda: self.current_editor.text.event_generate("<<Paste>>"))
        edit_menu.add_command(label="Select All", accelerator="Ctrl+A", command=self.select_all)
        edit_menu.add_command(label="Go to Definition", command=self.go_to_definition)
        edit_menu.add_command(label="Find and Replace", command=self.search_replace, accelerator="Ctrl+F")
        edit_menu.add_command(label="Go to Line", command=self.goto_line, accelerator="Ctrl+G")
        menubar.add_cascade(label="Edit", menu=edit_menu)
        # Run Menu
        run_menu = tk.Menu(menubar, tearoff=0)
        run_menu.add_command(label="Run Live", command=self.run_code, accelerator="F5")
        run_menu.add_command(label="Run Code", command=self.run_file)
        run_menu.add_command(label="Profile Code", command=self.profile_code)
        run_menu.add_command(label="Compile File", command=self.compile_file)
        run_menu.add_command(label="Debug", command=self.start_debugger)
        run_menu.add_command(label="Lint", command=self.lint_file)
        run_menu.add_command(label="Run Unit Tests", command=lambda: messagebox.showinfo("Unit Tests", "No tests defined."))
        menubar.add_cascade(label="Run ▶", menu=run_menu)
        # Git Menu
        git_menu = tk.Menu(menubar, tearoff=0)
        git_menu.add_command(label="Git Status", command=self.git_status)
        git_menu.add_command(label="Git Init", command=self.git_init)
        git_menu.add_command(label="Git Clone", command=self.git_clone)
        git_menu.add_command(label="Git Commit", command=self.git_commit)
        git_menu.add_command(label="Git Push", command=self.git_push)
        git_menu.add_command(label="Git Pull", command=self.git_pull)
        git_menu.add_command(label="Git History", command=self.git_commit_history)
        menubar.add_cascade(label="Git", menu=git_menu)
        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Preferences", command=self.open_settings)
        tools_menu.add_command(label="Resource Monitor", command=self.show_resource_monitor)
        tools_menu.add_command(label="Security Analysis", command=self.security_analysis)
        tools_menu.add_command(label="Plugins/Extensions", command=self.manage_plugins)
        tools_menu.add_command(label="Terminal Shell Switch", command=self.open_terminal_shell)
        tools_menu.add_command(label="Remote Debug", command=self.remote_debug)
        tools_menu.add_command(label="Conditional Breakpoint", command=self.conditional_breakpoint)
        tools_menu.add_command(label="Live Share", command=self.live_share)
        tools_menu.add_command(label="Split View", command=self.split_view)
        tools_menu.add_command(label="Multiple Cursors", command=self.multiple_cursors)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        # Themes Menu
        themes_menu = tk.Menu(menubar, tearoff=0)
        themes_menu.add_command(label="Light Mode", command=self.light_theme)
        themes_menu.add_command(label="Dark Mode", command=self.dark_theme)
        themes_menu.add_command(label="Theme Settings", command=self.open_settings)
        menubar.add_cascade(label="Themes", menu=themes_menu)
        # Snippets Menu
        snippets_menu = tk.Menu(menubar, tearoff=0)
        snippets_menu.add_command(label="For Loop", command=lambda: self.insert_snippet("for i in range(10):\n    print(i)\n"))
        snippets_menu.add_command(label="If Main", command=lambda: self.insert_snippet("if __name__ == '__main__':\n    main()\n"))
        menubar.add_cascade(label="Snippets", menu=snippets_menu)
        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_help)
        help_menu.add_command(label="About", command=self.about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    # --- Live Code Execution Methods ---
    def run_code(self):
        self.console = scrolledtext.ScrolledText(self.console_frame, height=10, state="normal")
        self.console.pack(fill=tk.BOTH, expand=True)
        code_text = self.current_editor.text.get("1.0", tk.END)
        self.console.delete("1.0", tk.END)
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StdoutRedirector(self.console)
        sys.stderr = StdoutRedirector(self.console)
        def exec_code():
            try:
                exec(code_text, {"__name__": "__main__"})
            except Exception as e:
                print(e)
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
        threading.Thread(target=exec_code).start()
    def goto_line(self):
        line_num = simpledialog.askinteger("Go to Line", "Enter line number:")
        if line_num and self.current_editor:
            self.current_editor.text.mark_set("insert", f"{line_num}.0")
            self.current_editor.text.see(f"{line_num}.0")

    def search_replace(self):
        if self.current_editor:
            SearchReplaceDialog(self, self.current_editor)

    def run_code(self):
        # This is used by the "Run Code" menu item (not live mode)
        self.console = scrolledtext.ScrolledText(self.console_frame, height=10, state="normal")
        self.console.pack(fill=tk.BOTH, expand=True)
        code_text = self.current_editor.text.get("1.0", tk.END)
        self.console.delete("1.0", tk.END)
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StdoutRedirector(self.console)
        sys.stderr = StdoutRedirector(self.console)
        def exec_code():
            try:
                exec(code_text, {"__name__": "__main__"})
            except Exception as e:
                print(e)
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
        threading.Thread(target=exec_code).start()

    def profile_code(self):
        code_text = self.current_editor.text.get("1.0", tk.END)
        self.console.configure(state="normal")
        self.console.delete("1.0", tk.END)
        profiler = cProfile.Profile()
        def exec_profiled():
            profiler.enable()
            try:
                exec(code_text, {"__name__": "__main__"})
            except Exception as e:
                print(e)
            finally:
                profiler.disable()
                s = io.StringIO()
                ps = pstats.Stats(profiler, stream=s).sort_stats("cumulative")
                ps.print_stats()
                print(s.getvalue())
        threading.Thread(target=exec_profiled).start()

    def compile_file(self):
        if not self.current_editor or not self.current_editor.file_path:
            messagebox.showerror("Compile Error", "Please save the file before compiling.")
            return
        file_path = self.current_editor.file_path
        ext = os.path.splitext(file_path)[1].lower()
        base = os.path.splitext(file_path)[0]
        if ext == ".c":
            cmd = ["gcc", file_path, "-o", base]
        elif ext == ".cpp":
            cmd = ["g++", file_path, "-o", base]
        elif ext == ".java":
            cmd = ["javac", file_path]
        elif ext == ".py":
            cmd = ["python", "-m", "py_compile", file_path]
        else:
            messagebox.showerror("Compile Error", "Compilation not supported for this file type.")
            return
        try:
            self.status_bar.config(text=f"Compiling {file_path}...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout + "\n" + result.stderr
            self.status_bar.config(text="Compilation finished.")
            TerminalWindow(self, cmd)
        except Exception as e:
            messagebox.showerror("Compile Error", str(e))

    def lint_file(self):
        if not self.current_editor or not self.current_editor.file_path:
            messagebox.showerror("Lint Error", "Please open a file to lint.")
            return
        filename = self.current_editor.file_path
        try:
            result = subprocess.run(["pylint", filename], capture_output=True, text=True)
            lint_output = result.stdout + "\n" + result.stderr
            lint_window = tk.Toplevel(self)
            lint_window.title("Lint Results")
            txt = scrolledtext.ScrolledText(lint_window, width=100, height=30)
            txt.pack(fill=tk.BOTH, expand=True)
            txt.insert(tk.END, lint_output)
        except Exception as e:
            messagebox.showerror("Lint Error", str(e))

    def security_analysis(self):
        if self.current_editor:
            code_text = self.current_editor.text.get("1.0", tk.END)
            warnings = []
            if "eval(" in code_text:
                warnings.append("Usage of eval() detected.")
            if "exec(" in code_text:
                warnings.append("Usage of exec() detected.")
            if warnings:
                messagebox.showwarning("Security Analysis", "\n".join(warnings))
            else:
                messagebox.showinfo("Security Analysis", "No immediate security issues detected.")

    def open_settings(self):
        settings_window = tk.Toplevel(self)
        settings_window.title("Preferences")
        settings_window.geometry("450x400")
        ttk.Label(settings_window, text="Editor Font Family:").pack(pady=5)
        font_family_selector = ttk.Combobox(settings_window, values=['Courier New', 'Arial', 'Times New Roman', 'Consolas','Noto Sans Balinese', 'Noto Sans Telugu UI', 'Clock2017L_v0.4_170118', 'SEC Naskh Arabic', 'Noto Sans Sora Sompeng', 'Noto Sans Gujarati', 'SEC Devanagari', 'SEC Bengali', 'Noto Sans Old Persian', 'Noto Sans Old Turkic', 'Noto Sans Pahawh Hmong', 'Noto Sans Newa', 'Noto Sans Old Italic', 'SECTibetan', 'Clock2019L_v0.2_181017', 'SEC Bengali UI Medium', 'SEC Devanagari UI Medium', 'Noto Sans Lydian', 'Noto Serif Tamil', 'Noto Sans Malayalam UI Medium', 'Noto Serif CJK JP', 'SEC Naskh Arabic UI', 'Noto Sans Inscriptional Pahlavi', 'Noto Sans Linear A', 'Noto Sans Linear B', 'Roboto Black', 'Noto Sans Tai Viet', 'Noto Sans Malayalam', 'Noto Sans Osmanya', 'SamsungOneUINum', 'Noto Serif CJK KR', 'Noto Serif Ethiopic', 'Carrois Gothic SC', 'Noto Sans Gurmukhi', 'Noto Sans Malayalam UI', 'SEC Mono CJK SC', 'AndroidClock', 'Noto Sans Myanmar UI', 'Noto Sans Hebrew', 'SEC Mono CJK TC', 'Noto Sans Mono CJK SC', 'Noto Sans Ugaritic', 'Noto Serif Myanmar', 'Noto Sans Runic', 'Noto Sans Bhaiksuki', 'Noto Sans Kannada UI', 'SECGujarati', 'SEC Malayalam', 'Noto Sans Adlam', 'Noto Sans Tagalog', 'Noto Sans Tamil', 'Noto Sans Mono CJK TC', 'Noto Sans Old North Arabian', 'Noto Sans Lycian', 'Noto Sans Cypriot', 'Noto Sans Oriya UI', 'Noto Serif Khmer', 'Noto Sans Buhid', 'SEC Tamil Medium', 'SECCutiveMono', 'Noto Sans NKo', 'Noto Sans Meetei Mayek', 'Noto Sans Malayalam Medium', 'Noto Sans Avestan', 'Noto Sans Kaithi', 'Noto Sans Devanagari', 'Noto Sans CJK HK', 'Noto Sans Syriac Western', 'Noto Sans Sundanese', 'Noto Sans Kannada', 'Noto Sans Cuneiform', 'Noto Sans Sinhala', 'SEC CJK HK', 'Clock2017R_v0.4_170118', 'Roboto Thin', 'Noto Sans Ogham', 'Noto Sans Manichaean', 'Noto Sans Mro', 'Noto Sans Sinhala UI Medium', 'Noto Sans Old South Arabian', 'Noto Sans Syriac Estrangela', 'SECGurmukhi', 'Noto Serif Thai', 'Noto Serif Telugu', 'Noto Sans Bamum', 'Noto Sans Deseret', 'SamsungKhmerUI', 'Noto Sans Thai', 'SamsungOneUI', 'Noto Sans CJK JP', 'Noto Serif CJK SC', 'Noto Sans Armenian', 'Noto Sans Ol Chiki', 'Noto Sans Syloti Nagri', 'Noto Sans Javanese', 'Noto Sans Cherokee', 'Noto Sans Khmer', 'SECGurmukhi UI', 'SEC CJK JP', 'SEC Devanagari Medium', 'SEC Bengali Medium', 'Noto Sans Yi', 'Noto Sans Gurmukhi UI', 'SEC Tamil UI', 'Noto Serif CJK TC', 'Noto Sans Lao', 'SECTelugu', 'SEC Tamil UI Medium', 'Noto Sans CJK KR', 'Noto Sans Khmer UI', 'Coming Soon', 'Noto Naskh Arabic UI', 'Noto Sans Tifinagh', 'SEC CJK KR', 'Noto Sans Palmyrene', 'Noto Serif Bengali', 'Noto Sans Osage', 'Noto Sans Rejang', 'SEC Sans Lao UI', 'SamsungKorean_v2.0', 'Noto Sans Bengali UI Medium', 'Noto Serif Malayalam', 'Noto Sans Tamil UI', 'Noto Serif Devanagari', 'Noto Sans Phoenician', 'Noto Sans Inscriptional Parthian', 'Noto Sans Samaritan', 'SamsungMyanmarShan', 'Noto Serif Lao', 'Noto Sans Shavian', 'Noto Serif Gujarati', 'Noto Sans Georgian', 'SECKannada', 'SamsungMyanmarZawgyiUI', 'Noto Sans Vai', 'Noto Sans Imperial Aramaic', 'Noto Sans Buginese', 'Noto Sans Kayah Li', 'SEC Malayalam UI Medium', 'Noto Sans Lisu', 'SEC Tamil', 'Noto Sans Glagolitic', 'Noto Sans Multani', 'Droid Sans Mono', 'Noto Sans Kharoshthi', 'Noto Sans Myanmar', 'Noto Sans Telugu', 'SNum', 'Noto Sans Tamil Medium', 'Noto Naskh Arabic', 'Noto Sans Nabataean', 'Noto Sans Brahmi', 'Noto Sans Armenian Medium', 'Noto Sans CJK SC', 'Noto Sans Saurashtra', 'Noto Sans Tai Le', 'Noto Serif Gurmukhi', 'Noto Sans Symbols', 'Noto Sans Sinhala Medium', 'Noto Sans Bassa Vah', 'SNumCond', 'Noto Sans Lao UI', 'SECTelugu UI', 'Noto Sans Sharada', 'SEC CJK SC', 'Noto Sans Ethiopic', 'Noto Sans Marchen', 'SEC Malayalam Medium', 'SEC Devanagari UI', 'SEC Bengali UI', 'Noto Sans CJK TC', 'Roboto', 'Noto Sans Mongolian', 'Noto Sans Syriac Eastern', 'SEC CJK TC', 'Noto Sans Tamil UI Medium', 'clock2016_v1.1', 'CustomTkinter_shapes_font', 'Noto Sans Coptic', 'Roboto Condensed', 'Noto Sans Oriya', 'SamsungMyanmarUI', 'RobotoNum3L_ver2.2_191105 Light', 'Noto Sans Ahom', 'Noto Sans Miao', 'Noto Sans Hatran', 'Noto Sans Limbu', 'SECKannada UI', 'Noto Sans Thai UI', 'Noto Sans Tagbanwa', 'SEC Mono CJK HK', 'Noto Sans Devanagari Medium', 'SEC Malayalam UI', 'SECGujarati UI', 'SEC CJK Regular Extra', 'Noto Sans Gujarati UI', 'Noto Sans Tibetan', 'Noto Sans Devanagari UI', 'RobotoNum3R_ver2.0', 'Noto Sans Bengali', 'Noto Sans Batak', 'Noto Sans Mono CJK HK', 'Noto Serif Armenian', 'SEC Lao', 'Roboto Condensed Light', 'Noto Sans Bengali Medium', 'Noto Sans Meroitic', 'Noto Sans Phags Pa', 'Noto Serif', 'Noto Sans Mandaic', 'Noto Sans Bengali UI', 'SEC Mono CJK JP', 'Noto Serif Kannada', 'Noto Serif Sinhala', 'Noto Sans Chakma', 'Noto Sans Anatolian Hieroglyphs', 'Noto Sans Carian', 'Noto Sans Pau Cin Hau', 'Noto Sans New Tai Lue', 'SamsungKorean_v2.0 Light', 'Noto Sans Sinhala UI', 'Noto Sans Canadian Aboriginal', 'Noto Serif Hebrew', 'Noto Sans Devanagari UI Medium', 'Noto Sans Mono CJK JP', 'SEC Mono CJK KR', 'Noto Sans Tai Tham', 'Noto Sans Hanunoo', 'Noto Sans Cham', 'Dancing Script', 'Noto Sans Lepcha', 'Noto Sans Mono CJK KR', 'Noto Sans Elbasan', 'Noto Sans Gothic', 'Noto Sans Egyptian Hieroglyphs', 'Noto Sans Old Permic', 'Roboto Light', 'Cutive Mono', 'Roboto Condensed Medium', 'Noto Sans Thaana', 'Noto Sans Georgian Medium', 'SECFallback', 'Noto Serif Georgian', 'Roboto Medium'])
        font_family_selector.set(self.editor_font_family)
        font_family_selector.pack(pady=5)
        ttk.Label(settings_window, text="Editor Font Size:").pack(pady=5)
        font_size_entry = ttk.Entry(settings_window)
        font_size_entry.insert(0, str(self.editor_font_size))
        font_size_entry.pack(pady=5)
        def choose_fg():
            color = colorchooser.askcolor()[1]
            if color:
                fg_var.set(color)
        fg_var = tk.StringVar(value=self.editor_fg)
        ttk.Label(settings_window, text="Editor Text Color:").pack(pady=5)
        fg_frame = ttk.Frame(settings_window)
        fg_frame.pack(pady=5)
        ttk.Entry(fg_frame, textvariable=fg_var, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(fg_frame, text="Choose", command=choose_fg).pack(side=tk.LEFT, padx=5)
        def choose_bg():
            color = colorchooser.askcolor()[1]
            if color:
                bg_var.set(color)
        bg_var = tk.StringVar(value=self.editor_bg)
        ttk.Label(settings_window, text="Editor Background Color:").pack(pady=5)
        bg_frame = ttk.Frame(settings_window)
        bg_frame.pack(pady=5)
        ttk.Entry(bg_frame, textvariable=bg_var, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(bg_frame, text="Choose", command=choose_bg).pack(side=tk.LEFT, padx=5)
        def save_settings():
            self.editor_font_family = font_family_selector.get()
            try:
                self.editor_font_size = int(font_size_entry.get())
            except ValueError:
                messagebox.showerror("Error", "Font size must be an integer.")
                return
            self.editor_fg = fg_var.get()
            self.editor_bg = bg_var.get()
            if self.current_editor:
                self.current_editor.text.config(font=(self.editor_font_family, self.editor_font_size),
                                                fg=self.editor_fg, bg=self.editor_bg, insertbackground=self.editor_fg)
                self.current_editor._update_line_numbers()
            self.status_bar.config(text="Preferences updated")
            settings_window.destroy()
        ttk.Button(settings_window, text="Save", command=save_settings).pack(pady=20)

    def git_status(self):
        try:
            result = subprocess.run(["git", "status"], capture_output=True, text=True)
            messagebox.showinfo("Git Status", result.stdout)
        except Exception as e:
            messagebox.showerror("Git Error", str(e))

    def git_init(self):
        if not (self.current_editor and self.current_editor.file_path):
            messagebox.showwarning("No File", "Please open a project folder first.")
            return
        try:
            repo = git.Repo.init(os.path.dirname(self.current_editor.file_path))
            messagebox.showinfo("Git Init", "Git repository initialized successfully.")
        except Exception as e:
            messagebox.showerror("Git Init Error", str(e))

    def git_clone(self):
        repo_url = simpledialog.askstring("Git Clone", "Enter repository URL:")
        if repo_url:
            destination = filedialog.askdirectory()
            if destination:
                try:
                    git.Repo.clone_from(repo_url, destination)
                    messagebox.showinfo("Git Clone", "Repository cloned successfully.")
                except Exception as e:
                    messagebox.showerror("Git Clone Error", str(e))

    def git_push(self):
        if not (self.current_editor and self.current_editor.file_path):
            messagebox.showwarning("No File", "Please open a file first.")
            return
        try:
            repo = git.Repo(os.path.dirname(self.current_editor.file_path))
            repo.remotes.origin.push()
            messagebox.showinfo("Git Push", "Changes pushed to the remote repository.")
        except Exception as e:
            messagebox.showerror("Git Push Error", str(e))

    def git_pull(self):
        if not (self.current_editor and self.current_editor.file_path):
            messagebox.showwarning("No File", "Please open a file first.")
            return
        try:
            repo = git.Repo(os.path.dirname(self.current_editor.file_path))
            repo.remotes.origin.pull()
            messagebox.showinfo("Git Pull", "Changes pulled from the remote repository.")
        except Exception as e:
            messagebox.showerror("Git Pull Error", str(e))

    def git_commit_history(self):
        try:
            result = subprocess.run(["git", "log", "--oneline"], capture_output=True, text=True)
            messagebox.showinfo("Commit History", result.stdout)
        except Exception as e:
            messagebox.showerror("Git Error", str(e))

    def git_commit(self):
        message = simpledialog.askstring("Commit", "Enter commit message:")
        if message:
            try:
                subprocess.run(["git", "add", "."], check=True)
                subprocess.run(["git", "commit", "-m", message], check=True)
                messagebox.showinfo("Git Commit", "Commit successful.")
            except Exception as e:
                messagebox.showerror("Git Commit Error", str(e))

    def create_toolbar(self):
        #self.style = ttk.Style()
#        self.style.theme_use('clam')
#        self.style.configure('n.TButton', font=('Roboto', 8),
#                             foreground='lime', background='gray', relief=tk.RAISED, border=2, width=8)
        toolbar = ttk.Frame(self, relief=tk.RAISED)
        b1 = ttk.Button(toolbar, text="New", command=self.new_file, style='TButton',width=6).pack(side=tk.LEFT, padx=2, pady=2)
      #  b1.config(font=('AndroidClock',8))
        ttk.Button(toolbar, text="Open", command=self.open_file,style='TButton',width=6).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Save", command=self.save_file, style='TButton',width=6).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Run", command=self.run_file, style='TButton',width=6).pack(side=tk.LEFT, padx=2, pady=2)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(toolbar, text="Debug", command=self.start_debugger, style='TButton',width=6).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Git Status", command=self.git_status, style='TButton',width=8).pack(side=tk.LEFT, padx=2, pady=2)

    def create_status_bar(self):
        self.style = ttk.Style()
        self.fore_color = '#00FF00'
        self.back_color = '#383a42'
        self.style.theme_use('clam')
        self.status_bar = tk.Label(self, text="", relief=tk.SUNKEN, anchor=tk.W)#,bg=self.back_color)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_bar2 = tk.Frame(self, height=25, relief=tk.SUNKEN)
        self.status_bar2.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_bar2.config(bg=self.back_color)
        self.col_label = ttk.Label(self.status_bar2, text="Words: 0",foreground=self.fore_color,background=self.back_color)
        self.col_label.pack(side=tk.LEFT, padx=5)
        self.ln_col_label = ttk.Label(self.status_bar2, text="Ln 1, Col 1",foreground=self.fore_color,background=self.back_color)
        self.ln_col_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="Spaces: 4",foreground=self.fore_color,background=self.back_color).pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="UTF-8",foreground=self.fore_color,background=self.back_color).pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="LF",foreground=self.fore_color,background=self.back_color).pack(side=tk.LEFT, padx=5)
        self.status_var = tk.StringVar()
        ttk.Label(self.status_bar2,font=('AndroidClock',10) ,textvariable=self.status_var,foreground=self.fore_color,background=self.back_color).pack(side=tk.LEFT, padx=5)
        self.filetype_label = ttk.Label(self.status_bar2, text="☯ Unknown",foreground=self.fore_color,background=self.back_color)
        self.filetype_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="Layout: us",foreground=self.fore_color,background=self.back_color).pack(side=tk.LEFT, padx=5)

    def update_resource_usage(self):
        if psutil:
            cpu = '88'#psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            self.status_var.set(f"CPU: {cpu}% | Memory: {mem}%")
        else:
            self.status_var.set("Resource usage info unavailable (psutil not installed).")
        self.after(2000, self.update_resource_usage)

    def show_resource_monitor(self):
        if psutil:
            cpu = "88"#psutil.cpu_percent()
            mem = psutil.virtual_memory().percent
            messagebox.showinfo("Resource Monitor", f"CPU: {cpu}%\nMemory: {mem}%")
        else:
            messagebox.showwarning("Resource Monitor", "psutil not installed.")

    def security_analysis(self):
        if self.current_editor:
            code_text = self.current_editor.text.get("1.0", tk.END)
            warnings = []
            if "eval(" in code_text:
                warnings.append("Usage of eval() detected.")
            if "exec(" in code_text:
                warnings.append("Usage of exec() detected.")
            if warnings:
                messagebox.showwarning("Security Analysis", "\n".join(warnings))
            else:
                messagebox.showinfo("Security Analysis", "No immediate security issues detected.")

    def update_status(self, event):
        if self.current_editor:
            idx = self.current_editor.text.index(tk.INSERT)
            line, col = idx.split(".")
            words = len(self.current_editor.text.get("1.0", tk.END).split())
            self.ln_col_label.config(text=f"Ln {line}, Col {int(col)+1}")
            self.col_label.config(text=f"Words: {words}")

    def create_main_panes(self):
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        top_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
        main_pane.add(top_pane, weight=3)
        # Project Explorer Pane
        project_frame = ttk.Frame(top_pane, height=150, width=150)
        self.project_frame = project_frame
        tk.Label(project_frame, text="Project Explorer").pack(anchor=tk.W, padx=5, pady=5)
        top_pane.add(project_frame, weight=1)
        # Editor Pane with Notebook
        editor_frame = ttk.Frame(top_pane)
        self.editor_frame = editor_frame
        self.notebook = ttk.Notebook(editor_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        self.notebook.bind("<Button-1>", self.on_tab_click)
        top_pane.add(editor_frame, weight=4)
        # Assistant Pane (Code Assistant + Chat Bot)
        assistant_frame = ttk.Frame(top_pane, width=150)
        assistant_notebook = ttk.Notebook(assistant_frame)
        self.code_assistant = CodeAssistantPanel(assistant_notebook, self)
        self.chat_bot = ChatBotPanel(assistant_notebook)
        assistant_notebook.add(self.code_assistant, text="Assistant")
        assistant_notebook.add(self.chat_bot, text="Chat Bot")
        assistant_notebook.pack(fill=tk.BOTH, expand=True)
        top_pane.add(assistant_frame, weight=1)
        # Bottom Pane: Console Notebook
        self.console_frame = ttk.Frame(main_pane)
        self.console_notebook = ttk.Notebook(self.console_frame)
        self.console_notebook.pack(fill=tk.BOTH, expand=True)
        # Terminal Tab
        terminal_frame = ttk.Frame(self.console_notebook)
        if Terminal:
            self.terminal_tab_text = Terminal(terminal_frame, fg='lime', background='black', height=20)
            self.terminal_tab_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            self.terminal_tab_text = tk.Text(terminal_frame, height=100, bg="black", fg="white", width=10)
            self.terminal_tab_text.pack(fill=tk.BOTH, expand=True)
        self.console_notebook.add(terminal_frame, text="Terminal")
        # Debugger Tab
        debugger_frame = ttk.Frame(self.console_notebook)
        self.debugger_text = tk.Text(debugger_frame, bg="black", fg="red",height=80,width=10)
        self.debugger_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.console_notebook.add(debugger_frame, text="Debugger")
        # Python Interpreter Tab
        interpreter_frame = PythonInterpreterPanel(self.console_notebook)
        self.console_notebook.add(interpreter_frame, text="Python Interpreter")
        main_pane.add(self.console_frame, weight=1)
        # Project Explorer Treeview
        self.tree = ttk.Treeview(self.project_frame, selectmode="browse")
        default_dir = os.getcwd()
        root_node = self.tree.insert("", "end", "root", text=default_dir, open=True, values=[default_dir])
        if os.path.exists(default_dir):
            self.populate_tree(default_dir, "root")
        self.tree.bind("<Double-1>", self.on_tree_item_select)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def on_tab_click(self, event):
        x, y = event.x, event.y
        try:
            index = self.notebook.index("@%d,%d" % (x, y))
            tab_text = self.notebook.tab(index, "text")
            if event.x > self.notebook.winfo_width() - 20:
                if messagebox.askyesno("Close File", "Unsaved changes? Close this tab?"):
                    self.notebook.forget(index)
        except Exception:
            return

    def on_tab_changed(self, event):
        current = self.notebook.select()
        if current:
            self.current_editor = self.notebook.nametowidget(current)
            self.update_status(None)

    def open_project(self):
        directory = filedialog.askdirectory()
        if directory:
            self.populate_project_tree(directory)

    def populate_project_tree(self, directory):
        self.tree.delete(*self.tree.get_children())
        root_node = self.tree.insert("", "end", text=os.path.basename(directory),
                                      open=True, values=[directory])
        self.process_directory(root_node, directory)

    def process_directory(self, parent, path):
        try:
            for item in os.listdir(path):
                abs_path = os.path.join(path, item)
                if os.path.isdir(abs_path):
                    node = self.tree.insert(parent, "end", text=item, open=False, values=[abs_path])
                    self.process_directory(node, abs_path)
                else:
                    self.tree.insert(parent, "end", text=item, values=[abs_path])
        except PermissionError:
            pass

    def populate_tree(self, path, parent):
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                folder_id = self.tree.insert(parent, 'end', full_path, text=item, open=False, values=[full_path])
                self.populate_tree(full_path, folder_id)
            else:
                self.tree.insert(parent, 'end', full_path, text=item, values=[full_path])

    def on_tree_item_select(self, event):
        selected_item = self.tree.selection()[-1]
        values = self.tree.item(selected_item, "values")
        if values and os.path.isfile(values[0]):
            self.open_file_from_tree(values[0])

    def on_tree_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Open", command=lambda: self.on_tree_item_select(event))
            menu.add_command(label="Rename", command=lambda: self.rename_tree_item(item))
            menu.add_command(label="Delete", command=lambda: self.delete_tree_item(item))
            menu.add_command(label="New File", command=lambda: self.new_item_in_tree(item, is_folder=False))
            menu.add_command(label="New Folder", command=lambda: self.new_item_in_tree(item, is_folder=True))
            menu.post(event.x_root, event.y_root)

    def rename_tree_item(self, item):
        old_path = self.tree.item(item, "values")[0]
        new_name = simpledialog.askstring("Rename", "Enter new name:", initialvalue=os.path.basename(old_path))
        if new_name:
            new_path = os.path.join(os.path.dirname(old_path), new_name)
            try:
                os.rename(old_path, new_path)
                self.tree.item(item, text=new_name, values=[new_path])
                self.status_bar.config(text=f"Renamed to {new_path}")
            except Exception as e:
                messagebox.showerror("Rename Error", str(e))

    def delete_tree_item(self, item):
        file_path = self.tree.item(item, "values")[0]
        if messagebox.askyesno("Delete", f"Delete {file_path}?"):
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                else:
                    os.rmdir(file_path)
                self.tree.delete(item)
                self.status_bar.config(text=f"Deleted {file_path}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def new_item_in_tree(self, parent_item, is_folder=False):
        parent_path = self.tree.item(parent_item, "values")[0]
        name = simpledialog.askstring("New " + ("Folder" if is_folder else "File"),
                                      f"Enter name for the new {'folder' if is_folder else 'file'}:")
        if name:
            new_path = os.path.join(parent_path, name)
            try:
                if is_folder:
                    os.mkdir(new_path)
                else:
                    with open(new_path, "w") as f:
                        f.write("")
                self.tree.insert(parent_item, "end", text=name, values=[new_path])
                self.status_bar.config(text=f"Created {new_path}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def open_file_from_tree(self, file_path):
        try:
            with open(file_path, 'r') as file:
                content = file.read()
        except Exception as e:
            messagebox.showerror("File Open Error", str(e))
            return
        editor = CodeEditor(self.notebook, file_path=file_path,
                            font_family=self.editor_font_family,
                            font_size=self.editor_font_size,
                            fg=self.editor_fg,
                            bg=self.editor_bg)
        editor.text.insert("1.0", content)
        self.notebook.add(editor, text=os.path.basename(file_path) + "  ×")
        self.notebook.select(editor)
        self.current_editor = editor
        filetype = self.detect_file_type(file_path)
        self.filetype_label.config(text=f"☯ {filetype}")
        self.status_bar.config(text=f"Opened {file_path}")
        editor.highlight_syntax()

    def on_tab_click(self, event):
        # Detect if the click occurred in the rightmost 20 pixels of a tab label
        x, y = event.x, event.y
        try:
            index = self.notebook.index("@%d,%d" % (x, y))
            if index >= 0:
            	tab_text = self.notebook.tab(index, "text")
            	if tab_text.endswith("  ×"):
            		if messagebox.askyesno("Close File", "Unsaved changes. Do you want to close?"):
            			self.notebook.forget(index)
        except Exception:
            return
    def new_file(self):
        editor = CodeEditor(self.notebook,
                            font_family=self.editor_font_family,
                            font_size=self.editor_font_size,
                            fg=self.editor_fg,
                            bg=self.editor_bg)
        self.notebook.add(editor, text="Untitled  ×")
        self.notebook.select(editor)
        self.current_editor = editor
        editor.highlight_syntax()
        self.status_bar.config(text="New file created")
        self.filetype_label.config(text="☯ Unknown")

    def save_file(self):
        if self.current_editor:
            if self.current_editor.file_path:
                file_path = self.current_editor.file_path
            else:
                file_path = filedialog.asksaveasfilename(defaultextension=".py",
                                                         filetypes=[("All Files", "*.*"), ("Python Files", "*.py")])
                if not file_path:
                    return
                self.current_editor.file_path = file_path
                idx = self.notebook.index(self.notebook.select())
                self.notebook.tab(idx, text=os.path.basename(file_path) + "  ×")
            content = self.current_editor.text.get("1.0", tk.END)
            try:
                with open(file_path, "w") as f:
                    f.write(content)
                self.status_bar.config(text=f"Saved {file_path}")
                filetype = self.detect_file_type(file_path)
                self.filetype_label.config(text=f"☯ {filetype}")
                self.current_editor.highlight_syntax()
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def save_file_as(self):
        if self.current_editor:
            file_path = filedialog.asksaveasfilename(defaultextension=".py",
                                                     filetypes=[("All Files", "*.*"), ("Python Files", "*.py")])
            if file_path:
                self.current_editor.file_path = file_path
                idx = self.notebook.index(self.notebook.select())
                self.notebook.tab(idx, text=os.path.basename(file_path) + "  ×")
                self.save_file()
                filetype = self.detect_file_type(file_path)
                self.filetype_label.config(text=f"☯ {filetype}")

    def close_current_tab(self):
        current = self.notebook.select()
        if current:
            self.notebook.forget(current)

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*"), ("Python Files", "*.py")])
        if file_path:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
            except Exception as e:
                messagebox.showerror("File Open Error", str(e))
                return
            editor = CodeEditor(self.notebook, file_path=file_path,
                            font_family=self.editor_font_family,
                            font_size=self.editor_font_size,
                            fg=self.editor_fg,
                            bg=self.editor_bg)
            editor.text.insert("1.0", content)
            self.notebook.add(editor, text=os.path.basename(file_path) + "  ×")
            self.notebook.select(editor)
            self.current_editor = editor
            filetype = self.detect_file_type(file_path)
            editor.highlight_syntax()
            self.filetype_label.config(text=f"☯ {filetype}")
            self.status_bar.config(text=f"Opened {file_path}")

    def run_file(self):
        if self.current_editor and self.current_editor.file_path:
            ext = os.path.splitext(self.current_editor.file_path)[1].lower()
            if ext == ".py":
                command = ["python", self.current_editor.file_path]
            elif ext in [".sh", ".bash"]:
                command = ["bash", self.current_editor.file_path]
            elif ext in [".html", ".htm"]:
                webbrowser.open(self.current_editor.file_path)
                return
            elif ext == ".php":
                command = ["php", self.current_editor.file_path]
            elif ext == ".js":
                command = ["node", self.current_editor.file_path]
            else:
                command = ["python", self.current_editor.file_path]
            self.status_bar.config(text=f"Running {self.current_editor.file_path}")
            TerminalWindow(self, command)
        else:
            messagebox.showerror("Run Error", "Please save the file before running.")

    def start_debugger(self):
        if not (self.current_editor and self.current_editor.file_path):
            messagebox.showerror("Error", "No file open to debug.")
            return
        try:
            self.status_bar.config(text=f"Starting debugger for {self.current_editor.file_path}")
            debugpy.listen(("localhost", 8080))
            time.sleep(0.1)
            process = subprocess.Popen(["python", "-m", "pdb", self.current_editor.file_path],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            self.debugger_text.config(state="normal")
            self.debugger_text.insert(tk.END, stdout.decode())
            self.debugger_text.insert(tk.END, stderr.decode())
            self.debugger_text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Debugger Error", str(e))

    def autocomplete(self, event=None):
        if self.current_editor:
            try:
                line, col = self.current_editor.text.index("insert").split(".")
                line, col = int(line), int(col)
                completions = jedi.Script(code=self.current_editor.text.get("1.0", "insert"), 
                                          path=self.current_editor.file_path).complete(line=line, column=col)
                if completions:
                    completion_text = completions[0].name
                    self.current_editor.text.insert("insert", 
                        completion_text[len(self.current_editor.text.get("insert-1 chars", "insert")):])
            except Exception as e:
                print(f"Autocomplete Error: {e}")

    def light_theme(self):
        style = ttk.Style()
        style.theme_use("alt")
        style.configure("TLabel", background="white", foreground="black")
        style.configure("Treeview", background="white", foreground="black")
        style.configure("TFrame", background="white")
        style.configure('TButton', font=('Roboto', 8), foreground='lime', background='gray', relief=tk.RAISED, border=2)
        style.configure("TNotebook", background="white", foreground="black")
        self.configure(bg="white")
        self.status_bar.config(text="Theme Changed -> light mode")

    def dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TLabel", background="black", foreground="white")
        style.configure("TFrame", background="black")
        style.configure('TButton', font=('Roboto', 8), foreground='lime', background='#282c34', relief=tk.RAISED, border=2)
        style.configure("TNotebook", background="black", foreground="white")
        style.configure("Treeview", background="#282c34", foreground="lime")
        self.configure(bg="black")
        self.status_bar.config(text="Theme Changed -> dark mode")

    def about(self):
        messagebox.showinfo("About", "pyCoder_IDE v2.3\nEnhanced Python IDE with Git, plugin support, debugging, and more.\nEmail: mskalvin@cyberh4ck3r04.com")

    def live_share(self):
        messagebox.showinfo("Live Share", "Live share functionality is not implemented yet.")

    def multiple_cursors(self):
        messagebox.showinfo("Multiple Cursors", "Multiple cursors are not supported in this version.")

    def split_view(self):
        new_window = tk.Toplevel(self)
        new_window.title("Split View")
        text_widget = scrolledtext.ScrolledText(new_window, wrap=tk.NONE, undo=True,bg='#383a42',fg='#00FF00')
        text_widget.pack(fill=tk.BOTH, expand=True)
        if self.current_editor:
            text_widget.insert(tk.END, self.current_editor.text.get("1.0", tk.END))

    def insert_snippet(self, snippet):
        if self.current_editor:
            self.current_editor.text.insert(tk.INSERT, snippet)

    def show_help(self):
        help_text = (
            "pyCoder_IDE v2.3 Help\n\n"
            "Features:\n"
            " - Live Code Execution (Run Live): the code is re-executed every 2 seconds while live mode is on.\n"
            " - Syntax Highlighting\n"
            " - Code Navigation (Go to Definition, Go to Line, Find & Replace)\n"
            " - Integrated Terminal, Debugger, and Python Interpreter\n"
            " - Git Integration\n"
            " - Plugin Loader (load plugins from the 'plugins' folder)\n"
            " - Remote Debugging and Conditional Breakpoints\n"
            " - Stubs for Multiple Cursors and Split View\n"
            " - Customizable Themes and Preferences\n"
            "\nFor further documentation, please refer to the project wiki."
        )
        messagebox.showinfo("Documentation", help_text)

    def remote_debug(self):
        if debugpy:
            try:
                debugpy.listen(("localhost", 5678))
                messagebox.showinfo("Remote Debug", "Debugpy is now listening on port 5678. Attach your debugger.")
            except Exception as e:
                messagebox.showerror("Remote Debug", str(e))
        else:
            messagebox.showerror("Remote Debug", "debugpy is not installed.")

    def conditional_breakpoint(self):
        condition = simpledialog.askstring("Conditional Breakpoint", "Enter breakpoint condition:")
        if condition:
            try:
                if eval(condition, globals()):
                    if debugpy:
                        debugpy.breakpoint()
                        messagebox.showinfo("Conditional Breakpoint", "Breakpoint hit because condition evaluated to True.")
                    else:
                        messagebox.showwarning("Conditional Breakpoint", "debugpy not installed.")
                else:
                    messagebox.showinfo("Conditional Breakpoint", "Condition evaluated to False. No breakpoint triggered.")
            except Exception as e:
                messagebox.showerror("Conditional Breakpoint", str(e))

    def detect_file_type(self, file_path):
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        if ext == ".py":
            return "Python"
        elif ext == ".php":
            return "PHP"
        elif ext in [".html", ".htm"]:
            return "HTML"
        elif ext == ".java":
            return "Java"
        elif ext == ".js":
            return "JavaScript"
        elif ext == ".css":
            return "CSS"
        elif ext in [".sh", ".bash"]:
            return "Bash"
        elif ext == ".txt":
            return "Text"
        elif ext == ".inf":
            return "Malicious"
        elif ext == ".vbs":
            return "VisualBasic"
        elif ext == ".msk":
            return "KentFile"
        elif ext == ".exe":
            return "Executable"
        elif ext == ".bat":
            return "Batch"
        else:
            return "Unknown"
    def create_main_panes(self):
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        top_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
        main_pane.add(top_pane, weight=3)
        # Project Explorer Pane
        project_frame = ttk.Frame(top_pane, height=150, width=150)
        self.project_frame = project_frame
        tk.Label(project_frame, text="Project Explorer").pack(anchor=tk.W, padx=5, pady=5)
        top_pane.add(project_frame, weight=1)
        # Editor Pane with Notebook
        editor_frame = ttk.Frame(top_pane)
        self.editor_frame = editor_frame
        self.notebook = ttk.Notebook(editor_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        self.notebook.bind("<Button-1>", self.on_tab_click)
        top_pane.add(editor_frame, weight=4)
        # Assistant Pane (Code Assistant + Chat Bot)
        assistant_frame = ttk.Frame(top_pane, width=150)
        assistant_notebook = ttk.Notebook(assistant_frame)
        self.code_assistant = CodeAssistantPanel(assistant_notebook, self)
        self.chat_bot = ChatBotPanel(assistant_notebook)
        assistant_notebook.add(self.code_assistant, text="Assistant")
        assistant_notebook.add(self.chat_bot, text="Chat Bot")
        assistant_notebook.pack(fill=tk.BOTH, expand=True)
        top_pane.add(assistant_frame, weight=1)
        # Bottom Pane: Console Notebook
        self.console_frame = ttk.Frame(main_pane)
        self.console_notebook = ttk.Notebook(self.console_frame)
        self.console_notebook.pack(fill=tk.BOTH, expand=True)
        # Terminal Tab
        terminal_frame = ttk.Frame(self.console_notebook)
        if Terminal:
            self.terminal_tab_text = Terminal(terminal_frame, fg='lime', background='black', height=20)
            self.terminal_tab_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            self.terminal_tab_text = tk.Text(terminal_frame, height=20, bg="black", fg="white")
            self.terminal_tab_text.pack(fill=tk.BOTH, expand=True)
        self.console_notebook.add(terminal_frame, text="Terminal")
        # Debugger Tab
        debugger_frame = ttk.Frame(self.console_notebook)
        self.debugger_text = tk.Text(debugger_frame, bg="black", fg="red", height=20)
        self.debugger_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.console_notebook.add(debugger_frame, text="Debugger")
        # Python Interpreter Tab
        interpreter_frame = PythonInterpreterPanel(self.console_notebook)
        self.console_notebook.add(interpreter_frame, text="Python Interpreter")
        main_pane.add(self.console_frame, weight=1)
        # Project Explorer Treeview
        self.tree = ttk.Treeview(self.project_frame, selectmode="browse")
        default_dir = os.getcwd()
        root_node = self.tree.insert("", "end", "root", text=default_dir, open=True, values=[default_dir])
        if os.path.exists(default_dir):
            self.populate_tree(default_dir, "root")
        self.tree.bind("<Double-1>", self.on_tree_item_select)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

if __name__ == "__main__":
    app = FullVSIDE()
    app.mainloop()