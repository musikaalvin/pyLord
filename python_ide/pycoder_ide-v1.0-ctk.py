#!/usr/bin/env python
"""
pyCoder_IDE v2.3 (CustomTkinter Edition)
An enhanced Python IDE built with customtkinter featuring syntax highlighting,
live code execution, debugging, Git integration, plugin support, and more.
This version converts the original Tkinter‐based GUI to use customtkinter,
fixing the "['master'] are not supported arguments" error by removing
the reparenting via configure() and instead using the pack(in_=...) option.
"""

import customtkinter as ctk
from customtkinter import CTk, CTkToplevel, CTkFrame, CTkLabel, CTkButton, CTkEntry, CTkTextbox, CTkComboBox, CTkScrollbar, CTkTabview
import tkinter as tk  # for constants, Canvas, and menus/dialogs
from tkinter import filedialog, messagebox, simpledialog, colorchooser
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

# ---------------- Custom CTkNotebook -----------------
class CTkNotebook(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, *(), **kwargs)
        self.tabview = CTkTabview(self, corner_radius=0)
        self.tabview.pack(fill="both", expand=True)
        self.tabs = {}  # Stores tab name -> child widget
        self.current_tab = None

    def add(self, child, text):
        self.tabview.add(text)
        frame = self.tabview.tab(text)
        child.pack(in_=frame, fill="both", expand=True)
        self.tabs[text] = child
        self.current_tab = text

    def select(self, text):
        if text in self.tabs:
            self.tabview.set(text)
            self.current_tab = text

    def forget(self, text):
        if text in self.tabs:
            del self.tabs[text]
            for t in self.tabview.tab_names():
                self.tabview.delete(t)
            for t, widget in self.tabs.items():
                self.tabview.add(t)
                frame = self.tabview.tab(t)
                widget.pack(in_=frame, fill="both", expand=True)
            self.current_tab = list(self.tabs.keys())[0] if self.tabs else None

    def get_current(self):
        return self.tabs.get(self.current_tab)

    def tab_names(self):
        return list(self.tabs.keys())

# ----------------- Utility Classes & Functions ------------------

class StdoutRedirector(io.StringIO):
    """Redirects stdout/stderr to a CTkTextbox widget."""
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

class SearchReplaceDialog(CTkToplevel):
    def __init__(self, parent, editor):
        super().__init__(parent)
        self.title("Find and Replace")
        self.geometry("400x150")
        self.editor = editor
        self.grab_set()

        CTkLabel(self, text="Find:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.find_entry = CTkEntry(self, width=250)
        self.find_entry.grid(row=0, column=1, padx=5, pady=5)
        CTkLabel(self, text="Replace:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.replace_entry = CTkEntry(self, width=250)
        self.replace_entry.grid(row=1, column=1, padx=5, pady=5)

        btn_frame = CTkFrame(self)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5)
        CTkButton(btn_frame, text="Find Next", command=self.find_next).pack(side="left", padx=5)
        CTkButton(btn_frame, text="Replace", command=self.replace_one).pack(side="left", padx=5)
        CTkButton(btn_frame, text="Replace All", command=self.replace_all).pack(side="left", padx=5)
        CTkButton(btn_frame, text="Close", command=self.destroy).pack(side="left", padx=5)

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

class CodeAssistantPanel(ctk.CTkFrame):
    def __init__(self, master, ide, **kwargs):
        super().__init__(master, **kwargs)
        self.ide = ide
        self.mode = ctk.StringVar(value="Offline")
        CTkLabel(self, text="Assistant Mode:").pack(pady=(5, 0))
        self.mode_combo = CTkComboBox(self, variable=self.mode,
                                      values=["Offline", "Online"], width=120)
        self.mode_combo.pack(pady=(0, 5))
        self.update_button = CTkButton(self, text="Update Suggestions", command=self.update_suggestions)
        self.update_button.pack(pady=(0, 5))
        # Use a regular tk.Listbox for suggestions
        self.suggestions_list = tk.Listbox(self, height=15, bg='#282C34', fg='white')
        self.suggestions_list.pack(fill="both", expand=True, padx=5, pady=5, side="left")
        self.scrollbar = CTkScrollbar(self, orientation="vertical", command=self.suggestions_list.yview)
        self.suggestions_list.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

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
        else:
            self.suggestions_list.insert(tk.END, "Online mode not implemented.")

class ChatBotPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.mode = ctk.StringVar(value="Offline")
        top_frame = CTkFrame(self)
        top_frame.pack(fill="x", padx=5, pady=5)
        CTkLabel(top_frame, text="Chat Bot Mode:").pack(side="left")
        self.mode_combo = CTkComboBox(top_frame, variable=self.mode,
                                      values=["Offline", "Online"], width=100)
        self.mode_combo.pack(side="left", padx=5)
        self.chat_display = CTkTextbox(self, height=150)
        self.chat_display.configure(state="disabled", fg_color="#1E1E1E", text_color="white")
        self.chat_display.pack(fill="both", expand=True, padx=5, pady=5)
        bottom_frame = CTkFrame(self)
        bottom_frame.pack(fill="x", padx=5, pady=5)
        self.entry = CTkEntry(bottom_frame)
        self.entry.pack(side="left", fill="x", expand=True, padx=5)
        send_btn = CTkButton(bottom_frame, text="Send", command=self.send_message)
        send_btn.pack(side="left", padx=5)
        self.entry.bind("<Return>", lambda e: self.send_message())
        self.offline_bot = None

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
        self.chat_display.configure(state="normal")
        self.chat_display.insert(tk.END, text)
        self.chat_display.configure(state="disabled")
        self.chat_display.see(tk.END)

# ----------------- Code Editor ------------------

class CodeEditor(ctk.CTkFrame):
    def __init__(self, master, file_path=None, font_family="Courier New", font_size=10,
                 fg="white", bg="#1E1E1E"):
        super().__init__(master)
        self.file_path = file_path
        self.font_family = font_family
        self.font_size = font_size
        self.fg = fg
        self.bg = bg
        self._update_pending = None

        # Vertical scrollbar
        self.v_scrollbar = CTkScrollbar(self, orientation="vertical")
        self.v_scrollbar.pack(side="right", fill="y")
        # Horizontal scrollbar
        self.h_scrollbar = CTkScrollbar(self, orientation="horizontal")
        self.h_scrollbar.pack(side="bottom", fill="x")
        # Line numbers canvas (using tk.Canvas)
        self.linenumbers = tk.Canvas(self, width=40, bg="#2b2b2b", highlightthickness=0)
        self.linenumbers.pack(side="left", fill="y")
        # Code text widget using CTkTextbox
        self.text = CTkTextbox(self, padx=4, pady=4, wrap="none",
                               fg_color=self.bg, text_color=self.fg,
                               font=(self.font_family, self.font_size), width=800, height=600)
        self.text.pack(side="left", fill="both", expand=True)
        self.text.configure(yscrollcommand=self.on_scroll, xscrollcommand=self.h_scrollbar.set)
        self.v_scrollbar.configure(command=self.yview)
        self.h_scrollbar.configure(command=self.text.xview)
        self.text.bind("<Control-a>", self.select_all)
        self.text.bind("<KeyRelease>", self.schedule_update)
        self.text.bind("<ButtonRelease>", lambda e: self.winfo_toplevel().update_status(e))
        self.text.bind("<MouseWheel>", lambda e: self._update_line_numbers())
        self.text.bind("<Return>", self.auto_indent)
        self.setup_tags()
        self.folds = {}
        self.linenumbers.bind("<Button-1>", self.on_linenumber_click)

    def select_all(self, event=None):
        self.text.tag_add("sel", "1.0", tk.END)
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
            self.text.tag_config(str(token), **tag_opts)

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
        self.text.tag_config(tag, elide=True)
        self.folds[line_num] = {"folded": True, "range": (start, end), "tag": tag}

    def unfold_block(self, line_num):
        fold_info = self.folds.get(line_num)
        if fold_info:
            tag = fold_info.get("tag")
            self.text.tag_remove(tag, "1.0", tk.END)
            self.folds[line_num]["folded"] = False

# ----------------- Terminal & Interpreter Panels ------------------

class TerminalWindow(CTkToplevel):
    def __init__(self, master, command):
        super().__init__(master)
        self.title("Terminal")
        self.geometry("700x300")
        self.terminal = CTkTextbox(self, fg_color="black", text_color="lime")
        self.terminal.configure(state="disabled")
        self.terminal.pack(fill="both", expand=True)
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
                self.terminal.configure(state="normal")
                self.terminal.insert(tk.END, line)
                self.terminal.configure(state="disabled")
                self.terminal.see(tk.END)
        except queue.Empty:
            pass
        if self.process.poll() is None or not self.queue.empty():
            self.after(100, self.update_text)

class PythonInterpreterPanel(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.text = CTkTextbox(self, font=("Courier", 10), fg_color="black", text_color="lime", width=600, height=400)
        self.text.pack(expand=True, fill="both")
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

class FullVSIDE(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("pyCoder_IDE v2.3 (CustomTkinter Edition)")
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
        self.console_frame = CTkFrame(self, height=150)
        self.console_frame.pack(fill="both", side="bottom")

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
        plugin_window = CTkToplevel(self)
        plugin_window.title("Plugins")
        CTkLabel(plugin_window, text="Available Plugins:").pack(pady=5)
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
        CTkButton(plugin_window, text="Run Plugin", command=run_selected_plugin).pack(pady=5)

    def open_terminal_shell(self):
        dialog = CTkToplevel(self)
        dialog.title("Select Terminal Shell")
        CTkLabel(dialog, text="Choose a shell:").pack(padx=10, pady=10)
        shell_var = ctk.StringVar(value="bash")
        shell_combo = CTkComboBox(dialog, variable=shell_var, values=["bash", "zsh", "fish"], width=120)
        shell_combo.pack(padx=10, pady=10)
        def launch_shell():
            shell = shell_var.get()
            command = [shell]
            try:
                TerminalWindow(self, command)
            except Exception as e:
                messagebox.showerror("Terminal Error", str(e))
            dialog.destroy()
        CTkButton(dialog, text="Open Terminal", command=launch_shell).pack(padx=10, pady=10)

    # ---------------- Restored Methods ----------------
    def open_project(self):
        project_path = filedialog.askdirectory()
        if project_path:
            self.tree.delete(*self.tree.get_children())  # Clear previous project
            root_node = self.tree.insert("", "end", "root", text=project_path, open=True, values=[project_path])
            self.populate_project_tree(project_path, root_node)

    def populate_project_tree(self, directory, parent_node):
        """Recursively add files and folders to the project tree."""
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isdir(item_path):
                folder_node = self.tree.insert(parent_node, "end", text=item, values=[item_path])
                self.populate_project_tree(item_path, folder_node)
            else:
                self.tree.insert(parent_node, "end", text=item, values=[item_path])
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
            self.current_editor.text.tag_add("sel", "1.0", tk.END)
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
        run_menu.add_command(label="Run Live", command=self.run_live_code, accelerator="F5")
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

    def run_live_code(self):
        self.console = CTkTextbox(self.console_frame, height=10, fg_color="black", text_color="lime")
        self.console.pack(fill="both", expand=True)
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
            lint_window = CTkToplevel(self)
            lint_window.title("Lint Results")
            txt = CTkTextbox(lint_window, width=100, height=30)
            txt.pack(fill="both", expand=True)
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
        settings_window = CTkToplevel(self)
        settings_window.title("Preferences")
        settings_window.geometry("450x400")
        CTkLabel(settings_window, text="Editor Font Family:").pack(pady=5)
        font_family_selector = CTkComboBox(settings_window, values=['Courier New', 'Arial', 'Times New Roman', 'Consolas', 'AndroidClock'], width=200)
        font_family_selector.set(self.editor_font_family)
        font_family_selector.pack(pady=5)
        CTkLabel(settings_window, text="Editor Font Size:").pack(pady=5)
        font_size_entry = CTkEntry(settings_window)
        font_size_entry.insert(0, str(self.editor_font_size))
        font_size_entry.pack(pady=5)
        def choose_fg():
            color = colorchooser.askcolor()[1]
            if color:
                fg_var.set(color)
        fg_var = tk.StringVar(value=self.editor_fg)
        CTkLabel(settings_window, text="Editor Text Color:").pack(pady=5)
        fg_frame = CTkFrame(settings_window)
        fg_frame.pack(pady=5)
        CTkEntry(fg_frame, textvariable=fg_var, width=100).pack(side="left", padx=5)
        CTkButton(fg_frame, text="Choose", command=choose_fg).pack(side="left", padx=5)
        def choose_bg():
            color = colorchooser.askcolor()[1]
            if color:
                bg_var.set(color)
        bg_var = tk.StringVar(value=self.editor_bg)
        CTkLabel(settings_window, text="Editor Background Color:").pack(pady=5)
        bg_frame = CTkFrame(settings_window)
        bg_frame.pack(pady=5)
        CTkEntry(bg_frame, textvariable=bg_var, width=100).pack(side="left", padx=5)
        CTkButton(bg_frame, text="Choose", command=choose_bg).pack(side="left", padx=5)
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
                self.current_editor.text.configure(font=(self.editor_font_family, self.editor_font_size),
                                                   text_color=self.editor_fg, fg_color=self.editor_bg)
                self.current_editor._update_line_numbers()
            self.status_bar.configure(text="Preferences updated")
            settings_window.destroy()
        CTkButton(settings_window, text="Save", command=save_settings).pack(pady=20)

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
        toolbar = CTkFrame(self)
        toolbar.pack(side="top", fill="x")
        CTkButton(toolbar, text="New", command=self.new_file, width=60).pack(side="left", padx=2, pady=2)
        CTkButton(toolbar, text="Open", command=self.open_file, width=60).pack(side="left", padx=2, pady=2)
        CTkButton(toolbar, text="Save", command=self.save_file, width=60).pack(side="left", padx=2, pady=2)
        CTkButton(toolbar, text="Run", command=self.run_file, width=60).pack(side="left", padx=2, pady=2)
        CTkButton(toolbar, text="Debug", command=self.start_debugger, width=60).pack(side="left", padx=2, pady=2)
        CTkButton(toolbar, text="Git Status", command=self.git_status, width=80).pack(side="left", padx=2, pady=2)

    def create_status_bar(self):
        self.status_bar = CTkLabel(self, text="", anchor="w")
        self.status_bar.pack(side="bottom", fill="x")
        self.status_bar2 = CTkFrame(self, height=25)
        self.status_bar2.pack(fill="x", side="bottom")
        self.status_bar2.configure(fg_color="#383a42")
        self.col_label = CTkLabel(self.status_bar2, text="Words: 0", text_color="#00FF00")
        self.col_label.pack(side="left", padx=5)
        self.ln_col_label = CTkLabel(self.status_bar2, text="Ln 1, Col 1", text_color="#00FF00")
        self.ln_col_label.pack(side="left", padx=5)
        CTkLabel(self.status_bar2, text="Spaces: 4", text_color="#00FF00").pack(side="left", padx=5)
        CTkLabel(self.status_bar2, text="UTF-8", text_color="#00FF00").pack(side="left", padx=5)
        CTkLabel(self.status_bar2, text="LF", text_color="#00FF00").pack(side="left", padx=5)
        self.status_var = tk.StringVar()
        CTkLabel(self.status_bar2, font=('AndroidClock',10), textvariable=self.status_var, text_color="#00FF00").pack(side="left", padx=5)
        self.filetype_label = CTkLabel(self.status_bar2, text="☯ Unknown", text_color="#00FF00")
        self.filetype_label.pack(side="left", padx=5)
        CTkLabel(self.status_bar2, text="Layout: us", text_color="#00FF00").pack(side="left", padx=5)

    def update_resource_usage(self):
        if psutil:
            cpu = '88'  # Example value; replace with psutil.cpu_percent() if desired
            mem = psutil.virtual_memory().percent
            self.status_var.set(f"CPU: {cpu}% | Memory: {mem}%")
        else:
            self.status_var.set("Resource usage info unavailable (psutil not installed).")
        self.after(2000, self.update_resource_usage)

    def show_resource_monitor(self):
        if psutil:
            cpu = "88"  # Example value
            mem = psutil.virtual_memory().percent
            messagebox.showinfo("Resource Monitor", f"CPU: {cpu}%\nMemory: {mem}%")
        else:
            messagebox.showwarning("Resource Monitor", "psutil not installed.")

    def update_status(self, event):
        if self.current_editor:
            idx = self.current_editor.text.index(tk.INSERT)
            line, col = idx.split(".")
            words = len(self.current_editor.text.get("1.0", tk.END).split())
            self.ln_col_label.configure(text=f"Ln {line}, Col {int(col)+1}")
            self.col_label.configure(text=f"Words: {words}")

    def create_main_panes(self):
        main_pane = CTkFrame(self)
        main_pane.pack(fill="both", expand=True)
        top_pane = CTkFrame(main_pane)
        top_pane.pack(fill="both", expand=True)
        # Project Explorer Pane
        project_frame = CTkFrame(top_pane, width=150)
        self.project_frame = project_frame
        CTkLabel(project_frame, text="Project Explorer").pack(anchor="w", padx=5, pady=5)
        project_frame.pack(side="left", fill="y")
        # Editor Pane with Notebook
        editor_frame = CTkFrame(top_pane)
        self.editor_frame = editor_frame
        self.notebook = CTkNotebook(editor_frame)
        self.notebook.pack(fill="both", expand=True)
        editor_frame.pack(side="left", fill="both", expand=True)
        # Assistant Pane (Code Assistant + Chat Bot)
        assistant_frame = CTkFrame(top_pane, width=150)
        assistant_notebook = CTkNotebook(assistant_frame)
        # FIX: Pass self (the IDE instance) as the ide parameter.
        self.code_assistant = CodeAssistantPanel(assistant_notebook, ide=self)
        self.chat_bot = ChatBotPanel(assistant_notebook)
        assistant_notebook.add(self.code_assistant, text="Assistant")
        assistant_notebook.add(self.chat_bot, text="Chat Bot")
        assistant_notebook.pack(fill="both", expand=True)
        assistant_frame.pack(side="left", fill="y")
        # Bottom Pane: Console Notebook
        self.console_frame = CTkFrame(main_pane)
        self.console_notebook = CTkNotebook(self.console_frame)
        self.console_notebook.pack(fill="both", expand=True)
        # Terminal Tab
        terminal_frame = CTkFrame(self.console_notebook)
        if Terminal:
            self.terminal_tab_text = Terminal(terminal_frame, fg='lime', background='black', height=20)
            self.terminal_tab_text.pack(fill="both", expand=True, padx=5, pady=5)
        else:
            self.terminal_tab_text = CTkTextbox(terminal_frame, fg_color="black", text_color="white")
            self.terminal_tab_text.pack(fill="both", expand=True)
        self.console_notebook.add(terminal_frame, text="Terminal")
        # Debugger Tab
        debugger_frame = CTkFrame(self.console_notebook)
        self.debugger_text = CTkTextbox(debugger_frame, fg_color="black", text_color="red")
        self.debugger_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.console_notebook.add(debugger_frame, text="Debugger")
        # Python Interpreter Tab
        interpreter_frame = PythonInterpreterPanel(self.console_notebook)
        self.console_notebook.add(interpreter_frame, text="Python Interpreter")
        self.console_frame.pack(fill="both", expand=True)
        # Project Explorer Treeview (using tk.ttk.Treeview)
        self.tree = tk.ttk.Treeview(self.project_frame, selectmode="browse")
        default_dir = os.getcwd()
        root_node = self.tree.insert("", "end", "root", text=default_dir, open=True, values=[default_dir])
        if os.path.exists(default_dir):
            
            self.populate_project_tree(default_dir, "root")
        self.tree.bind("<Double-1>", self.on_tree_item_select)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

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
        editor = CodeEditor(self.notebook,
                            file_path=file_path,
                            font_family=self.editor_font_family,
                            font_size=self.editor_font_size,
                            fg=self.editor_fg,
                            bg=self.editor_bg)
        editor.text.insert("1.0", content)
        self.notebook.add(editor, text=os.path.basename(file_path) + "  ×")
        self.notebook.select(os.path.basename(file_path) + "  ×")
        self.current_editor = editor
        filetype = "Python" if file_path.endswith(".py") else "Unknown"
        self.filetype_label.configure(text=f"☯ {filetype}")
        self.status_bar.configure(text=f"Opened {file_path}")
        editor.highlight_syntax()

    def new_file(self):
        editor = CodeEditor(self.notebook,
                              font_family=self.editor_font_family,
                              font_size=self.editor_font_size,
                              fg=self.editor_fg,
                              bg=self.editor_bg)
        self.notebook.add(editor, text="Untitled  ×")
        self.notebook.select("Untitled  ×")
        self.current_editor = editor
        editor.highlight_syntax()
        self.status_bar.configure(text="New file created")
        self.filetype_label.configure(text="☯ Unknown")

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
                self.notebook.add(self.current_editor, text=os.path.basename(file_path) + "  ×")
            content = self.current_editor.text.get("1.0", tk.END)
            try:
                with open(file_path, "w") as f:
                    f.write(content)
                self.status_bar.config(text=f"Saved {file_path}")
                filetype = "Python" if file_path.endswith(".py") else "Unknown"
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
                self.notebook.add(self.current_editor, text=os.path.basename(file_path) + "  ×")
                self.save_file()
                filetype = "Python" if file_path.endswith(".py") else "Unknown"
                self.filetype_label.config(text=f"☯ {filetype}")

    def close_current_tab(self):
        if self.current_editor:
            current_tab = self.notebook.current_tab
            self.notebook.forget(current_tab)

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
            self.notebook.select(os.path.basename(file_path) + "  ×")
            self.current_editor = editor
            filetype = "Python" if file_path.endswith(".py") else "Unknown"
            editor.highlight_syntax()
            self.filetype_label.config(text=f"☯ {filetype}")
            self.status_bar.config(text=f"Opened {file_path}")

    def start_debugger(self):
        if not (self.current_editor and self.current_editor.file_path):
            messagebox.showerror("Error", "No file open to debug.")
            return
        try:
            self.status_bar.configure(text=f"Starting debugger for {self.current_editor.file_path}")
            debugpy.listen(("localhost", 8080))
            time.sleep(0.1)
            process = subprocess.Popen(["python", "-m", "pdb", self.current_editor.file_path],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            self.debugger_text.configure(state="normal")
            self.debugger_text.insert(tk.END, stdout.decode())
            self.debugger_text.insert(tk.END, stderr.decode())
            self.debugger_text.configure(state="disabled")
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
                    self.current_editor.text.insert("insert", completion_text[len(self.current_editor.text.get("insert-1 chars", "insert")):])
            except Exception as e:
                print(f"Autocomplete Error: {e}")

    # Placeholder methods for features not implemented in this conversion:
    def remote_debug(self):
        messagebox.showinfo("Remote Debug", "Remote Debug not implemented.")

    def conditional_breakpoint(self):
        messagebox.showinfo("Conditional Breakpoint", "Conditional Breakpoint not implemented.")

    def live_share(self):
        messagebox.showinfo("Live Share", "Live Share not implemented.")

    def split_view(self):
        messagebox.showinfo("Split View", "Split View not implemented.")

    def multiple_cursors(self):
        messagebox.showinfo("Multiple Cursors", "Multiple Cursors not implemented.")

    def light_theme(self):
        ctk.set_appearance_mode("light")

    def dark_theme(self):
        ctk.set_appearance_mode("dark")

    def insert_snippet(self, snippet):
        if self.current_editor:
            self.current_editor.text.insert(tk.INSERT, snippet)

    def show_help(self):
        messagebox.showinfo("Help", "Documentation not available.")

    def about(self):
        messagebox.showinfo("About", "pyCoder_IDE v2.3 (CustomTkinter Edition)\nBy mskalvin")

if __name__ == "__main__":
    app = FullVSIDE()
    app.mainloop()