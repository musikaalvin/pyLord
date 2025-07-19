import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, colorchooser
import subprocess, os, threading, queue, time, re, debugpy
import pylint.lint
import webbrowser
#import openai  # for online chatbot
try:
    import git
    import openai
    import chatterbot
    import chatterbot_corpus
except ImportError:
    git = None
    openai = None
    chatterbot = None
    chatterbot_corpus = None
try:
    from tkterminal import Terminal
except ImportError:
    Terminal = None
import jedi
from pygments import lex
from pygments.lexers import PythonLexer, HtmlLexer, JavascriptLexer, PhpLexer, CssLexer, BashLexer
from pygments.styles import get_style_by_name

# --- Utility: Choose lexer based on file extension ---
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

# --- Code Assistant Panel ---
class CodeAssistantPanel(tk.Frame):
    def __init__(self, master, ide, **kwargs):
        super().__init__(master, **kwargs)
        self.ide = ide
        self.mode = tk.StringVar(value="Offline")
        mode_label = ttk.Label(self, text="Assistant Mode:")
        mode_label.pack(pady=(5, 0))
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
                code = self.ide.current_editor.text.get("1.0", tk.END)
                cursor_index = self.ide.current_editor.text.index(tk.INSERT)
                try:
                    line, column = map(int, cursor_index.split('.'))
                except Exception:
                    line, column = 1, 0
                try:
                    script = jedi.Script(code, path=self.ide.current_editor.file_path)
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
            # For online suggestions, we use the OpenAI API to get completions.
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

# --- Chat Bot Panel ---
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
        # For offline chatbot, initialize once if possible
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
            # Use OpenAI's API for a real online chatbot response.
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
            # Offline chatbot using ChatterBot
            try:
                from chatterbot import ChatBot
                from chatterbot.trainers import ChatterBotCorpusTrainer
                if not self.offline_bot:
                    self.offline_bot = ChatBot("Offline Bot")
                    trainer = ChatterBotCorpusTrainer(self.offline_bot)
                    trainer.train("chatterbot.corpus.english")
                bot_response = str(self.offline_bot.get_response(msg))
            except Exception as e:
                bot_response = f"Offline error: {e}"
        self.after(500, lambda: self.append_text(f"Bot: {bot_response}\n"))

    def append_text(self, text):
        self.chat_display.config(state="normal")
        self.chat_display.insert(tk.END, text)
        self.chat_display.config(state="disabled")
        self.chat_display.see(tk.END)

# --- Code Editor Widget ---
class CodeEditor(tk.Frame):
    def __init__(self, master, file_path=None, font_family="Courier New", font_size=10,
                 fg="white", bg="#1E1E1E"):
        super().__init__(master)
        self.file_path = file_path
        self.font_family = font_family
        self.font_size = font_size
        self.fg = fg
        self.bg = bg
        # Shared vertical scrollbar
        self.v_scrollbar = ttk.Scrollbar(self, orient="vertical")
        self.v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        # Canvas for line numbers
        self.linenumbers = tk.Canvas(self, width=40, bg="#2b2b2b", highlightthickness=0)
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        # Main text widget
        self.text = tk.Text(self, undo=True, wrap="none", yscrollcommand=self.on_scroll,
                            bg=self.bg, fg=self.fg, insertbackground=self.fg,
                            font=(self.font_family, self.font_size))
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.v_scrollbar.config(command=self.yview)
        # Bind events for updating line numbers and cursor position
        self.text.bind("<KeyRelease>", self._on_key_release)
        self.text.bind("<ButtonRelease>", lambda e: self.winfo_toplevel().update_status(e))
        self.text.bind("<MouseWheel>", lambda e: self._on_change())
        self.text.bind("<Button-4>", lambda e: self._on_change())
        self.text.bind("<Button-5>", lambda e: self._on_change())
        self.text.bind("<Return>", self.auto_indent)
        self.setup_tags()
        self._update_line_numbers()

    def on_scroll(self, *args):
        self.v_scrollbar.set(*args)
        self.text.yview_moveto(args[0])
        self._update_line_numbers()

    def yview(self, *args):
        self.text.yview(*args)
        self._update_line_numbers()

    def _on_change(self, event=None):
        self._update_line_numbers()

    def _on_key_release(self, event=None):
        self._update_line_numbers()
        self.highlight_syntax()
        top = self.winfo_toplevel()
        if hasattr(top, "code_assistant"):
            top.code_assistant.update_suggestions()

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
            self.text.tag_remove(tag, "1.0", tk.END)
        lexer = get_lexer_for_file(self.file_path) if self.file_path else PythonLexer()
        self.text.mark_set("range_start", "1.0")
        for token, txt in lex(content, lexer):
            self.text.mark_set("range_end", f"range_start + {len(txt)}c")
            self.text.tag_add(str(token), "range_start", "range_end")
            self.text.mark_set("range_start", "range_end")

    def auto_indent(self, event):
        line_start = self.text.get("insert linestart", "insert")
        indent = re.match(r"\s*", line_start).group()
        if line_start.rstrip().endswith(":"):
            indent += "    "
        self.text.insert("insert", "\n" + indent)
        return "break"

    def _update_line_numbers(self):
        self.linenumbers.delete("all")
        i = self.text.index("@0,0")
        while True:
            dline = self.text.dlineinfo(i)
            if dline is None:
                break
            y = dline[1]
            line_num = str(i).split(".")[0]
            self.linenumbers.create_text(38, y, anchor="ne", text=line_num,
                                         fill="grey", font=(self.font_family, self.font_size))
            i = self.text.index(f"{i}+1line")

# --- Terminal Window ---
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
        self.logo = (
            ".--.\n"
            "|o o |\n"
            "|\_/ |\n"
            "//   \\ \\\n"
            "(|     | )\n"
            "/'\\_   _/`\\\n"
            "\\___) (___/\n"
            "PYTHON_PROGRAMMING_IDE By mskalvin\n"
            "pyLord@cyb3rh4ck3r04\n"
        )
        self.queue.put(f"{self.logo}\n")
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

# --- Main IDE Application ---
class FullVSIDE(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("pyCoder_IDE")
        self.geometry("900x900")
        # Default font and theme settings:
        self.editor_font_family = "Courier New"
        self.editor_font_size = 10
        self.editor_fg = "white"
        self.editor_bg = "#1E1E1E"
        self.theme = "dark"
        self.current_editor = None
        self.create_widgets()
        self.bind_shortcuts()

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
        self.bind("<Control-x>", lambda _: self.close())
        self.bind("<Control-r>", lambda _: self.run_file())
        self.bind("<Control-g>", lambda _: self.goto_line())
        self.bind("<Control-space>", lambda _: self.autocomplete())
        self.bind("<F5>", lambda _: self.run_file())
        self.bind("<Control-f>", lambda e: self.search_replace())
        self.bind("<KeyRelease>", self.update_status)

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
        edit_menu.add_command(label="Find", command=self.find2, accelerator="Ctrl+F")
        edit_menu.add_command(label="Go to Line", command=self.goto_line, accelerator="Ctrl+G")
        edit_menu.add_command(label="Find and Replace", command=self.search_replace, accelerator="Ctrl+F")
        menubar.add_cascade(label="Edit", menu=edit_menu)
        # Run Menu
        run_menu = tk.Menu(menubar, tearoff=0)
        run_menu.add_command(label="Run File", accelerator="F5", command=self.run_file)
        run_menu.add_command(label="Compile File", command=self.compile_file)
        run_menu.add_command(label="Debug", command=self.start_debugger)
        run_menu.add_command(label="Lint", command=self.lint_file)
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
        git_menu.add_command(label="Commit Changes", command=self.git_commit)
        menubar.add_cascade(label="Git", menu=git_menu)
        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Preferences", command=self.open_settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        # Settings Menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Configure")
        settings_menu.add_command(label="Extensions")
        settings_menu.add_command(label="Update")
        settings_menu.add_command(label="Donate")
        menubar.add_cascade(label="⚙️ Settings", menu=settings_menu)
        # Themes Menu
        themes_menu = tk.Menu(menubar, tearoff=0)
        themes_menu.add_command(label="Light Mode", command=self.light_theme)
        themes_menu.add_command(label="Dark Mode", command=self.dark_theme)
        themes_menu.add_command(label="Theme Settings", command=self.open_settings)
        menubar.add_cascade(label="Themes", menu=themes_menu)
        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menubar)

    def lint_file(self):
        current_tab = self.notebook.select()
        if not current_tab:
            return
        filename = self.notebook.tab(current_tab, "text")
        if filename:
            pylint.lint.Run([filename], do_exit=False)
            self.terminal.config(state="normal")
            self.terminal.insert("end", "\nLinting Completed")
            self.terminal.config(state="disabled")

    def create_toolbar(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('new.TFrame', font=('Roboto', 10),
                             foreground='lime', background='gray', relief=tk.RAISED)
        self.style.configure('new.TButton', font=('Roboto', 10),
                             foreground='lime', background='gray', relief=tk.RAISED, width=8, border=2)
        toolbar = ttk.Frame(self, relief=tk.RAISED, style='new.TFrame')
        ttk.Button(toolbar, text="New", command=self.new_file, style='new.TButton').pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Open", command=self.open_file, style='new.TButton').pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Save", command=self.save_file, style='new.TButton').pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Run", command=self.run_file, style='new.TButton').pack(side=tk.LEFT, padx=2, pady=2)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(toolbar, text="Debug", style='new.TButton', command=self.start_debugger).pack(side=tk.LEFT, padx=2, pady=2)
        ttk.Button(toolbar, text="Git Status", style='new.TButton', command=self.git_status).pack(side=tk.LEFT, padx=2, pady=2)

    def create_status_bar(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('new.TLabel', foreground='lime', background='#1E1E1E',
                             font=('Roboto', 8), relief=tk.RAISED)
        self.status_bar = ttk.Label(self, style="new.TLabel", text="", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_bar2 = ttk.Frame(self, height=25, relief=tk.SUNKEN, style="new.TLabel")
        self.status_bar2.pack(fill=tk.X, side=tk.BOTTOM)
        self.col_label = ttk.Label(self.status_bar2, text="Words: 0", style='new.TLabel')
        self.col_label.pack(side=tk.LEFT, padx=5)
        self.ln_col_label = ttk.Label(self.status_bar2, text="Ln 1, Col 1", style='new.TLabel')
        self.ln_col_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="Spaces: 4", style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="UTF-8", style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="LF", style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="⚠ 0", style='new.TLabel').pack(side=tk.LEFT, padx=5)
        self.filetype_label = ttk.Label(self.status_bar2, text="☯ Unknown", style='new.TLabel')
        self.filetype_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="Layout: us", style='new.TLabel').pack(side=tk.LEFT, padx=5)

    def update_status(self, event):
        if self.current_editor:
            idx = self.current_editor.text.index(tk.INSERT)
            #wd = len(self.current_editor)
            line, col = idx.split(".")
            self.ln_col_label.config(text=f"Ln {line}, Col {int(col)+1}")
            self.col_label.config(text=f"Words: {col}")

    def create_main_panes(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        self.main_pane = main_pane
        top_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
        main_pane.add(top_pane, weight=3)
        # Project Explorer Pane
        project_frame = ttk.Frame(top_pane, style='new.TFrame')
        self.project_frame = project_frame
        project_label = ttk.Label(project_frame, text="Project Explorer")
        project_label.pack(anchor=tk.W, padx=5, pady=5)
        top_pane.add(project_frame, weight=1)
        # Editor Pane with Notebook
        editor_frame = ttk.Frame(top_pane, style='new.TFrame')
        self.editor_frame = editor_frame
        self.notebook = ttk.Notebook(editor_frame, style='new.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True)
        top_pane.add(editor_frame, weight=4)
        # Right Pane: Assistant Notebook (Code Assistant + Chat Bot)
        assistant_frame = ttk.Frame(top_pane, width=150, style='new.TFrame')
        assistant_notebook = ttk.Notebook(assistant_frame, style='new.TNotebook')
        self.code_assistant = CodeAssistantPanel(assistant_notebook, self)
        self.chat_bot = ChatBotPanel(assistant_notebook)
        assistant_notebook.add(self.code_assistant, text="Assistant")
        assistant_notebook.add(self.chat_bot, text="Chat Bot")
        assistant_notebook.pack(fill=tk.BOTH, expand=True)
        top_pane.add(assistant_frame, weight=1)
        # Bottom Pane: Integrated Terminal
        self.console_frame = ttk.Frame(main_pane, style='new.TFrame')
        try:
            if Terminal:
                self.terminal = Terminal(self.console_frame, fg='lime', background='black', height=20)
                self.terminal.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            else:
                self.terminal = tk.Text(self.console_frame, height=10, bg="black", fg="white")
                self.terminal.pack(fill=tk.BOTH, expand=True)
        except Exception as e:
            messagebox.showerror('Terminal Error', f'Failed to load terminal: {e}')
        main_pane.add(self.console_frame, weight=1)
        # Enhance Tree Explorer: bind right-click for context menu
        self.tree = ttk.Treeview(self.project_frame, style='new.Treeview', selectmode="browse")
        default_dir = os.getcwd()
        self.tree.insert("", "end", "root", text="Project Files", open=True, values=[default_dir])
        if os.path.exists(default_dir):
            self.populate_tree(default_dir, "root")
        self.tree.bind("<Double-1>", self.on_tree_item_select)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

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
                    node = self.tree.insert(parent, "end", text=item,
                                            open=False, values=[abs_path])
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
        self.notebook.add(editor, text=os.path.basename(file_path))
        self.notebook.select(editor)
        self.current_editor = editor
        filetype = self.detect_file_type(file_path)
        self.filetype_label.config(text=f"☯ {filetype}")
        self.status_bar.config(text=f"Opened {file_path}")

    def autocomplete(self, event=None):
        line, col = self.current_editor.text.index("insert").split(".")
        line, col = int(line), int(col)
        try:
            completions = jedi.Script(code=self.current_editor.text.get("1.0", "insert"), 
                                      path=self.current_editor.file_path).complete(line=line, column=col)
            if completions:
                completion_text = completions[0].name
                self.current_editor.text.insert("insert", 
                    completion_text[len(self.current_editor.text.get("insert-1 chars", "insert")):])
        except Exception as e:
            print(f"Autocomplete Error: {e}")

    def new_file(self):
        editor = CodeEditor(self.notebook,
                            font_family=self.editor_font_family,
                            font_size=self.editor_font_size,
                            fg=self.editor_fg,
                            bg=self.editor_bg)
        self.notebook.add(editor, text="Untitled")
        self.notebook.select(editor)
        self.current_editor = editor
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
                self.notebook.tab(idx, text=os.path.basename(file_path))
            content = self.current_editor.text.get("1.0", tk.END)
            try:
                with open(file_path, "w") as f:
                    f.write(content)
                self.status_bar.config(text=f"Saved {file_path}")
                filetype = self.detect_file_type(file_path)
                self.filetype_label.config(text=f"☯ {filetype}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def save_file_as(self):
        if self.current_editor:
            file_path = filedialog.asksaveasfilename(defaultextension=".py",
                                                     filetypes=[("All Files", "*.*"), ("Python Files", "*.py")])
            if file_path:
                self.current_editor.file_path = file_path
                idx = self.notebook.index(self.notebook.select())
                self.notebook.tab(idx, text=os.path.basename(file_path))
                self.save_file()

    def close(self):
        if messagebox.askyesno("Close File", "Unsaved changes. Do you want to close?"):
            self.close_current_tab()

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
            self.notebook.add(editor, text=os.path.basename(file_path))
            self.notebook.select(editor)
            self.current_editor = editor
            filetype = self.detect_file_type(file_path)
            self.filetype_label.config(text=f"☯ {filetype}")
            self.status_bar.config(text=f"Opened {file_path}")

    def close_current_tab(self):
        current = self.notebook.select()
        if current:
            self.notebook.forget(current)

    def run_file(self):
        if self.current_editor and self.current_editor.file_path:
            command = ["python", self.current_editor.file_path]
            self.status_bar.config(text=f"Running {self.current_editor.file_path}")
            TerminalWindow(self, command)
        else:
            messagebox.showerror("Run Error", "Please save the file before running.")

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
        else:
            messagebox.showerror("Compile Error", "Compilation not supported for this file type.")
            return
        try:
            self.status_bar.config(text=f"Compiling {file_path}...")
            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout + "\n" + result.stderr
            self.status_bar.config(text="Compilation finished.")
            TerminalWindow(self, cmd)  # show output in terminal window
        except Exception as e:
            messagebox.showerror("Compile Error", str(e))

    def search_replace(self):
        if not self.current_editor:
            return
        SearchReplaceDialog(self, self.current_editor)

    def goto_line(self):
        line_number = simpledialog.askinteger("Go to Line", "Enter line number:")
        if line_number:
            self.current_editor.text.mark_set("insert", f"{line_number}.0")
            self.current_editor.text.see(f"{line_number}.0")

    def find2(self):
        search_term = simpledialog.askstring("Find", "Enter text to find:")
        if search_term:
            self.current_editor.text.tag_remove("found", "1.0", tk.END)
            start_index = "1.0"
            while True:
                start_index = self.current_editor.text.search(search_term, start_index, stopindex=tk.END)
                if not start_index:
                    break
                end_index = f"{start_index}+{len(search_term)}c"
                self.current_editor.text.tag_add("found", start_index, end_index)
                start_index = end_index
            self.current_editor.text.tag_config("found", background="grey")
        else:
            messagebox.showwarning('Error','NOT FOUND !')

    def start_debugger(self):
        current_tab = self.notebook.select()
        if not current_tab or not (self.current_editor and self.current_editor.file_path):
            messagebox.showerror("Error", "No file open to debug.")
            return
        filename = self.notebook.tab(current_tab, "text")
        self.status_bar.config(text=f"Starting Debugger for {filename}")
        debugpy.listen(("localhost", 8080))
        time.sleep(0.1)
        process = subprocess.Popen(["python", "-m", "pdb", self.current_editor.file_path],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.terminal.config(state="normal")
        self.terminal.insert(tk.END, stdout.decode())
        self.terminal.insert(tk.END, stderr.decode())
        self.terminal.config(state=tk.DISABLED)

    def light_theme(self):
        style = ttk.Style()
        style.theme_use("alt")
        style.configure("new.TLabel", background="white", foreground="black")
        style.configure("new.Treeview", background="white", foreground="black")
        style.configure("new.TFrame", background="white")
        self.style.configure('new.TButton', font=('Roboto', 8),
                             foreground='lime', background='gray', relief=tk.RAISED, border=2, width=8)
        style.configure("new.TNotebook", background="white", foreground="black")
        self.configure(bg="white")
        self.status_bar.config(text="Theme Changed -> light mode")

    def dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("new.TLabel", background="black", foreground="white")
        style.configure("new.TFrame", background="black")
        self.style.configure('new.TButton', font=('Roboto', 8),
                             foreground='lime', background='#282c34', relief=tk.RAISED, border=2)
        style.configure("new.TNotebook", background="black", foreground="white")
        style.configure("new.Treeview", background="#282c34", foreground="lime")
        self.configure(bg="black")
        self.status_bar.config(text="Theme Changed -> dark mode")

    def about(self):
        messagebox.showinfo("About", "Python IDE v2.1\nA Python IDE with Git integration, real online/offline chat bot assistance,\ncompilation support, and enhanced file explorer and customization options.\nEmail: mskalvin@cyberh4ck3r04.com")

    def open_settings(self):
        settings_window = tk.Toplevel(self)
        settings_window.title("Preferences")
        settings_window.geometry("450x400")
        # Font Family
        ttk.Label(settings_window, text="Editor Font Family:").pack(pady=5)
        font_family_selector = ttk.Combobox(settings_window, values=["Courier New", "Arial", "Times New Roman", "Consolas"])
        font_family_selector.set(self.editor_font_family)
        font_family_selector.pack(pady=5)
        # Font Size
        ttk.Label(settings_window, text="Editor Font Size:").pack(pady=5)
        font_size_entry = ttk.Entry(settings_window)
        font_size_entry.insert(0, str(self.editor_font_size))
        font_size_entry.pack(pady=5)
        # Foreground Color
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
        # Background Color
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
        # Save Button
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
                messagebox.showerror("Git Error", str(e))

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
        elif ext == ".bat":
            return "Batch"
        else:
            return "Unknown"

if __name__ == "__main__":
    app = FullVSIDE()
    app.mainloop()