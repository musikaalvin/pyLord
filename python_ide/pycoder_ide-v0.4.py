import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext, ttk
import subprocess
import os
import threading
import queue
import debugpy
import keyword, time, re, pylint.lint, webbrowser
from pygments import lex
from pygments.lexers import PythonLexer
from pygments.styles import get_style_by_name
# Removed: 
from tkterminal import Terminal
try:
    import git
except ImportError:
    jedi = None
    git = None


# --- Code Assistant Panel (Offline & Online) ---
class CodeAssistantPanel(tk.Frame):
    def __init__(self, master, ide, **kwargs):
        super().__init__(master, **kwargs)
        self.ide = ide
        self.mode = tk.StringVar(value="Offline")
        # Mode selection
        mode_label = ttk.Label(self, text="Assistant Mode:")
        mode_label.pack(pady=(5, 0))
        self.mode_combo = ttk.Combobox(self, textvariable=self.mode,
                                       values=["Offline", "Online"], state="readonly", width=12)
        self.mode_combo.pack(pady=(0, 5))
        # Button to update suggestions
        self.update_button = ttk.Button(self, text="Update Suggestions", command=self.update_suggestions)
        self.update_button.pack(pady=(0, 5))
        # Listbox with scrollbar to show suggestions
        self.suggestions_list = tk.Listbox(self, height=15, bg='black', fg='white')
        self.suggestions_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5, side=tk.LEFT)
        self.scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.suggestions_list.yview)
        self.suggestions_list.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        # Initial style update
        self.configure(bg="#282C34")
        self.suggestions_list.configure(bg="#282C34", fg="white")

    
    def update_suggestions(self):
        self.suggestions_list.delete(0, tk.END)
        mode = self.mode.get()
        import jedi
        if mode == "Offline":
            if not jedi:
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
            # Simulated online suggestions.
            dummy_suggestions = [
                "Online Suggestion 1",
                "Online Suggestion 2",
                "Online Suggestion 3",
                "Online Suggestion 4",
            ]
            for suggestion in dummy_suggestions:
                self.suggestions_list.insert(tk.END, suggestion)
        else:
            self.suggestions_list.insert(tk.END, "Unknown mode.")


# --- Code Editor Widget ---
class CodeEditor(tk.Frame):
    def __init__(self, master, file_path=None):
        super().__init__(master)
        self.file_path = file_path
        # Line numbers widget
        self.linenumbers = tk.Text(self, width=4, padx=4, takefocus=0, border=0,
                                   background="grey", fg="blue", state="disabled",
                                   wrap="none", font=("Courier New", 10))
        self.linenumbers.pack(side=tk.LEFT, fill=tk.Y)
        # Main text widget
        self.text = scrolledtext.ScrolledText(self, undo=True, wrap="word",
                                              bg="#1E1E1E", fg="white", insertbackground="white",
                                              font=("Courier New", 10), width=15)
        self.text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        self.text.config(yscrollcommand=self._on_text_scroll)
        # Bind Return for auto-indent and KeyRelease to update suggestions
        self.text.bind("<Return>", self.auto_indent)
        self.text.bind("<KeyRelease>", self._on_key_release)
        #self.text.bind("<KeyRelease>", self.update_status)
        self.linenumbers.bind("<Button-1>", self.goto_clicked_line)
        self.setup_tags()
        self._update_line_numbers()

    #def update_status(self, event):
#        line, col = self.text.index(tk.INSERT).split(".")
#        self.ln_col_label.config(text=f"Ln {line}, Col {int(col) + 1}")
    def goto_selected_line(self, event):
        """ Open a file from the project explorer """
        selected = self.linenumbers.curselection()
        if selected:
            self.line = self.linenumbers.get(selected[0])
            self.goto_line(self.line)
            #self.open_file(file_path)
    def goto_line(self,line):
        line_number = self.line#simpledialog.askinteger("Go to Line", "Enter line number:")
        if line_number:
            self.current_editor.text.mark_set("insert", f"{line_number}.0")
            self.current_editor.text.see(f"{line_number}.0")
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
        self.text.mark_set("range_start", "1.0")
        for tag in self.text.tag_names():
            self.text.tag_remove(tag, "1.0", tk.END)
        for token, txt in lex(content, PythonLexer()):
            self.text.mark_set("range_end", f"range_start + {len(txt)}c")
            self.text.tag_add(str(token), "range_start", "range_end")
            self.text.mark_set("range_start", "range_end")

    def _on_text_scroll(self, *args):
        self.linenumbers.yview_moveto(args[0])

    def _on_key_release(self, event=None):
        self._update_line_numbers()
        self.highlight_syntax()
        # Automatically update suggestions as user types.
        top = self.winfo_toplevel()
        if hasattr(top, "code_assistant"):
            top.code_assistant.update_suggestions()

    def auto_indent(self, event):
        """Insert a newline and copy the previous line's indentation."""
        index = self.text.index("insert")
        line_no = int(index.split('.')[0])
        indent = ""
        if line_no > 1:
            prev_line = self.text.get(f"{line_no - 1}.0", f"{line_no - 1}.end")
            for ch in prev_line:
                if ch in (" ", "\t"):
                    indent += ch
                else:
                    break
        self.text.insert("insert", "\n" + indent)
        return "break"

    def goto_clicked_line(self, event):
        """Jump to the clicked line in the editor."""
        try:
            line = self.linenumbers.index("@%d,%d" % (event.x, event.y)).split(".")[0]
            self.text.mark_set("insert", f"{line}.0")
            self.text.see(f"{line}.0")
        except Exception:
            pass

    def _update_line_numbers(self):
        self.linenumbers.config(state="normal")
        self.linenumbers.delete("1.0", tk.END)
        line_count = int(self.text.index("end-1c").split(".")[0])
        lines = "\n".join(str(i) for i in range(1, line_count + 1))
        self.linenumbers.insert("1.0", lines)
        self.linenumbers.config(state="disabled")


# --- Terminal Window ---
class TerminalWindow(tk.Toplevel):
    def __init__(self, master, command):
        super().__init__(master)
        self.title("Terminal")
        self.geometry("700x300")
        self.terminal = scrolledtext.ScrolledText(self, state='disabled', fg='lime', bg='black')
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
        self.geometry("700x900")
        self.current_editor = None
        self.theme = "dark"  # default theme
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
        self.bind("<Control-x>", lambda _: self.close)
        self.bind("<Control-r>", lambda _: self.run_file())
        #self.bind("<Control-f>", lambda _: self.find2())
        self.bind("<Control-g>", lambda _: self.goto_line())
        self.bind("<Control-space>", lambda _: self.autocomplete())
        self.bind("<F5>", lambda _: self.run_file())
        self.bind("<Control-f>", lambda e: self.search_replace())
        self.bind("<KeyRelease>", self.update_status)
        #self.current_editor.text.bind("<KeyRelease>", self.update_status)
        

    def create_menu(self):
        menubar = tk.Menu(self)
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
        edit_menu = tk.Menu(menubar)
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
        run_menu = tk.Menu(menubar, tearoff=0)
        run_menu.add_command(label="Run File", accelerator="F5", command=self.run_file)
        run_menu.add_command(label="Debug", command=self.start_debugger)
        run_menu.add_command(label="Lint", command=self.lint_file)
        menubar.add_cascade(label="Run ▶", menu=run_menu)
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
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Prog langs.", command=self.preferences)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Configure")
        settings_menu.add_command(label="Extensions")
        settings_menu.add_command(label="Update")
        settings_menu.add_command(label="Donate")
        menubar.add_cascade(label="⚙️ Settings", menu=settings_menu)
        themes_menu = tk.Menu(menubar, tearoff=0)
        themes_menu.add_command(label="Light Mode", command=self.light_theme)
        themes_menu.add_command(label="Dark Mode", command=self.dark_theme)
        themes_menu.add_command(label="Theme Settings", command=self.open_settings)
        menubar.add_cascade(label="Themes", menu=themes_menu)
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
        self.style.configure('new.TFrame', font=('RobotoNum3L_ver2.2_191105 Light', 6),
                             foreground='lime', background='gray', relief=tk.RAISED)
        self.style.configure('new.TButton', font=('RobotoNum3L_ver2.2_191105 Light', 7),
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
                             font=('RobotoNum3L_ver2.2_191105 Light', 8), relief=tk.RAISED)
        self.status_bar = ttk.Label(self, style="new.TLabel", text="", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # --- Status Bar ---
        self.status_bar2 = ttk.Frame(self, height=25, relief=tk.SUNKEN, style="new.TLabel")
        self.status_bar2.pack(fill=tk.X, side=tk.BOTTOM)
        
    
        self.col_label = ttk.Label(self.status_bar2, text="Column Selection",style='new.TLabel')
        self.col_label.pack(side=tk.LEFT, padx=5)
        self.ln_col_label = ttk.Label(self.status_bar2, text="Ln 1, Col 1",style='new.TLabel')
        self.ln_col_label.pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="Spaces: 4",style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="UTF-8",style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text=" LF ",style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text=" ⚠ 0 ",style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="☯  Python",style='new.TLabel').pack(side=tk.LEFT, padx=5)
        ttk.Label(self.status_bar2, text="Layout: us",style='new.TLabel').pack(side=tk.LEFT, padx=5)

    def update_status(self, event):
        line, col = self.current_editor.text.index(tk.INSERT).split(".")
        self.ln_col_label.config(text=f"Ln {line}, Col {int(col) + 1}")
    def create_main_panes(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('new.TFrame', font=('RobotoNum3L_ver2.2_191105 Light', 6),
                             foreground='lime', background='gray', relief=tk.RAISED)
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL, height=10)
        main_pane.pack(fill=tk.BOTH, expand=True, anchor='nw')
        self.main_pane = main_pane
        top_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
        self.top_pane = top_pane
        main_pane.add(top_pane)
        # Project Explorer pane
        project_frame = ttk.Frame(top_pane, height=300, style='new.TFrame')
        self.project_frame = project_frame
        project_label = ttk.Label(project_frame, text="Project Explorer")
        project_label.pack(anchor=tk.W, padx=5, pady=5)
        top_pane.add(project_frame)
        # Editor pane with Notebook
        editor_frame = ttk.Frame(top_pane, style='new.TFrame', height=30)
        self.editor_frame = editor_frame 
        self.notebook = ttk.Notebook(editor_frame, style='new.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True)
        top_pane.add(editor_frame)
        # Code Assistant pane
        assistant_frame = ttk.Frame(top_pane, width=90, style='new.TFrame')
        self.assistant_frame = assistant_frame
        self.code_assistant = CodeAssistantPanel(assistant_frame, self)
        self.code_assistant.pack(fill=tk.BOTH, expand=True)
        top_pane.add(assistant_frame)
        # Integrated Terminal pane (at the bottom)
        self.console_frame = ttk.Frame(main_pane, height=10, style='new.TFrame')
        try:
            self.terminal = Terminal(self.console_frame, fg='lime', background='black', height=20)
            self.terminal.pack(fill=tk.BOTH, anchor='center', expand=True, padx=5, pady=5)
        except Exception as e:
            messagebox.showerror('Terminal Error', f'Failed to load terminal: {e}')
        main_pane.add(self.console_frame)
        # Populate the project explorer tree with a default directory (adjust as needed)
        #self.style = ttk.Style()
        #self.style.theme_use('classic')
        self.style.configure('new.Treeview', foreground='cyan', background='#282c34', font=('Jokerman', 8))
        self.tree = ttk.Treeview(self.project_frame, style='new.Treeview',
                                 selectmode="browse", height=20)
        default_dir = '/sdcard/kentsoft/MY_PYTHON_PROJECTS/'
        self.tree.insert("", "end", "root", text="Project Files", open=True, values=[default_dir])
        if os.path.exists(default_dir):
            self.populate_tree(default_dir, "root")
        self.tree.bind("<Double-1>", self.on_tree_item_select)
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

    def open_file_from_tree(self, file_path):
        try:
            with open(file_path, 'r') as file:
                content = file.read()
        except Exception as e:
            messagebox.showerror("File Open Error", str(e))
            return
        self.current_file = file_path
        editor = CodeEditor(self.notebook, file_path=file_path)
        editor.text.insert("1.0", content)
        self.notebook.add(editor, text=os.path.basename(file_path))
        self.notebook.select(editor)
        self.current_editor = editor
        self.status_bar.config(text=f"Opened {file_path}")

    def on_project_right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Open", command=lambda: self.on_tree_item_select(event))
            menu.add_command(label="Delete", command=lambda: self.delete_project_item(item))
            menu.post(event.x_root, event.y_root)

    def delete_project_item(self, item):
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

    def autocomplete(self, event=None):
        line, col = self.current_editor.text.index("insert").split(".")
        line, col = int(line), int(col)
        try:
            import jedi
            completions = jedi.Script(code=self.current_editor.text.get("1.0", "insert"), path=self.current_file).complete(line=line, column=col)
            if completions:
                completion_text = completions[0].name
                self.current_editor.text.insert("insert", completion_text[len(self.current_editor.text.get("insert-1 chars", "insert")):])
        except Exception as e:
            print(f"Autocomplete Error: {e}")

    def new_file(self):
        editor = CodeEditor(self.notebook)
        self.editor = editor 
        self.notebook.add(editor, text="Untitled")
        self.notebook.select(editor)
        self.current_editor = editor
        self.status_bar.config(text="New file created")
        self.close_button = ttk.Button(self.editor_frame, style='new.TButton',
                                       text="×", command=self.close)
        self.close_button.pack(side="right", pady=5, padx=4)

    def save_file(self):
        if self.current_editor:
            if self.current_editor.file_path:
                file_path = self.current_editor.file_path
            else:
                file_path = filedialog.asksaveasfilename(defaultextension=".py",
                                                         filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
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
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def save_file_as(self):
        if self.current_editor:
            file_path = filedialog.asksaveasfilename(defaultextension=".py",
                                                     filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
            if file_path:
                self.current_editor.file_path = file_path
                idx = self.notebook.index(self.notebook.select())
                self.notebook.tab(idx, text=os.path.basename(file_path))
                self.save_file()

    def close(self):
        if messagebox.askyesno("Close File", "Unsaved changes. Do you want to close?"):
            self.close_current_tab()

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
        if file_path:
            try:
                with open(file_path, "r") as f:
                    content = f.read()
            except Exception as e:
                messagebox.showerror("File Open Error", str(e))
                return
            editor = CodeEditor(self.notebook, file_path=file_path)
            editor.text.insert("1.0", content)
            self.notebook.add(editor, text=os.path.basename(file_path))
            self.notebook.select(editor)
            self.current_editor = editor
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

    def search_replace(self):
        if not self.current_editor:
            return
        SearchReplaceDialog(self, self.current_editor)

    def jump_to_line(self, linenumber):
        if linenumber is not None:
            try:
                self.current_editor.text.see(f"{linenumber}.0")
                self.current_editor.text.mark_set("insert", f"{linenumber}.0")
            except tk.TclError:
                messagebox.showerror("Error", "Invalid line number.")

    def goto_line(self):
        line_number = simpledialog.askinteger("Go to Line", "Enter line number:")
        if line_number:
            self.current_editor.text.mark_set("insert", f"{line_number}.0")
            self.current_editor.text.see(f"{line_number}.0")
            #self.jump_to_line(line_number)

    def goto_clicked_line(self, event):
        try:
            line = self.linenumbers.index("@%d,%d" % (event.x, event.y)).split(".")[0]
            self.current_editor.text.mark_set("insert", f"{line}.0")
            self.current_editor.text.see(f"{line}.0")
        except Exception:
            pass

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

    def get_current_editor(self):
        current_tab = self.notebook.select()
        return self.notebook.nametowidget(current_tab).winfo_children()[0]

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
        style.theme_use("alt")  # Light Theme
        style.configure("new.TLabel", background="white", foreground="black")
        style.configure("new.Treeview", background="white", foreground="black")
        style.configure("new.TFrame", background="white")	   
        self.style.configure('new.TButton', font=('RobotoNum3L_ver2.2_191105 Light', 8),
                             foreground='lime', background='gray', relief=tk.RAISED, border=2, width=8)
        style.configure("new.TNotebook", background="white", foreground="black")
        self.configure(bg="white")
        self.status_bar.config(text="Theme Changed -> lightmode")

    def dark_theme(self):
        style = ttk.Style()
        style.theme_use("clam")  # Dark Theme
        style.configure("new.TLabel", background="black", foreground="white")
        style.configure("new.TFrame", background="black")
        self.style.configure('new.TButton', font=('RobotoNum3L_ver2.2_191105 Light', 8),
                             foreground='lime', background='#282c34', relief=tk.RAISED, border=2)
        style.configure("new.TNotebook", background="black", foreground="white")
        style.configure("new.Treeview", background="#282c34", foreground="lime")
        self.configure(bg="black")
        self.status_bar.config(text="Theme Changed -> darkmode")

    def about(self):
        messagebox.showinfo("About", "Python IDE v2.0 - A Python IDE with Git integration and an integrated online/offline code assistant by KentLabs\nEmail: mskalvin@cyberh4ck3r04.com")

    def open_settings(self):
        import tkinter
        from tkinter import ttk
        try:
            settings_window = tkinter.Toplevel(self)
            settings_window.title("Preferences")
            settings_window.geometry("400x300")
            ttk.Label(settings_window, text="Editor Font:").pack(pady=5)
            font_selector = ttk.Combobox(settings_window, values=["Courier", "Arial", "Times New Roman"])
            font_selector.pack(pady=5)
            self.theme = "dark"
            dark_mode_toggle = ttk.Checkbutton(settings_window, text="Enable Dark Mode", command=self.dark_theme)
            dark_mode_toggle.pack(pady=5)
            ttk.Button(settings_window, text="Save", command=settings_window.destroy).pack(pady=10)
        except Exception as e:
            messagebox.showwarning('Exception', f'{e}')

    def git_status(self):
        try:
            result = subprocess.run(["git", "status"], capture_output=True, text=True)
            messagebox.showinfo("Git Status", result.stdout)
        except Exception as e:
            messagebox.showerror("Git Error", str(e))

    def preferences(self):
        messagebox.showinfo("Preferences", "Preferences feature coming soon!")

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
        """Displays Git commit history."""
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


class SearchReplaceDialog(tk.Toplevel):
    def __init__(self, parent, editor):
        super().__init__(parent)
        self.editor = editor
        self.title("Search and Replace")
        self.geometry("400x150")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Find:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.find_entry = tk.Entry(self, width=30)
        self.find_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(self, text="Replace:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.replace_entry = tk.Entry(self, width=30)
        self.replace_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(self, text="Find", command=self.find_text).grid(row=2, column=0, padx=5, pady=5)
        tk.Button(self, text="Replace", command=self.replace_text).grid(row=2, column=1, padx=5, pady=5)

    def replace_text(self):
        target = self.find_entry.get()
        replacement = self.replace_entry.get()
        content = self.editor.text.get("1.0", tk.END)
        new_content = content.replace(target, replacement)
        self.editor.text.delete("1.0", tk.END)
        self.editor.text.insert("1.0", new_content)
        self.editor.text.tag_remove("search", "1.0", tk.END)
        messagebox.showinfo("Replace", "All occurrences replaced.")

    def find_text(self):
        target = self.find_entry.get()
        self.editor.text.tag_remove("search", "1.0", tk.END)
        if target:
            start = "1.0"
            while True:
                pos = self.editor.text.search(target, start, stopindex=tk.END)
                if not pos:
                    break
                end = f"{pos}+{len(target)}c"
                self.editor.text.tag_add("search", pos, end)
                start = end
            self.editor.text.tag_config("search", background="grey")


if __name__ == "__main__":
    app = FullVSIDE()
    app.mainloop()
