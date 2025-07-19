#importing all necessary modules
try:
    import tkinter as tk
    from tkinter import filedialog, ttk, scrolledtext, messagebox,simpledialog,font
    import subprocess,jedi, keyword,os,pylint.lint,webbrowser,queue,debugpy,threading,time
    from pygments import lex, lexer
    #from colors import *
    #import git
    from pygments.formatter import Formatter
    from pygments.lexers import PythonLexer
    from flask import Flask, render_template_string
    from tkcode import CodeEditor
    from tkterminal import Terminal
except ImportError:
    messagebox.showerror("Missing Dependency", "Please install 'tkcode' using:\n pip install tkcode")
    sys.exit(1)
# Initialize Flask app for live preview
app = Flask(__name__)
# Global Variables
current_file = None
project_dir = None
git_repo = None

class PythonIDE():
    def __init__(self,root):
        super().__init__()
        self.root = root
        self.root.title("Full-Featured Python IDE")
        self.root.geometry("700x1000")#android
        #self.root.geometry("1000x600")#pc
        self.root.configure(bg="#282C34")
        #self.root.configure(bg="#1e1e1e")
        self.open_files = {}
        self.file_tabs = {}
        self.current_file = None
        self.filename = None
        self.tab_id = None
        self.style = ttk.Style()
        self.style.theme_use('classic')
        # Initialize Git Repo
        self.repo = None
        self.window = tk.Tk()
        # Main layout
        self.create_menu()
        self.create_widgets()
        self.create_project_explorer()
        
        try:
        	self.add_tab(filename=None, content="")        
        except:
        	pass        	        
        #self.create_console()
        self.bind_shortcuts()
        fonts = ['AndroidClock','Roboto Medium','Noto Sans Telugu UI','Roboto Thin','RobotoNum3L_ver2.2_191105 Light','Roboto Condensed Medium']
        self.line_number_bars = tk.Text(self.notebook, width=4, padx=4, fg="cyan", bg="#1b1b1b", font=("Courier", 10, "bold italic"))
        self.line_number_bars.pack(side=tk.LEFT, fill=tk.X)
        self.update_line_numbers(self.text_widget)
    def goto_clicked_line(self, event):
        """Go to a line when clicked in line numbers."""
        line = self.line_numbers.index("@%d,%d" % (event.x, event.y)).split(".")[0]
        self.text_editor.mark_set("insert", f"{line}.0")
        self.text_editor.see(f"{line}.0")
    def update_line_numbers(self, event=None):
        """Update line numbers to match text editor."""
        self.line_numbers.config(state="normal")
        self.line_numbers.delete("1.0", tk.END)

        line_count = self.text_widget.index("end-1c").split(".")[0]
        line_numbers_str = "\n".join(str(i) for i in range(1, int(line_count) + 1))
        self.line_numbers.insert("1.0", line_numbers_str)

        self.line_numbers.config(state="disabled")

        # Ensure line numbers scroll with text
        self.line_numbers.yview_moveto(self.text_widget.yview()[0])
    def create_menu(self):
        menu_bar = tk.Menu(self.root)

        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New", command=self.new_file, accelerator="Ctrl+N")
        file_menu.add_command(label="Open", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As", command=self.save_as_file)
        file_menu.add_separator()
        file_menu.add_command(label="Close File", command=self.closefile)
        file_menu.add_separator()
        file_menu.add_command(label="Visit Site", command=lambda: messagebox.showinfo('SITE', 'http://www.kentsoft.com'))
        file_menu.add_separator()
        file_menu.add_command(label="⚠ Exit", command=self.exit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Edit menu
        edit_menu = tk.Menu(menu_bar)#, tearoff=0)
        edit_menu.add_command(label="Undo", command=self.undo)
        edit_menu.add_command(label="Redo", command=self.redo)
        #edit_menu.add_separator()
        edit_menu.add_command(label="Cut", command=self.cut)
        edit_menu.add_command(label="Copy", command=self.copy)
        edit_menu.add_command(label="Paste", command=self.paste)
        edit_menu.add_command(label="Find", command=self.find2, accelerator="Ctrl+F")
        edit_menu.add_command(label="Go to Line ", command=self.goto_line, accelerator="Ctrl+G")
        menu_bar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Find and Replace", command=self.find_and_replace)
        # Run menu
        run_menu = tk.Menu(menu_bar, tearoff=0)
        run_menu.add_command(label="Run ▶", command=self.run_code, accelerator="F5")
        run_menu.add_command(label="Debug", command=self.start_debugger)
        run_menu.add_command(label="Lint", command=self.lint_file)
        menu_bar.add_cascade(label="Execute", menu=run_menu)
        # Git menu
        git_menu = tk.Menu(menu_bar, tearoff=0)
        git_menu.add_command(label="Git Init", command=self.git_init)
        git_menu.add_command(label="Git Clone", command=self.git_clone)
        git_menu.add_command(label="Git Commit", command=self.git_commit)
        git_menu.add_command(label="Git Push", command=self.git_push)
        git_menu.add_command(label="Git Pull", command=self.git_pull)
        git_menu.add_command(label="Commit Changes", command=self.git_commit)
        menu_bar.add_cascade(label="Git", menu=git_menu)

        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Prog langs.", command=self.preferences)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        # Settings Menu for theme switching
        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Configure")
        settings_menu.add_command(label="Extensions")
        settings_menu.add_command(label="Update")
        settings_menu.add_command(label="Donate")
        
        menu_bar.add_cascade(label="⚙️ Settings", menu=settings_menu)
        
        themes_menu = tk.Menu(menu_bar, tearoff=0)     
        settings_menu.add_cascade(label="Themes", menu=themes_menu)
        themes_menu.add_command(label="Toggle Dark/Light Theme", command=self.toggle_theme)
        themes_menu.add_command(label="Theme Settings", command=self.open_settings)
    
        self.root.config(menu=menu_bar)
        
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        

    def create_widgets(self):
        # Main Paned Window
        self.main_pane = tk.PanedWindow(self.root, orient=tk.VERTICAL, sashwidth=10, bg="#252526",height=1)
        self.main_pane.pack(fill=tk.BOTH, expand=True)
        # Top Pane (Project Explorer + Editor)
        self.top_pane = tk.PanedWindow(self.main_pane, orient=tk.HORIZONTAL, sashwidth=10, bg="#252526",height=100)
        self.main_pane.add(self.top_pane)
        # Left Panel - Project Explorer
        self.project_frame = tk.Frame(self.top_pane, bg="#333",height=100)
        self.project_frame.pack(side="left", fill="y", padx=5, pady=5)
        # Bottom Console
        self.console_frame = tk.Frame(self.main_pane, height=1, bg="#1e1e1e")
        #self.console_text = scrolledtext.ScrolledText(self.console_frame, height=1, bg="black", fg="white", insertbackground="white")
        #self.console_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.console_input = tk.Entry(self.console_frame, bg="#2e2e2e", fg="white", insertbackground="white")
        self.console_input.pack(side=tk.BOTTOM,fill=tk.X, padx=5, pady=2)
        # Integrated Terminal
        try:
            #try:
                self.terminal = Terminal(self.console_frame)
                self.terminal.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
 # Correct packing
      #  except Exception as e:
       #         )
        except:
        	messagebox.showerror('Terminal Error', f'Failed to load terminal: {e}')
        	self.console_frame.add(self.terminal, weight=1)
        	self.console_frame.add(self.console_input, weight=1)
        
       # self.console_input.bind("<Return>", self.execute_console_command)
#        self.console_input.bind("<Up>", self.console_history_up)  # Command history
#        self.console_input.bind("<Down>", self.console_history_down)  # Command history
        self.console_history = []
        self.console_history_index = -1

        # ... (Rest of the widgets code)
        logo = """
        .--.  
       |o o |  
       |\_/ |  
      //   \ \  
     (|     | )  
    /'\_   _/`\\  
    \___) (___/
    PYTHON_PROGRAMMING_IDE By mskalvin
    pyLord@cyb3rh4ck3r04
        """
        self.terminal.insert("end", f"{logo}")
        self.style = ttk.Style ()
        self.style. theme_use('clam')
        self.style. configure ('self.status_bar.TLabel',font=('Jokerman',8),foreground='lime',background='black',fill='both',relief=tk.RAISED)
        self.status_bar = ttk.Label(self.root, text="                  ⚠ 0       | UTF-8 |       ☯ Python   |       Layout: US       | Terminal >_", 
                                    anchor=tk.W, relief=tk.RAISED,style="self.status_bar.TLabel")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.main_pane.add(self.console_frame)
        # Middle Panel - Editor
        self.editor_frame = tk.Frame(self.top_pane, bg="#282C34",height=30)
        self.editor_frame.pack(side="top", fill="both", expand=True)

        self.style = ttk.Style ()
        self.style. theme_use('clam')
        self.style. configure ('new.TNotebook',font=('Jokerman',8),foreground='lime',background='black',fill='both',relief=tk.RAISED)
        self.notebook = ttk.Notebook(self.editor_frame,style='new.TNotebook')
        self.notebook.pack(fill="both", expand=True)
    def create_project_explorer(self):
            self.style = ttk.Style ()
            self.style. theme_use('classic')
            self.style. configure ('self.tree.Treeview',foreground='cyan',background='#282c34',font=('Jokerman',8),height=0, expand=True)
            
            self.tree = ttk.Treeview(self.project_frame,style='self.tree.Treeview', selectmode="browse", height=0)
            self.tree.insert("", "end", "root", text="Project Files", open=True)
            dir = '/sdcard/kentsoft/','root'
            self.populate_tree(os.getcwd(), "root")
            #self.tree.bind("<Double-1>", self.on_tree_item_select)
            self.tree.pack(fill='both', expand=True)
            
    def populate_tree(self, path, parent):
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                folder_id = self.tree.insert(parent, 'end', full_path, text=item, open=False)
                self.populate_tree(full_path, folder_id)  # Recursively add subfolders
            else:
                self.tree.insert(parent, 'end', full_path, text=item)
    def on_tree_item_select(self, event):
        selected_item = self.tree.selection()[0]
        if os.path.isfile(selected_item):
            self.open_file_from_tree(selected_item)

    def open_file_from_tree(self, file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            self.add_tab(file_path, content)
        self.file_path = file_path
        self.text_widget.delete('1.0', tk.END)
        self.text_widget.insert('1.0', content)
        self.highlight_syntax(self.text_widget)
    def open_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Python Files", "*.py"), ("HTML Files", "*.html"), ("CSS Files", "*.css"),("All Files", ".*")])
        self.filepath = filepath
        if filepath:
            with open(filepath, "r") as file:
                content = file.read()
            self.add_tab(filepath, content)       
    def add_tab(self, filename=None, content=""):#self, filename, content):      
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style. configure ('self.close_button.TButton',font=('RobotoNum3L_ver2.2_191105 Light',10),foreground='red',background='#282c34',fill='both',relief=tk.SUNKEN,border=1,width=2,height=1)
        frame = tk.Frame(self.notebook,height=2)
        self.frame = frame
        #style='self.line_number_bar.TText', 
        self.line_number_bar = tk.Text(frame, width=4, padx=4, font=("Courier", 10, "bold italic"),bg="black", fg="cyan")
        self.line_number_bar.pack(side=tk.LEFT, fill=tk.Y)
        self.text_widget = scrolledtext.ScrolledText(frame, wrap="word", bg="#1E1E1E", fg="white", insertbackground="white")
        self.text_widget.insert("1.0", content)
        self.text_widget.pack(fill="both", expand=True)
        #self.text_widget.bind("<KeyRelease>", lambda event: self.update_line_numbers(self.text_widget))
#        # ... (Existing tab creation code)
#        self.text_widget.bind("<KeyRelease>", self.on_text_change)
#        self.text_widget.bind("<Control-space>", self.autocomplete)
        self.tab_name = os.path.basename(filename) if filename else "Untitled"
        self.tab_id = self.notebook.add(frame, text=self.tab_name)
        self.highlight_syntax(self.text_widget)
        if content:
            self.text_widget.insert("1.0", content)
            self.update_line_numbers(self.text_widget)
        
       
        close_button = ttk.Button(frame,style='self.close_button.TButton', text="×", command=lambda: self.close_tab(filename, frame))
        close_button.pack(side="right",pady=5,padx=4)

        self.notebook.add(frame, text=os.path.basename(filename))
        self.open_files[filename] = self.text_widget
        self.current_file = filename
        self.filename = filename
        
        self.notebook.select(frame)
        self.file_tabs[self.tab_id] = self.text_widget
    def on_text_change(self, event=None):
        self.update_line_numbers(self.text_widget)
        self.highlight_syntax(self.text_widget) 
    def update_line_numbers(self, text_widget):
        self.line_number_bar.config(state=tk.NORMAL)
        self.line_number_bar.delete("1.0", tk.END)
        lines = self.text_widget.index("end-1c").split(".")[0]
        line_numbers = "\n".join(str(i) for i in range(1, int(lines) + 1))
        self.line_numbers = line_numbers
        self.line_number_bar.insert("1.0", line_numbers)
        
        self.line_number_bar.config(state=tk.DISABLED)
        self.linenum = lines
  
   
    def on_tab_changed(self, event):
        current_tab = self.notebook.select()
        if current_tab:
            frame = self.notebook.nametowidget(current_tab)
            self.text_widget = frame.winfo_children()[1]
            self.current_file = list(self.open_files.keys())[list(self.open_files.values()).index(self.text_widget)] if self.text_widget in self.open_files.values() else None
            if self.current_file:
                self.filename = self.current_file

    
    def close_tab(self, filename, frame):
        if filename in self.open_files:
            if self.text_widget.edit_modified():
                if not messagebox.askyesno("Close File", "Unsaved changes. Do you want to close?"):
                	return 
                del self.open_files[filename]
            self.notebook.forget(frame)    
   
    def closefile(self,filename):
        if messagebox.askyesno("Close File", "⚠ Do you really want to close this file?"):
            self.close_tab(self.filename, self.frame)

    def exit(self):
        if messagebox.askyesno("Exit", "⚠ Do you really want to exit?"):
            self.root.destroy()
    
    def save_file(self, event=None):
        if self.current_file:
            with open(self.current_file, 'w') as file:
                file.write(self.text_widget.get('1.0', tk.END))
        else:
            self.save_as_file()
    def save_file_as(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".py", filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        if file_path:
            self.current_file = file_path
            self.save_file()
   
    def save_as_file(self):
        global file_path
        file_path = filedialog.asksaveasfilename(defaultextension=".py", filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        if file_path:
            self.current_file = file_path
            with open(file_path, 'w') as file:
                self.tab_name = os.path.basename(file_path) if file_path else "Untitled"
                self.tab_id = self.notebook.add(self.frame, text=self.tab_name)

                file.write(self.text_widget.get('1.0', tk.END))
    def new_file(self):
        try:
        	self.add_tab()#self.file_path.get())
        except Exception as e:
        	pass
    def goto_line_from_number(self, event):
        try:
            line_number = int(self.line_number_bar.get("current line start", "current line end").strip())
            self.text_widget.see(f"{line_number}.0")  # Scroll to the line
            self.text_widget.mark_set("insert", f"{line_number}.0") # Place cursor at the beginning of the line
        except ValueError:
            pass  # Handle cases where the clicked area isn't a valid number

    def jump_to_line(self,line_numbers):
        if line_numbers is not None:
            try:
                self.text_widget.see(f"{line_numbers}.0")
                self.text_widget.mark_set("insert", f"{line_numbers}.0")
            except tk.TclError:
                messagebox.showerror("Error", "Invalid line number.")
    def goto_clicked_line(self, event):
        """Go to a line when clicked in line numbers."""
        try:
        	line = self.line_numbers.index("@%d,%d" % (event.x, event.y)).split(".")[0]
        	self.text_widget.mark_set("insert", f"{line}.0")
        	self.text_widget.see(f"{line}.0")
        except:
        	pass
    def indent_automatically(self, event):
        current_line = self.text_widget.get("insert linestart", "insert lineend")
        if current_line.strip():  # Only indent if the line is not empty
            indentation = len(current_line) - len(current_line.lstrip())  # Get current indentation
            self.text_widget.insert("insert", "  ")  # Insert 4 spaces
            return "break" # Prevent default tab behavior
    def auto_indent_on_return(self, event):
        current_line = self.text_widget.get("insert linestart", "insert lineend")
        indentation = len(current_line) - len(current_line.lstrip())
        self.text_widget.insert("insert", "\n" + "   " * indentation)
        return "break"
    def execute_console_command(self, event=None):
        command = self.console_input.get().strip()
        if not command:
            return

        if hasattr(self, 'terminal') and self.terminal:
            self.terminal.run_command(command)
        else:
            messagebox.showerror('Error', 'Integrated terminal is not available.')
        self.console_input.delete(0, tk.END)
        # ... (Existing code for executing commands)
        command = self.console_text.get("end-2l", "end-1l").strip()
        if command:
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                self.console_text.insert("end", "\n" + output)
            except subprocess.CalledProcessError as e:
                self.console_text.insert("end", "\nError: " + e.output)       
        self.console_history.append(command)  # Add command to history
        self.console_history_index = len(self.console_history) - 1

    def console_history_up(self, event):
        if self.console_history:
            self.console_history_index = max(0, self.console_history_index - 1)
            self.console_input.delete(0, tk.END)
            self.console_input.insert(0, self.console_history[self.console_history_index])

    def console_history_down(self, event):
        if self.console_history:
            self.console_history_index = min(len(self.console_history) - 1, self.console_history_index + 1)
            self.console_input.delete(0, tk.END)
            self.console_input.insert(0, self.console_history[self.console_history_index])

    def auto_indent(self, event):
        """Auto-indent new lines based on the previous line's indentation."""
        index = self.text_widget.index("insert")
        prev_line_index = f"{int(index.split('.')[0]) - 1}.0"
        prev_line = self.text_widget.get(prev_line_index, prev_line_index + " lineend")

        indent = len(prev_line) - len(prev_line.lstrip())  # Count leading spaces
        self.text_widget.insert("insert", " " * indent)
        return "break"
    def autocomplete(self, event=None):
        line, col = self.text_widget.index("insert").split(".")
        line, col = int(line), int(col)
        if self.text_widget.edit_modified():
            try:
                completions = jedi.Script(code=self.text_widget.get("1.0", "insert"), path=self.current_file).complete(line=line, column=col)
                if completions:
                    completion_text = completions[0].name
                    self.text_widget.insert("insert", completion_text[len(self.text_widget.get("insert-1 chars", "insert")):])
            except Exception as e:
                print(f"Autocomplete Error: {e}")
    
    def start_debugger(self):
        current_tab = self.notebook.select()
        if not current_tab:
            messagebox.showerror("Error", "No file open to debug.")
            return

        filename = self.notebook.tab(current_tab, "text")
        # Placeholder for debugger integration (actual Python debugger)
        self.console_text.insert("end", "\nStarting Debugger for " + filename)
        """Starts the Python debugger using debugpy."""
        debugpy.listen(("localhost", 8080))
        time.sleep(0.1)
        self.console_text.insert("end", "\nDebugger started. Waiting for connection...")
        self.console_text.config(state=tk.NORMAL)
        #self.console_text.delete("1.0", tk.END)
        process = subprocess.Popen(["python", "-m", "pdb", self.current_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        self.console_text.insert(tk.END, stdout.decode())
        self.console_text.insert(tk.END, stderr.decode(), "error")
        self.console_text.config(state=tk.DISABLED)


    def start_live_preview(self):
        """Starts a Flask web server for live preview."""
        def run_flask():
            app.run(debug=True, port=8080)

        threading.Thread(target=run_flask, daemon=True).start()
    def lint_file(self):
        current_tab = self.notebook.select()
        if not current_tab:
            return

        filename = self.notebook.tab(current_tab, "text")
        if filename:
            lint = pylint.lint.Run([filename], do_exit=False)
            self.console_text.insert("end", "\nLinting Completed")

    def highlight_syntax(self, text_widget):
        text_widget.tag_configure("keyword", foreground="lime")
        text_widget.tag_configure("string", foreground="orange")
        text_widget.tag_configure("number", foreground="purple")
        text_widget.tag_configure("comment", foreground="gray")
        text_widget.tag_configure("function", foreground="cyan")
        text_widget.tag_configure("builtin", foreground="red")

        content = text_widget.get("1.0", tk.END)
        text_widget.mark_set("range_start", "1.0")
        #for token, content in lexer.lex(content, PythonLexer()):
        for token, content in lex(content, PythonLexer()):
            text_widget.mark_set("range_end", "range_start + %dc" % len(content))
            tag_name = ""
            if str(token) in ["Token.Keyword"]:
                tag_name = "keyword"
            elif str(token) in ["Token.Literal.String"]:
                tag_name = "string"
            elif str(token) in ["Token.Literal.Number"]:
                tag_name = "number"
            elif str(token) in ["Token.Comment"]:
                tag_name = "comment"
            elif str(token) in ["Token.Name.Function"]:
                tag_name = "function"
            elif str(token) in ["Token.Name.Builtin"]:
                tag_name = "builtin"
            if tag_name:
                text_widget.tag_add(tag_name, "range_start", "range_end")
            text_widget.mark_set("range_start", "range_end")
    def git_init(self):
        if not self.file_path:
            messagebox.showwarning("No File", "Please open a project folder first.")
            return
        try:
            repo = git.Repo.init(os.path.dirname(self.file_path))
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

    def execute_console_command(self, event=None):
        command = self.console_input.get().strip()
        if not command:
            return

        if hasattr(self, 'terminal') and self.terminal:
            self.terminal.run_command(command)
        else:
            messagebox.showerror('Error', 'Integrated terminal is not available.')
        self.console_input.delete(0, tk.END)
        """ Execute shell commands and Python scripts in the console. """
        command = self.console_input.get().strip()
        if not command:
            return

        self.console_text.insert(tk.END, f"> {command}\n")
        self.console_text.see(tk.END)

        if command.endswith(".py") and os.path.exists(command):
            process = subprocess.Popen(["python", command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        else:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        stdout, stderr = process.communicate()

        if stdout:
            self.console_text.insert(tk.END, stdout + "\n")
        if stderr:
            self.console_text.insert(tk.END, stderr + "\n", "error")

        self.console_text.see(tk.END)
        self.console_input.delete(0, tk.END)
    def execute_command(self, event):
        command = self.console_text.get("end-2l", "end-1l").strip()
        if command:
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                self.console_text.insert("end", "\n" + output)
            except subprocess.CalledProcessError as e:
                self.console_text.insert("end", "\nError: " + e.output)
    def git_commit(self):
        try:
            command = "git commit -m 'Committing changes'"
            
            repo = git.Repo(os.path.dirname(self.file_path))
            message = simpledialog.askstring("Git Commit", "Enter commit message:")
            if message:
                repo.git.add(A=True)
                repo.index.commit(message)
                self.execute_command(command)
                messagebox.showinfo("Git Commit", "Changes committed.")
        except Exception as e:
            messagebox.showerror("Git Commit Error", str(e))

    def git_push(self):
        try:
            self.repo = git.Repo(search_parent_directories=True)
        except git.exc.InvalidGitRepositoryError:
            self.repo = None
        try:
            repo = git.Repo(os.path.dirname(self.file_path))
            repo.remotes.origin.push()
            messagebox.showinfo("Git Push", "Changes pushed to the remote repository.")
        except Exception as e:
            messagebox.showerror("Git Push Error", str(e))

    def git_pull(self):
        try:
            repo = git.Repo(os.path.dirname(self.file_path))
            repo.remotes.origin.pull()
            messagebox.showinfo("Git Pull", "Changes pulled from the remote repository.")
        except Exception as e:
            messagebox.showerror("Git Pull Error", str(e))

    def undo(self):
        self.text_widget.event_generate("<<Undo>>")

    def redo(self):
        self.text_widget.event_generate("<<Redo>>")

    def cut(self):
        self.text_widget.event_generate("<<Cut>>")

    def copy(self):
        self.text_widget.event_generate("<<Copy>>")

    def paste(self):
        self.text_widget.event_generate("<<Paste>>")

    def find_and_replace(self):
        find_window = tk.Toplevel(self.root)
        find_window.title("Find and Replace")

        find_label = tk.Label(find_window, text="Find:")
        find_label.grid(row=0, column=0)
        find_entry = tk.Entry(find_window)
        find_entry.grid(row=0, column=1)

        replace_label = tk.Label(find_window, text="Replace:")
        replace_label.grid(row=1, column=0)
        replace_entry = tk.Entry(find_window)
        replace_entry.grid(row=1, column=1)

        def replace_all():
            find_text = find_entry.get()
            replace_text = replace_entry.get()
            self.text_widget.tag_remove("found", "1.0", tk.END)
            start_index = "1.0"
            while True:
                start_index = self.text_widget.search(find_text, start_index, stopindex=tk.END)
                if not start_index:
                    break
                end_index = f"{start_index}+{len(find_text)}c"
                self.text_widget.delete(start_index, end_index)
                self.text_widget.insert(start_index, replace_text)
                start_index = f"{start_index}+{len(replace_text)}c"  # Move index after replacement

        replace_button = tk.Button(find_window, text="Replace All", command=replace_all)
        replace_button.grid(row=2, column=1)
    def find2(self):  # Improved find function
        search_term = simpledialog.askstring("Find", "Enter text to find:")
        if search_term:
            self.text_widget.tag_remove("found", "1.0", tk.END)  # Clear previous highlights
            start_index = "1.0"
            while True:
                start_index = self.text_widget.search(search_term, start_index, stopindex=tk.END)
                if not start_index:
                    break
                end_index = f"{start_index}+{len(search_term)}c"
                self.text_widget.tag_add("found", start_index, end_index)
                start_index = end_index
            self.text_widget.tag_config("found", background="grey")  # Highlight found terms

    # ... (Rest of the existing functions)
    def preferences(self):
        messagebox.showinfo("Preferences", "Preferences feature coming soon!")

    def about(self):
        messagebox.showinfo("About", "Python IDE v2.0 - A Python IDE with Git integration by KentLabs\nEmail: mskalvin@cyberh4ck3r04.com")
    def get_current_editor(self):
        current_tab = self.notebook.select()
        return self.notebook.nametowidget(current_tab).winfo_children()[0]
    def git_commit(self):
        command = "git commit -m 'Committing changes'"
        self.execute_command(command)
    #def git_commit(self):
        if self.repo:
            try:
                self.repo.git.add(all=True)
                self.repo.index.commit("Committing changes")
                self.console_text.insert("end", "\nChanges committed successfully.")
            except Exception as e:
                self.console_text.insert("end", f"\nError committing changes: {e}")
        else:
            self.console_text.insert("end", "\nNo Git repository found.")

    def toggle_theme(self):
        current_bg = self.editor_frame.cget("bg")
        if current_bg == "#282C34":
        #if self.theme == "dark":
            self.theme = "light"
            self.apply_light_theme()
        else:
            self.theme = "dark"
            self.apply_dark_theme()

    def apply_dark_theme(self):
            self.root.configure(bg="#282C34")
            self.main_pane.configure(bg="#282C34")
            self.editor_frame.configure(bg="#282C34")
            self.console_text.configure(bg="black", fg="lime")
            self.editor_frame.configure(bg="#282C34")
            self.project_frame.configure(bg="#282C34")
            self.top_pane.configure(bg="#282C34")
            self.style. configure ('self.status_bar.TLabel',font=('Jokerman',8),foreground='lime',background='black',fill='both',relief=tk.RAISED)
            self.text_widget.configure(bg="black", fg="lime")##3aae91
          
            self.style. configure ('self.line_number_bar.TText',font=('Jokerman',8),foreground='cyan',background='#1b1b1b',fill='both',relief=tk.RAISED)
            self.style. theme_use('clam')
            self.style. configure ('self.tree.Treeview',font=('Jokerman',8),foreground='lime',background='black',fill='both',relief=tk.RAISED)
            #self.style. theme_use('clam')
            self.style. configure ('self.close_button.TButton',font=('Jokerman',8),foreground='red',background='black',fill='both',relief=tk.RAISED,border=4,width=2)
    def apply_light_theme(self):
        self.root.configure(bg="white")
        self.main_pane.configure(bg="white")
        self.editor_frame.configure(bg="white")
        self.console_text.configure(bg="white", fg="black")
        self.project_frame.configure(bg="white")
        self.top_pane.configure(bg="white")
        self.text_widget.configure(bg="white", fg="black")
    def goto_line(self):
        line_number = simpledialog.askinteger("Go to Line", "Enter line number:")
        if line_number:
            text_widget = self.get_current_editor()
            text_widget.mark_set("insert", f"{line_number}.0")
            text_widget.see(f"{line_number}.0")
            self.jump_to_line(line_number)
    def run_code(self, event=None):
        #global file_path
        if not self.current_file:
            messagebox.showwarning("Save File", "Please save your code before running.")
            return

        self.save_file()  # Ensure the latest code is saved

        command = f'python3 "{self.current_file}"'
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

        stdout, stderr = process.communicate()

        self.console_text.delete('1.0', tk.END)
        if stdout:
            self.console_text.insert(tk.END, stdout)
        if stderr:
            self.console_text.insert(tk.END, stderr)
    def get_current_editor(self):
        current_tab = self.notebook.select()
        return self.notebook.nametowidget(current_tab).winfo_children()[0]
    def open_settings(self):
        """ Open settings window """
        import tkinter #as tk
        from tkinter import ttk
        try:
        	settings_window = tkinter.Toplevel(self.window)
        	settings_window.title("Preferences")
        	settings_window.geometry("400x300")
        	ttk.Label(settings_window, text="Editor Font:").pack(pady=5)
        	font_selector = ttk.Combobox(settings_window, values=["Courier", "Arial", "Times New Roman"])
        	font_selector.pack(pady=5)
        	self.theme = "dark"
        	dark_mode_toggle = ttk.Checkbutton(settings_window, text="Enable Dark Mode",command=self.apply_dark_theme)
        	dark_mode_toggle.pack(pady=5)
        	ttk.Button(settings_window, text="Save", command=settings_window.destroy).pack(pady=10)
        except Exception as e:
        	messagebox.showwarning('! Exception :',f'{e}')

        
    def bind_shortcuts(self):
        self.root.bind("<Control-s>", lambda _: self.save_as_file())#self.save_file())
        self.root.bind("<Control-o>", lambda _: self.open_file())
        self.root.bind("<Control-n>", lambda _: self.new_file())
        #self.root.bind("<Control-x>", lambda _: self.close_tab(self.filename, self.frame))
        self.root.bind("<Control-x>", lambda _: self.closefile(self.filename))
        self.root.bind("<Control-r>", lambda _: self.run_code())
        self.root.bind("<Control-f>", lambda _: self.find_text())
        self.root.bind("<Control-g>", lambda _: self.goto_line())
        self.root.bind("<Control-j>", lambda _: self.jump_to_line())
        #self.root.bind("<KeyRelease>", self.on_text_change)
        self.root.bind("<Return>", self.auto_indent)
        self.root.bind("<Button-1>", self.goto_clicked_line)
        self.console_input.bind("<Return>", lambda event: self.terminal.run_command(self.console_input.get()))
        self.root.bind("<Up>", self.console_history_up)  # Command history
        self.root.bind("<Down>", self.console_history_down)
        self.root.bind("<F5>", lambda event: self.run_code())
        
        #self.text_widget.bind("<KeyRelease>", lambda event: self.update_line_numbers(self.text_widget))
        # ... (Existing tab creation code)
        self.root.bind("<KeyRelease>", self.on_text_change)
        self.root.bind("<Control-space>", self.autocomplete)
        self.root.bind("<Double-1>", self.on_tree_item_select)

@app.route("/")
def live_preview():
    """Flask route for live preview."""
    return render_template_string("<h1>Live Preview</h1><p>Auto-refresh coming soon...</p>")
if __name__ == "__main__":
    root = tk.Tk()
    app = PythonIDE(root)
    root.mainloop()