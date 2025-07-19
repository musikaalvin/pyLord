import os, subprocess
import tkinter as tk
from pygments import lex
#from colors import *
from pygments.lexers import PythonLexer
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
#import git
global file_path

class PythonIDE:
    def __init__(self, root):
        self.root = root
        self.root.title("Python IDE Code")
        self.root.geometry("700x1100")
        self.root.minsize(700,1000)
        self.root.configure(bg="#1e1e1e")
        self.style = ttk.Style()
        self.style.theme_use('classic')
        fonts = ['AndroidClock','Roboto Medium','Noto Sans Telugu UI','Roboto Thin','RobotoNum3L_ver2.2_191105 Light','Roboto Condensed Medium']
        self.style. configure (root,font=('RobotoNum3L_ver2.2_191105 Light',8),foreground='cyan',background='#282c34')
        self.style. configure ('event_label.TLabel',font=('RobotoNum3L_ver2.2_191105 Light',10),foreground='cyan',background='#282c34',fill='both',relief=tk.RAISED)
        #self.style = ttk.Style()
#        self.style.theme_use('classic')
#        self.style. configure ('self.close_btn.TButton',font=('RobotoNum3L_ver2.2_191105 Light',10),foreground='red',background='#282c34',fill='both',relief=tk.SUNKEN,border=3)
        

        self.file_tabs = {}
        self.current_file = None
        self.file_path = None

        # Sidebar
        self.sidebar = tk.Frame(self.root, bg="#252526", width=50)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        
        # Create Menu
        self.create_menu()
        
        self.create_sidebar()

        #self.add_sidebar_buttons()
        self.style. configure ('self.notebook.TNotebook',font=('RobotoNum3L_ver2.2_191105 Light',8),foreground='lime',background='#282c34',fill='both',relief=tk.RAISED)

        # Main Editor
        self.notebook = ttk.Notebook(self.root,style='new.TNotebook')
        self.notebook.pack(expand=True, fill=tk.BOTH)

        # Console Output
        self.console = scrolledtext.ScrolledText(self.root,font=('RobotoNum3L_ver2.2_191105 Light',7), height=15, bg="black", fg="red")
        self.console.pack(fill=tk.X)
        status_bar = ttk.Label(self.root,style='log_frame.TLabel' ,text="⚠ 0   UTF-8    ☯ Python    Layout: US   Terminal ○",font=('bold',8), border=5, relief=tk.RAISED, anchor=tk.W).pack(side=tk.TOP, fill=tk.X)

        # Bottom Status Bar
        self.status_bar = tk.Label(self.root, text="RUNNING", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#252526", fg="red")
        self.status_bar.pack(fill=tk.X,side=tk.BOTTOM)

        self.create_new_tab()

    def create_sidebar(self):
        self.sidebar = tk.Frame(self.sidebar, width=0, relief="raised")
        self.sidebar.pack(side=tk.LEFT, fill='y')
        style = ttk.Style ()
        style. theme_use('classic')
        style. configure ('new.Treeview',foreground='cyan',background='#282c34',font=('Jokerman',8),height=0)
        self.tree = ttk.Treeview(self.sidebar, selectmode="browse", height=0,style='new.Treeview')
        self.tree.pack(fill='both', expand=True)

        self.tree.insert("", "end", "root", text="Project Files", open=True)
        self.populate_tree(os.getcwd(), "root")

        self.tree.bind("<Double-1>", self.on_tree_item_select)
        #self.tree.bind("<Button-1>", self.toggle_folder)  # Click to toggle folders


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
            self.create_new_tab(file_path, content)
        self.file_path = file_path
        self.text_editor.delete('1.0', tk.END)
        self.text_editor.insert('1.0', content)
    #def add_sidebar_buttons(self):
#        buttons = [("Explorer", "📂"), ("Search", "🔍"), ("Source Control", "🔀"), ("Run", "▶"), ("Extensions", "🛠️")]
#        for text, icon in buttons:
#            btn = tk.Button(self.sidebar, text=f"{icon}\n{text}", fg="white", bg="#252526", borderwidth=0, command=lambda t=text: self.sidebar_action(t))
#            btn.pack(fill=tk.X, pady=5)

    def sidebar_action(self, action):
        self.status_bar.config(text=f"{action} clicked!")

    def create_new_tab(self, filename=None, content=""):
        self.tab_frame = ttk.Frame(self.notebook)

        # Line Number Frame
        self.line_number_bar = tk.Text(self.tab_frame, width=4, padx=4, fg="cyan", bg="#1b1b1b", font=("Courier", 10, "bold italic"))
        self.line_number_bar.pack(side=tk.LEFT, fill=tk.Y)
        
        # Text Editor
        self.text_editor = tk.Text(self.tab_frame, wrap=tk.WORD, font=("Courier", 10), bg="#282c34", fg="white", insertbackground="white")
        self.text_editor.pack(expand=True, fill=tk.BOTH, side=tk.LEFT)
        self.text_editor.bind("<KeyRelease>", lambda event: self.update_line_numbers(self.text_editor))
        #status_bar = ttk.Label(self.text_editor,style='log_frame.TLabel' ,text="⚠ 0   UTF-8    ☯ Python    Layout: US   Terminal ○",font=('bold',8), border=5, relief=tk.RAISED, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)

        # Close Button for Tab
        self.tab_name = os.path.basename(filename) if filename else "Untitled"
        self.tab_id = self.notebook.add(self.tab_frame, text=self.tab_name)

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style. configure ('self.close_btn.TButton',font=('RobotoNum3L_ver2.2_191105 Light',10),foreground='red',background='#282c34',fill='both',relief=tk.SUNKEN,border=1,width=2,height=1)
        # Close Tab Button
        self.close_btn = ttk.Button(self.root,text="X", command=lambda: self.close_tab(self.tab_id, self.text_editor),style='self.close_btn.TButton')
        self.close_btn.pack(side=tk.RIGHT,pady=5,padx=4)

        self.notebook.select(self.tab_frame)
        self.file_tabs[self.tab_id] = self.text_editor

        # Load content if opening a file
        if content:
            self.text_editor.insert("1.0", content)
            self.update_line_numbers(self.text_editor)

    def update_line_numbers(self, text_editor):
        self.line_number_bar.config(state=tk.NORMAL)
        self.line_number_bar.delete("1.0", tk.END)
        lines = self.text_editor.index("end-1c").split(".")[0]
        line_numbers = "\n".join(str(i) for i in range(1, int(lines) + 1))
        self.line_number_bar.insert("1.0", line_numbers)
        self.line_number_bar.config(state=tk.DISABLED)

    def close_tab(self, tab_frame, text_editor):
        if self.text_editor.edit_modified():
            if not messagebox.askyesno("Close File", "Unsaved changes. Do you want to close?"):
                return
        self.notebook.forget(self.tab_frame)
        
        del self.file_tabs[self.tab_id]
        #self.create_new_tab()

        
    def get_current_editor(self):
        current_tab = self.notebook.select()
        return self.file_tabs[current_tab]
        #self.create_new_tab()

    def highlight_syntax(self, text_editor):
        content = self.text_editor.get("1.0", tk.END)
        self.text_editor.mark_set("range_start", "1.0")
        for token, content in lex(content, PythonLexer()):
            self.text_editor.mark_set("range_end", "range_start + %dc" % len(content))
            self.text_editor.tag_add(str(token), "range_start", "range_end")
            self.text_editor.mark_set("range_start", "range_end")

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r") as file:
                content = file.read()
            self.create_new_tab(file_path, content)

    def save_file(self):
        if not self.current_file:
            self.save_file_as()
        else:
            with open(self.current_file, "w") as file:
                file.write(self.get_current_editor().get("1.0", tk.END))

    def save_file_as(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".py", filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        if file_path:
            self.current_file = file_path
            self.save_file()

    def run_code(self):
        code = self.get_current_editor().get("1.0", tk.END)
        with open("temp_script.py", "w") as f:
            f.write(code)

        #output = os.popen("python temp_script.py").read()
        output = os.system(f'python3 temp_script.py')
        self.console.delete("1.0", tk.END)
        self.console.insert(tk.END, output)

   

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
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="Undo", command=self.undo)
        edit_menu.add_command(label="Redo", command=self.redo)
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut", command=self.cut)
        edit_menu.add_command(label="Copy", command=self.copy)
        edit_menu.add_command(label="Paste", command=self.paste)
        edit_menu.add_command(label="Find", command=self.find)
        menu_bar.add_cascade(label="Edit", menu=edit_menu)

        # Run menu
        run_menu = tk.Menu(menu_bar, tearoff=0)
        run_menu.add_command(label="Run ▶", command=self.run_code, accelerator="F5")
        run_menu.add_command(label="Debug", command=self.debug_code)
        menu_bar.add_cascade(label="Execute", menu=run_menu)

        # Git menu
        git_menu = tk.Menu(menu_bar, tearoff=0)
        git_menu.add_command(label="Git Init", command=self.git_init)
        git_menu.add_command(label="Git Clone", command=self.git_clone)
        git_menu.add_command(label="Git Commit", command=self.git_commit)
        git_menu.add_command(label="Git Push", command=self.git_push)
        git_menu.add_command(label="Git Pull", command=self.git_pull)
        menu_bar.add_cascade(label="Git", menu=git_menu)

        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        tools_menu.add_command(label="Prog langs.", command=self.preferences)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        settings_menu = tk.Menu(menu_bar, tearoff=0)
        settings_menu.add_command(label="Configure")
        settings_menu.add_command(label="Extensions")
        settings_menu.add_command(label="Themes")
        settings_menu.add_command(label="Update")
        settings_menu.add_command(label="Donate")
        menu_bar.add_cascade(label="⚙️ Settings", menu=settings_menu)

        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.about)
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menu_bar)

    def new_file(self):
        self.file_path = None
        self.create_new_tab()
        self.text_editor.delete('1.0', tk.END)

    def closefile(self):
        if messagebox.askyesno("Close File", "⚠ Do you really want to close this file?"):
            self.file_path = None
            self.text_editor.delete('1.0', tk.END)
    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, 'r') as file:
                content = file.read()
                self.create_new_tab(file_path, content)
            self.file_path = file_path
            self.text_editor.delete('1.0', tk.END)
            self.text_editor.insert('1.0', content)

    def exit(self):
        if messagebox.askyesno("Exit", "⚠ Do you really want to exit?"):
            self.root.destroy()
    def save_file(self, event=None):
        if self.file_path:
            with open(self.file_path, 'w') as file:
                file.write(self.text_editor.get('1.0', tk.END))
        else:
            self.save_as_file()

    def save_as_file(self):
        global file_path
        file_path = filedialog.asksaveasfilename(defaultextension=".py", filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        if file_path:
            self.file_path = file_path
            with open(file_path, 'w') as file:
                self.tab_name = os.path.basename(file_path) if file_path else "Untitled"
                self.tab_id = self.notebook.add(self.tab_frame, text=self.tab_name)

                file.write(self.text_editor.get('1.0', tk.END))

    def run_code(self, event=None):
        #global file_path
        if not self.file_path:
            messagebox.showwarning("Save File", "Please save your code before running.")
            return

        self.save_file()  # Ensure the latest code is saved

        command = f'python3 "{self.file_path}"'
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

        stdout, stderr = process.communicate()

        self.console.delete('1.0', tk.END)
        if stdout:
            self.console.insert(tk.END, stdout)
        if stderr:
            self.console.insert(tk.END,red+ stderr)

    def debug_code(self):
        messagebox.showinfo("Debug", "Debugging feature coming soon!")

    

    def highlight_syntax(self, text_editor):
        content = text_editor.get("1.0", tk.END)
        self.text_editor.mark_set("range_start", "1.0")
        for token, content in lex(content, PythonLexer()):
            self.text_editor.mark_set("range_end", "range_start + %dc" % len(content))
            self.text_editor.tag_add(str(token), "range_start", "range_end")
            self.text_editor.mark_set("range_start", "range_end")
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

    def git_commit(self):
        try:
            repo = git.Repo(os.path.dirname(self.file_path))
            message = simpledialog.askstring("Git Commit", "Enter commit message:")
            if message:
                repo.git.add(A=True)
                repo.index.commit(message)
                messagebox.showinfo("Git Commit", "Changes committed.")
        except Exception as e:
            messagebox.showerror("Git Commit Error", str(e))

    def git_push(self):
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
        self.text_editor.event_generate("<<Undo>>")

    def redo(self):
        self.text_editor.event_generate("<<Redo>>")

    def cut(self):
        self.text_editor.event_generate("<<Cut>>")

    def copy(self):
        self.text_editor.event_generate("<<Copy>>")

    def paste(self):
        self.text_editor.event_generate("<<Paste>>")

    def find(self):
        search_term = simpledialog.askstring("Find", "Enter text to find:")
        if search_term:
            text = self.text_editor.get("1.0", tk.END)
            if search_term in text:
                messagebox.showinfo("Find", f"'{search_term}' found in the code.")
            else:
                messagebox.showinfo("Find", f"'{search_term}' not found.")

    def preferences(self):
        messagebox.showinfo("Preferences", "Preferences feature coming soon!")

    def about(self):
        messagebox.showinfo("About", "Python IDE v2.0 - A Python IDE with Git integration by KentLabs\nEmail: mskalvin@cyberh4ck3r04.com")
    def get_current_editor(self):
        current_tab = self.notebook.select()
        return self.notebook.nametowidget(current_tab).winfo_children()[0]

if __name__ == "__main__":
    root = tk.Tk()
    app = PythonIDE(root)
    root.mainloop()