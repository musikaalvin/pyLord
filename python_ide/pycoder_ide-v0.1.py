import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import os
import subprocess
import pygments
from pygments.lexers import PythonLexer
#from pygments.formatters import TkFormatter

class PythonIDE:
    def __init__(self, root):
        self.root = root
        self.root.title("Python IDE")
        self.root.geometry("700x900")

        self.file_path = None
        self.style = ttk.Style()
        self.style.theme_use('clam')
        fonts = ['AndroidClock','Roboto Medium','Noto Sans Telugu UI','Roboto Thin','RobotoNum3L_ver2.2_191105 Light','Roboto Condensed Medium']
        self.style. configure (root,font=('RobotoNum3L_ver2.2_191105 Light',8),foreground='black',background='white')

        # Create UI Components
        self.create_menu()
        self.create_project_explorer()
        self.create_text_editor()
        self.create_console()

    def create_menu(self):
        menu_bar = tk.Menu(self.root)

        # File Menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="New", command=self.new_file, accelerator="Ctrl+N")
        file_menu.add_command(label="Open", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As", command=self.save_as_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_ide)
        menu_bar.add_cascade(label="File", menu=file_menu)

        # Edit Menu
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        edit_menu.add_command(label="Undo", command=lambda: self.text_editor.event_generate("<<Undo>>"))
        edit_menu.add_command(label="Redo", command=lambda: self.text_editor.event_generate("<<Redo>>"))
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut", command=lambda: self.text_editor.event_generate("<<Cut>>"))
        edit_menu.add_command(label="Copy", command=lambda: self.text_editor.event_generate("<<Copy>>"))
        edit_menu.add_command(label="Paste", command=lambda: self.text_editor.event_generate("<<Paste>>"))
        menu_bar.add_cascade(label="Edit", menu=edit_menu)

        # Run Menu
        run_menu = tk.Menu(menu_bar, tearoff=0)
        run_menu.add_command(label="Run", command=self.run_code, accelerator="F5")
        menu_bar.add_cascade(label="Run", menu=run_menu)

        # Help Menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Python IDE v1.0"))
        menu_bar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menu_bar)

    def create_project_explorer(self):
        self.project_frame = ttk.Frame(self.root, width=100, relief=tk.SUNKEN)
        self.project_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.project_label = ttk.Label(self.project_frame, text="Project Explorer", font=("Arial", 10, "bold"))
        self.project_label.pack(pady=5)

        self.project_list = tk.Listbox(self.project_frame)
        self.project_list.pack(fill=tk.BOTH, expand=True)
        self.project_list.bind("<Double-Button-1>", self.open_selected_file)

        # Open project folder
        open_folder_button = ttk.Button(self.project_frame, text="Open Folder", command=self.open_folder)
        open_folder_button.pack(pady=5)

    def create_text_editor(self):
        self.text_editor = scrolledtext.ScrolledText(self.root, wrap="word", font=("Consolas", 10),height="10")
        self.text_editor.pack(expand=True, fill='both', side=tk.LEFT)

        # Apply Syntax Highlighting
        self.apply_syntax_highlighting()

    def create_console(self):
        self.console = scrolledtext.ScrolledText(self.root, height=20, font=("Consolas", 10), bg="black", fg="white")
        self.console.pack(fill='both', expand=True, side=tk.BOTTOM)

    def apply_syntax_highlighting(self):
        """ Apply syntax highlighting to the text editor """
        code = self.text_editor.get("1.0", tk.END)
        self.text_editor.mark_set("range_start", "1.0")

        for token, content in pygments.lex(code, PythonLexer()):
            self.text_editor.insert("range_start", content, token)
            self.text_editor.mark_set("range_start", "range_start + %dc" % len(content))

    def open_folder(self):
        global folder
        """ Open a project folder and list files in the Project Explorer """
        folder = filedialog.askdirectory()
        if folder:
            self.project_list.delete(0, tk.END)
            for file in os.listdir(folder):
                if file.endswith(".py"):
                    self.project_list.insert(tk.END, os.path.join('/'+file))

                    #self.project_list.insert(tk.END, os.path.join(folder, file))

    def open_selected_file(self, event):
        """ Open a file from the project explorer """
        selected = self.project_list.curselection()
        if selected:
            file_path = self.project_list.get(selected[0])
            self.open_file(file_path)

    def new_file(self):
        self.file_path = None
        self.text_editor.delete("1.0", tk.END)

    def open_file(self, path=None):
        global folder
        """ Open a Python file """
        if path is None:
            path = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])

        if path:
            with open(str(folder)+path, "r") as file:
                content = file.read()
            self.file_path = path
            self.text_editor.delete("1.0", tk.END)
            self.text_editor.insert("1.0", content)
            self.apply_syntax_highlighting()

    def save_file(self):
        if self.file_path:
            with open(self.file_path, "w") as file:
                file.write(self.text_editor.get("1.0", tk.END))
        else:
            self.save_as_file()

    def save_as_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".py", filetypes=[("Python Files", "*.py")])
        if file_path:
            self.file_path = file_path
            with open(file_path, "w") as file:
                file.write(self.text_editor.get("1.0", tk.END))

    def run_code(self):
        if not self.file_path:
            messagebox.showwarning("Save File", "Please save your code before running.")
            return

        self.save_file()  # Ensure latest code is saved

        command = f'python3 "{self.file_path}"'
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)

        stdout, stderr = process.communicate()

        self.console.delete("1.0", tk.END)
        if stdout:
            self.console.insert(tk.END, stdout)
        if stderr:
            self.console.insert(tk.END, stderr)

    def exit_ide(self):
        self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = PythonIDE(root)
    root.mainloop()
