from impt import *
from menu import *
from time import strftime
#ip ='192.168.104.222'
os.system("clear")
logo()
menu1()
while True:
    hos = socket.gethostname()
    uname = str('127.0.0.1')
    #os.system('whoami'))
    #uname = socket.gethostbyname(hos)
    date = strftime("%d %m %y")
    cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+str(uname)+"\033[1;37m|\033[1;33m" + date + "\033[1;37m>\n|___________~$> "))   
    #cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+uname+"\033[1;37m|\033[1;33m" + date + "\033[1;37m>\n|___________~$> "))   

    if '11' in cmd:
        crackhash()
        
    #if "1" in cmd:
        #execute(cmd)
       # if "xx" or 'b' or 'back' in cmd:
           # os.system('clear')
          #  logo()
          #  menu1()
    if "2" in cmd:
        os.system('clear')
        logo()
        menu2()
        cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+uname+"\033[1;37m|\033[1;33m" + date + "\033[1;378m>\n|___________~$> "))
        if "1" in cmd:
             #listener()
             import TcpReverseShellServer.py
        if "2" in cmd:
              #client()
              import TcpReverseShellClient.py
    if "3" in cmd:
        bomb()
    if "xx" or 'b' or 'back' in cmd:
        os.system('clear')
        logo()
        menu1()
    if "4" in cmd:
        print(green + "*"*25)
        ask = input(white+'['+red+'+'+white+']'+purple+' use default host ?  '+green+' y'+white+'/'+red+'n'+white+' :')
        if ask == 'y':
             default = 'localhost'
             port = input(white+"["+red+"+"+white+"] "+purple+"Enter port to scan :"+ purple)
             scan_target(default, int(port))
        if ask == 'n':
             host = input(purple +"[+] Enter target to scan :"+ purple)
             port = input(purple +"[+] Enter port to scan :"+ purple)
             scan_target(host, int(port))        
        
    if "5" in cmd:
        #os.system('clear')
        logo()
        sleep(0.2)
        installtools()
        sleep(0.2)
    if "1" in cmd:
    	payload()
    if "6" in cmd:
        os.system('clear')
        #import 
        os.system("clear && clear && python3 antivirus_pro_v2.3.py")
        #from antivirus_pro import *
        #kentviruscan()
    if '7' in cmd:
        os.system('clear')
        logo()
        menu4()
        cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+uname+"\033[1;37m|\033[1;33m" + date + "\033[1;37m>\n|___________~$> "))      
        if "1" in cmd:       
            receivefile()
        if  "2" in cmd:
            sendfile()
    if "8" in cmd:
        while True:
            os.system('clear')
            logo()
            menu3()
            cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+uname+"\033[1;37m|\033[1;33m" + date + "\033[1;37m>\n|___________~$> "))
            if "1" in cmd:
                 file = input (red +"file directory to encrypt >> ")
                 path = "/sdcard/" + file
                 encryptfile(path)
            if "2" in cmd:
                decryptfile()
            elif '3' in cmd:
            	os.system('python3 kentlocker.py')
            elif 'exit' in cmd:
                print(red +'[!] exiting ...')                   
                sys.exit()
            elif "xx" or 'b' or 'back' in cmd:
               os.system('clear && python3 sys.argv[0]')
               #logo()
               #menu1()
    if str('9') in cmd:
        os.system('clear')
        logo()
        menu5()
        cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+uname+"\033[1;37m|\033[1;33m" + date + "\033[1;37m>\n|___________~$> "))
        if "1" in cmd:
             from virusrun import *
        if "2" in cmd:
             virusrun2()
        if "3" in cmd:
              virusrun3()       
        if "2" in cmd:
              virusrun4()                 
    if "10" in cmd:
         os.system("python")
  
    else:
            hos = socket.gethostname()
            uname = socket.gethostbyname(uname)
            date = strftime("%d %m %y")
            cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+uname+"\033[1;37m|\033[1;33m" + date + "\033[1;37m>\n|___________~$> "))
            while True:
                cmd = str(input(white +"[\033[1;32mh4ck3r\033[1;37m]\033[1;36m@\033[1;37m[\033[1;31m"+uname+"\033[1;37m|\033[1;33m" + date + "\033[1;37m>\n|___________~$> "))

