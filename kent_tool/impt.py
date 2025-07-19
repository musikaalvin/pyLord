import os, sys, threading, subprocess, sys, socket, glob, re, hashlib, random#, pyAesCrypt
#import shell, passcracker, bkdoor, portscanner, antivirus, bkdoor_tcp, kentshare_receiver, kentshare_sender, antivirus, ddos, expt
#folder = '/storage/emulated/0/kentsoft/kent_bkdoor/modules/'
folder = os.getcwd()+"/modules/"
directorys = "/sdcard/a/"
#directorys = "/Users/st.marys 29/"
#glob.glob(os.chdir(os.path.join(folder)))
from sktmodule import * #connect, close, scan_target, start_server
from menu import * #menu1, menu2, menu3, menu4, menu5
from bkdoorclient import client
from bkdoorlistener import *
#from notfound import cmdnotfound
#from encryptervirus import encrypt
from sender import sendfile
from receiver import receivefile
from hashcracker import crackhash
from init import __init__
from ddos import bomb
from colors import *
from install import installtools
from sktmodule import *
from datetime import datetime
from time import sleep
from time import strftime
from encrypter import encryptfile
from encryptvirus import encryptfile
from zipvirus import *
from deltvirus import *
from virnamesdb import *
from decrypter import decryptfile
from adminshell import payload
from scriptrunner import execute
from adminshellconfig import *# config
#from admincmdshell import cmdshell
#from virusrun import *
global scan, s, conect, close, connect, start_server
global start, status, file
from filesize import *
from sniffer import sniff
#from scan import *
import zipfile
from av_engine import scan_directory
from av_engine_tk import Av_engine_tk
