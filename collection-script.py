#!/usr/bin/env python
import sys
import os
from datetime import datetime
import time
import platform
import socket
import _winreg


"""
Purpose of this program is to collect information from windows systems to help with vunlerability assessments
"""
#global variables
path = ""
date = ""
sys_os = []
hostname = ""
ipaddr = ""
aname = ""
dir = ""
reg = ""
registry = {}


def get_tool_path():
    """
    ask user for tool path, validate it, return it
    """
    global path
    path = raw_input("What is the path to the tools directory: ")
    if path[-1] != "\\":
        path = path + "\\"
    
    if os.path.exists(path + "psloglist.exe") == True:
        return path
    else:
        print "Invalid path, tools not found"
        path = get_tool_path()
    return path

def date_time_stamp():
    """
    Here we want to get the current date/time and format it for naming files
    """
    cal_date = ""
    cal_time = ""
    whole = ""
    zone = ""
    
    whole = str(datetime.now()).split(" ")
    cal_date = whole[0]
    cal_date = cal_date.replace("-", ".")
    cal_time = whole[1].split(":")
    zone = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
    zone = zone / 60 / 60 * -1
    date = cal_date + "-" + cal_time[0] + cal_time[1] + "GMT" + str(zone)
    return date
    
def get_os():
    """
    We want to get the windows OS version we are working with.
    It changes some of the other functions later.  Some items are windows 7 or xp etc specific
    """
    
    pform = ""
    version = ""
    spack = ""
    name = ""
    
    pform = platform.system()
    if pform == "Windows":
        version = platform.win32_ver()
        temp = pform + " " + version[0] + " " + version[2]
        name = list(platform.uname())[1]
        return temp, name
    else:
        print "Not Windows?  Terminating"
        exit()
    return

def get_ip():
    """
    We need to determine how many IP addresses are assigned to the system.
    The user needs to let us know which is primary if there are more than 1.
    """
    socketip =[]
    listip = []
    i = []
    select = 0
    count = 0
    choose = ""
    selection = ""
    socketip = socket.getaddrinfo(socket.gethostname(), None)
    for i in socketip:
        if i[0] == 2:
            listip.append(i[4][0])
    if len(listip) > 1:
        print "\n\nWe have more than 1 IP Address on this system."
        print "Please choose the primary below:"
        for choose in listip:
            print str(count) + " " + choose
            if count < len(listip):
                count += 1
        
        while True:
            selection = raw_input("\nSelection: ")
            if int(selection) > (len(listip) - 1 ) or int(selection) < 0:
                print "Incorrect, pick one of the above!"
            else:
                return listip[int(selection)]

def make_assessment_name():
    """
    Here we combine a few of the above to create a descriptive directory and filename structure.
    This ensures that later we know what we collected and validate it is complete.
    """
    global date, hostname, ipaddr, aname, dir
    import os
    
    dir = "c:\\assessment\\"
    if os.path.exists(dir) == False:
        os.mkdir(dir)
    aname = date + "-" + hostname + "-" + ipaddr
    dir = dir + aname
    os.mkdir(dir)
    return

def sysint_registry(action):
    """
    open the reg file, create or delete the registry keys in Computer\HKEY_CURRENT_USER.
    """
    global ptestath, reg, registry
    file = ""
    reg = ""
    regfile = ""
    
    
    if action == "create":
        _winreg.CreateKey(_winreg.HKEY_CURRENT_USER,"HKEY_CURRENT_USER\\Software\\Sysinternals")
        reg = open(path + 'sysinternals-eulas.reg', 'r')
        for regfile in reg:
            regfile = regfile[:-1]
            if regfile.startswith("[HKEY_CURRENT_USER\\Software\\Sysinternals"):
                key = regfile[19:-1]
                registry[key] = []
                _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, key)
                akey = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, key, 0, _winreg.KEY_WRITE)
            elif regfile.startswith('"'):
                value = regfile.split("=")
                name = value[0][1:-1]
                type = value[1].split(":")
                registry[key] = (name, int(type[1]))
                try:
                    _winreg.SetValueEx(akey, registry[key][0], 0, _winreg.REG_DWORD, registry[key][1])
                except:
                    print "Something is wrong with the sysinternals registry eula file,"
                    print "Or something is wrong with the permissions in the registry Hive/key"
                    print r"HKEY_CURRENT_USER\Software\Sysinternals"
    elif action == "delete":
        for key in sorted(registry.iterkeys(), reverse = True):
            if key == "Software\\Sysinternals":
                _winreg.DeleteKey(_winreg.HKEY_CURRENT_USER, key)
            else:
                _winreg.DeleteKey(_winreg.HKEY_CURRENT_USER, key)

#print out usage message
print "\nWelcome to the Vulnerability Assessment Collection Tool (VZP VAC).\n\n"
print "This script is designed to run locally on a system where"
print "The utilities needed are also local to the system, either"
print "copied under c:\assessment\tools, mapped back to a share on"
print "the assessment laptop, or from a CD.  You will need to provide"
print "the location for the script to run properly.\n"
print "The script will create a directory local to this system called"
print "c:\\assessment\\ \n"
print "All collection files and logs will be stored in a unique"
print "directory under c:\\assessment\\.  When it is done, copy all those "
print "directories and files up the the assessment laptop via the "
print "collection share.  Then, delete the local c:\assessment directory"
print "here.  Future versions may make the mapping, move the files, and"
print "delete the temporary files here automatically."

#first get the path to the tools needed
path = get_tool_path()

#get the date and time and format it
date = date_time_stamp()

#get the OS and hostname and format those
sys_os, hostname = get_os()

#get the IP address, format it
ipaddr = get_ip()

#create the directories and and standard filename
make_assessment_name()

#create the sysinternals EULA registry keys
sysint_registry('create')








