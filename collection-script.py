#!/usr/bin/env python
import sys, os, time, platform, socket, _winreg, subprocess, win32security, msvcrt
from datetime import datetime
from subprocess import PIPE
from win32netcon import *
from psutil import *
from win32net import *
from win32wnet import *






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
sqldir = ""
reg = ""
registry = {}
outputpath = ''



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

def get_output_path():

    path = raw_input('Default output path is c:\\assessment\\. \nHit enter to keep or type new path/unc to change: ')
    if path.startswith('\\'):
        user = raw_input('username: ')
        password = raw_input('password: ')
        outpath = WNet32addconnection2(['RESOURCETYPE_DISK','O:',path,''],password,username)
        return outpath
    elif path == '':
        return 'c:\assessment'
    else:
        if os.path.exists(path):
            return path
        else:
            print 'That path doesn\'t exist, try again.'
            get_output_path()
        

def date_time_stamp():
    """
    Here we want to get the current date/time and format it for naming files
    """
    cal_date = ""
    cal_time = ""
    whole = ""
    zone = ""
    splittz = []
    
    whole = str(datetime.now()).split(" ")
    cal_date = whole[0]
    cal_date = cal_date.replace("-", ".")
    cal_time = whole[1].split(":")
    #zone = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
    #zone = zone / 60 / 60 * -1
    zone = time.strftime("%z")
    splittz = zone.split(" ")
    zone = splittz[0][:1] + splittz[1][:1] + splittz[2][:1]    
    date = cal_date + "-" + cal_time[0] + cal_time[1] + zone
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
    return listip[0]

def make_assessment_name():
    """
    Here we combine a few of the above to create a descriptive directory and filename structure.
    This ensures that later we know what we collected and validate it is complete.
    """
    global date, hostname, ipaddr, aname, dir, sqldir
    import os
    
    dir = "c:\\assessment\\"
    if os.path.exists(dir) == False:
        os.mkdir(dir)
    aname = str(date) + "-" + hostname + "-" + str(ipaddr)
    dir = dir + aname + "\\"
    sqldir = dir + "sql\\"
    os.mkdir(dir)
    os.mkdir(sqldir)
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

def collection():
    global path, date, sys_os, hostname, ipaddr, aname, dir, sqldir
    infile = []
    outfile = ""
    sqlfile = ""
    sqlline = ""
    info = []
    flag = 0
    flag2 = 0
    flag3 = 0
    proc = 0
    processor = ""
    commandline = ""
    bname = dir + aname
    sqlname = sqldir + aname
    logfile = open(dir + "assessment-log.txt", 'w')
    skip = 0
    
    
    #Start by getting System Info
    infile = subprocess.Popen("systeminfo.exe", stdout=PIPE, stderr=PIPE)
    infile = infile.communicate()[0].split("\n")
    outfile = open(bname + "-systeminfo.txt", 'w')
    sqlfile = open(sqlname + "-systeminfo.csv", 'w')
    sqlfile.write("IP")
    for line in infile:
        line = line[:-1]
        if line != "" and line.startswith("Hotfix") == 0 and flag == 0:
            info = line.split(":", 1)
            info[0] = info[0].lstrip()
            info[1] = info[1].lstrip()
            if info[0].startswith("Proc") == 1:
                processor = info[0]
                proc = 1
            elif proc == 1:
                info[0] = processor
                outfile.write(info[0] + "," + info[1] + "\n")
                sqlfile.write("," + info[0])
                sqlline += "," + info[1]
                proc = 0
            else:
                info[1] = info[1].split(",")[0]
                outfile.write(info[0] + "," + info[1] + "\n")
                sqlfile.write("," + info[0])
                sqlline += "," + info[1]
        elif line.startswith("Hotfix") == 1:
            flag = 1
            outfile.close
            sqlfile.write("\n" + ipaddr + sqlline)
            sqlfile.close
    logfile.write('Systeminfo module                Passed\n')
    
    #Get the Software Registry        
    infile = subprocess.Popen("regedit.exe /E /S " + bname + "-Software-Registry.reg HKEY_LOCAL_MACHINE\\Software")
    logfile.write('Software Reg Module              Passed\n')
    
    #get the environment variables CSV and raw file
    outfile = open(sqlname + "-environment-variables.csv", 'w')
    rawfile = open(bname + "-env-variables.txt", 'w')
    header = "key/ip,VarName,Value\n"
    outfile.write(header)
    
    #Get environment variables
    for key in os.environ:
        outfile.write(ipaddr + "," + key + "," + os.environ[key] + "\n")
        rawfile.write(key + ":\t" + os.environ[key] + "\n")
    rawfile.close
    outfile.close
    logfile.write('Environment Var Module           Passed\n')
    
    
    #get IP and Interface information
    with open(bname + '-ipconfig.txt', 'w') as outfile:
        subprocess.call('ipconfig.exe /all', stdout=outfile)
    logfile.write('IPConfig Module                  Passed\n')
    
    #get AD DC and domain name information
    try:
        dc = win32security.DsGetDcName()
        if dc:
            dcfile = open(sqlname + '-wkstation-AD-info.csv', 'w')
            header = "ip/key,DomainControllerAddress,DnsForestName,DomainName,DomainControllerName"
            dcfile.write(header + "\n")
            dcfile.write(ipaddr + "," + dc['DomainControllerAddress'][2:] + "," + 
                         dc['DnsForestName'] + "," + dc['DomainName'] + "," + dc['DomainControllerName'][2:]
                         + "\n")
            dcfile.close
            logfile.write('AD DC/Name Module                Passed\n')
    except:
        logfile.write('AD DC/Name Module                failed/no domain\n')
        pass
    
    
    #get IP routing informatino
    with open(bname + '-Routes.txt', 'w') as outfile:
        subprocess.call('netstat.exe -nr ', stdout=outfile)
    logfile.write('IP Route Raw Module              Passed\n')
    
    
    #Get Network Listeners Raw
    with open(bname + '-TCP-NetworkListeners.txt', 'w') as outfile:
        p1 = subprocess.Popen('netstat.exe -nao', stdout=PIPE)
        p2 = subprocess.Popen('findstr /c:LISTEN', stdin=p1.stdout, stdout=outfile)
    logfile.write('TCP Netstat Raw Module           Passed\n')
    with open(bname + '-UDP-NetworkListeners.txt', 'w') as outfile:
        p1 = subprocess.Popen('netstat.exe -nao', stdout=PIPE)
        p2 = subprocess.Popen('findstr /c:*:*', stdin=p1.stdout, stdout=outfile)
    logfile.write('UDP Netstat Raw Module           Passed\n')
        
    
    #Get Network Listeners CSV
    """
    Uses a combination of PSUTIL module and Sysinternals and OS utilities
    to create two tables for TCP and UDP and give src, dst, ports, PIDs,
    and command line or executable
    """
    
    netstat_header = []
    tcp_listen = open(sqlname + '-netstat-listeners-TCP.csv', 'w')
    udp_listen = open(sqlname + '-netstat-listeners-UDP.csv', 'w')
    
    netstat = subprocess.Popen('netstat.exe -nao', stdout=PIPE, stderr=PIPE)
    netstat = netstat.communicate()[0].split("\n")
    for line in netstat:
        print 'Hit "c" to skip if needed...\n'
        if msvcrt.kbhit():
            if ord(msvcrt.getch()) == 99 or ord(msvcrt.getch()) == 67:
                skip = 1
                break
        line = line.split()
        
        if line and line[0] == "Proto":
            line.pop(2)
            line.pop(3)
            line.append("Executable")
            line.insert(0,"key/ip")
            tcp_listen.write(",".join(line) + '\n')
            line.pop(4)
            udp_listen.write(",".join(line) + '\n')
        elif line and line[0] == "TCP" and line[3] == "LISTENING":
            try:
                process = Process(int(line[4]))
                try:
                    cmd = process.exe
                    line.append(cmd)
                except:
                    process = subprocess.Popen([path + 'tcpvcon.exe', '-a', '-c', '-n', line[4]], stdout=PIPE)
                    process = process.communicate()[0].split(",")
                    line.append(process[1])
            except:
                cmd = 'orphaned process'
                line.append(cmd)
            line.insert(0, ipaddr)
            tcp_listen.write(",".join(line) + '\n')
        elif line and line[0] == "UDP" and line[2] == "*:*":
            process = Process(int(line[3]))
            try:
                cmd = process.exe
                line.append(cmd)
            except:
                process = subprocess.Popen([path + 'tcpvcon.exe', '-a', '-c', '-n', line[3]], stdout=PIPE)
                process = process.communicate()[0].split(",")
                line.append(process[1])
            line.insert(0, ipaddr)
            udp_listen.write(",".join(line) + '\n')
    tcp_listen.close
    udp_listen.close
    if skip == 1:
        logfile.write('Listeners CSV Module             SKIPPED\n')
        skip = 0
    else:
        logfile.write('Listeners CSV Module             Passed\n')

    #get local users and group membership
    users = NetUserEnum(None,2)
    header = "ip/key,name,full_name,password_age,num_logons,acct_expires,last_logon,groups\n"
    sqlfile = open(sqlname + '-localusers.csv', 'w')
    sqlfile.write(header)
    for x in range(len(users[0])):
        groups = NetUserGetLocalGroups(None, users[0][x]['name'])
        groups = ",".join(groups) + "\n"
        if users[0][x]['acct_expires']== -1:
            line = ",".join((ipaddr, users[0][x]['name'], users[0][x]['full_name'],
                            str(users[0][x]['password_age']/60/60/24),
                            str(users[0][x]['num_logons']),
                            'NEVER',
                            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(users[0][x]['last_logon'])),
                            groups))
        else:
            line = ",".join((ipaddr, users[0][x]['name'], users[0][x]['full_name'],
                             str(users[0][x]['password_age']/60/60/24),
                             str(users[0][x]['num_logons']),
                             time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(users[0][x]['acct_expires'])),
                             time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(users[0][x]['last_logon'])),
                             groups))
        sqlfile.write(line)
    logfile.write('Local User and Group Module      Passed\n')
    
    #get AD Users and membership if DC present
    try:
        dc = NetGetDCName()
        header = 'DC,name,full_name,password_age,num_logons,acct_expires,last_logon,groups\n'
        sqlfile = open(sqlname + "-AD-Users.csv", "w")
        sqlfile.write(header)
        #dc = NetGetDCName()
        users = NetUserEnum(dc,2)
        adgroups = []
        if dc:
            for x in range(len(users[0])):
                groups = NetUserGetGroups(dc, users[0][x]['name'])
                for y in range(len(groups)):
                    adgroups.append(str(groups[y][0]))
                groups = ",".join(adgroups) + "\n"
                adgroups = []
                line = ",".join((ipaddr, users[0][x]['name'], users[0][x]['full_name'],
                                str(users[0][x]['password_age']/60/60/24), str(users[0][x]['num_logons']),
                                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(users[0][x]['acct_expires'])),
                                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(users[0][x]['last_logon'])),
                                groups))
                sqlfile.write(line)#code
        logfile.write('AD Users Module                  Passed\n')
    except:
        logfile.write('AD Users Module                  Failed/No Domain\n')    
        pass
    
        
    
    #get local groups and group membership
    groups = []
    header = "ip/key,group_name,users\n"
    sqlfile = open(sqlname + '-localgroups.csv', 'w')
    sqlfile.write(header)
    line = subprocess.Popen('net.exe localgroup', stdout=PIPE)
    line = line.communicate()[0].split("\n")
    for x in range(len(line)):
        if line[x].startswith('*'):
            groups.append(line[x][1:-1])
        
    for x in range(len(groups)):
        temp = NetLocalGroupGetMembers(socket.gethostname(), groups[x], 1)
        for y in range(len(temp[0])):
            groups[x] = ",".join((groups[x], temp[0][y]['name']))
        groups[x] = ",".join((ipaddr, groups[x], "\n"))
        sqlfile.write(groups[x])
    logfile.write('Local group Module               Passed\n')
    
    
    #get AD groups and membership if DC present
    try:
        dc = NetGetDCName()
        adgroups = []
        adgroup = ""
        users = []
        sqlfile = open(sqlname + '-AD-Groups.csv', 'w')
        header = 'DC,ADGroupName,Users\n'
        sqlfile.write(header)
        if dc:
            groups = NetGroupEnum(dc,2)
            for x in range(len(groups[0])):
                users = NetGroupGetUsers(dc,str(groups[0][x]['name']), 1)
                for y in range(len(users[0])):
                    adgroups.append(str(users[0][y]['name']))
                adgroup = dc + "," + str(groups[0][x]['name']) + "," + ",".join(adgroups) + "\n"
                sqlfile.write(adgroup)
                adgroups = []
        logfile.write('AD Group Module                  Passed\n')
    except:
        logfile.write('AD Group Module                  Failed/No Domain\n')    
        pass
    
    
    #Get local shares
    header = 'ip/key,sharename,path\n'
    sqlfile = open(sqlname + '-localshares.csv', 'w')
    sqlfile.write(header)
    line = NetShareEnum(socket.gethostname(),2)
    for x in range(len(line[0])):
        share = ",".join((ipaddr, str(line[0][x]['netname']), str(line[0][x]['path']), "\n"))
        sqlfile.write(share)
    logfile.write("Local Share Module               Passed\n")

        
    #Get password policy
    with open(bname + '-password-policy.txt', 'w') as outfile:
        subprocess.call('net.exe accounts', stdout=outfile)
    logfile.write('Password Policy Module           Passed\n')
    """
    Add post processing
    """
    
    #NBTSTAT
    try:
        with open(bname + '-nbtstat-cachednames.txt', 'w') as outfile:
            subprocess.call('nbtstat.exe -r', stdout=outfile)
        with open(bname + '-nbtstat-remotesessions.txt', 'w') as outfile:
            subprocess.call('nbtstat.exe -S', stdout=outfile)
        logfile.write('NBTSTAT Module                   Passed\n')
    except:
        logfile.write('NBTSTAT Module                   Failed/64bit System?\n')
        pass
        #with open(bname + '-nbtstat-cachednames.txt', 'w') as outfile:
        #    subprocess.call('nbtstat.exe -r', stdout=outfile)
        #with open(bname + '-nbtstat-remotesessions.txt', 'w') as outfile:
        #    subprocess.call('nbtstat.exe -S', stdout=outfile)
    
    #get firewall info
    with open(bname + '-firewall-config.txt', 'w') as outfile:
        subprocess.call('netsh.exe firewall show config', stdout=outfile)
    logfile.write('firewall module                  Passed\n')
    """
    Add post processing
    """


    #Get task / process list
    try:
        with open(bname + '-tasks-tasklist.txt', 'w') as outfile:
            subprocess.call('tasklist.exe', stdout=outfile)
        logfile.write('tasklist module                  Passed\n')
    except:
        logfile.write('tasklist module                  failed\n')
    
    
    try:
        with open(bname + '-tasks-wmic.txt', 'w') as outfile:
            subprocess.call('wmic.exe process list', stdout=outfile)
        logfile.write('wmic tasks module                Passed\n')
    except:
        logfile.write('wmic tasks module                Failed\n')
        
        
    try:
        with open(bname + '-tasks-pslist-tree.txt', 'w') as outfile:
            subprocess.call(path + 'pslist.exe -t', stdout=outfile)
        logfile.write('pslist task tree module          Passed\n')
    except:
        logfile.write('pslist task tree module          Failed\n')
        
        
    try:
        with open(bname + '-tasks-pslist-detailed.txt', 'w') as outfile:
            subprocess.call(path + 'pslist.exe -x', stdout=outfile)
        logfile.write('pslist detailed module           Passed\n')
    except:
        logfile.write('pslist detailed module           Failed\n')
    """
    Add post processing
    """
    
    #sysinternals
    try:
        with open(bname + '-whois-loggedon.txt', 'w') as outfile:
            subprocess.call(path + 'psloggedon.exe', stdout=outfile)
        logfile.write('loggedon module                  Passed\n')
    except:
        logfile.write('loggedon Module                  Failed\n')
        
        
    try:
        with open(bname + '-local-services.txt', 'w') as outfile:
            subprocess.call(path + 'psservice.exe', stdout=outfile)
        logfile.write('PSservices List Module           Passed\n')
    except:
        logfile.write('PSservices List Module           Failed\n')
        
        
    try:
        with open(bname + '-services-config.txt', 'w') as outfile:
            subprocess.call(path + 'psservice.exe config', stdout=outfile)
        logfile.write('PSservices detailed Module       Passed\n')
    except:
        logfile.write('PSservices detailed Module       Failed\n')
        
        
        
    try:
        with open(sqlname + '-tcpview.csv', 'w') as outfile:
            subprocess.call(path + 'tcpvcon.exe -a -c -n', stdout=outfile)
        logfile.write('tcpview csv module               Passed\n')
    except:
        logfile.write('tcpview csv module               Failed\n')
        
        
        
    try:
        with open(sqlname + '-system-event-log.csv', 'w') as outfile:
            subprocess.call(path + 'psloglist.exe -s system', stdout=outfile)
        logfile.write('System Event Log Module          Passed\n')
    except:
        logfile.write('System Event Log Module          Failed\n')
        
        
        
    try:
        with open(sqlname + '-application-event-log.csv', 'w') as outfile:
            subprocess.call(path + 'psloglist.exe -s application', stdout=outfile)
        logfile.write('Application Event Log Module     Passed\n')
    except:
        logfile.write('Application Event Log Module     Failed\n')
        
        
        
    try:
        with open(sqlname + '-security-event-log.csv', 'w') as outfile:
            subprocess.call(path + 'psloglist.exe -s security', stdout=outfile)
        logfile.write('Security Event Log Module        Passed\n')
    except:
        logfile.write('Security Event Log Module        Failed\n')
        
        
        
    try:
        with open(sqlname + '-autoruns.csv', 'w') as outfile:
            subprocess.call(path + 'autorunsc.exe -a -c -m', stdout=outfile)
        logfile.write('Autoruns Module                  Passed\n')
    except:
        logfile.write('Autoruns Module                  Failed\n')
        
        
        
    try:
        with open(bname + '-open-handles.txt', 'w') as outfile:
            subprocess.call(path + 'handle.exe -a', stdout=outfile)
        logfile.write('Open Handles Module              Passed\n')
    except:
        logfile.write('Open Handles Module              Failed\n')
        
        
        
    try:
        with open(bname + '-logonsessions.txt', 'w') as outfile:
            subprocess.call(path + 'logonsessions.exe', stdout=outfile)
        logfile.write('logonsessions Module             Passed\n')
    except:
        logfile.write('logonsessions Module             Failed\n')
        
        
        
    try:
        with open(bname + '-files-opened-remotely.txt', 'w') as outfile:
            subprocess.call(path + 'psfile.exe', stdout=outfile)
        logfile.write('remote open files module         Passed\n')
    except:
        logfile.write('remote open files module         Failed\n')
        
        
        
    try:
        with open(sqlname + '-installed-apps-patches.csv', 'w') as outfile:
            subprocess.call(path + 'psinfo.exe', stdout=outfile)
        logfile.write('Installed Apps/Patches Module    Passed\n')
    except:
        logfile.write('Installed Apps/Patches Module    Failed\n')
    """
    Add post processing
    """
    logfile.close
    

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

#now get output path
outputpath = get_output_path()

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

#Start first part of collection
collection()









