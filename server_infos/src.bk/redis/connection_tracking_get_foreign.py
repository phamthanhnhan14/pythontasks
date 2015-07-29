# To change this license header, choose License Headers in Project Properties.
# To change this template file, choose Tools | Templates
# and open the template in the editor.

__author__="locth2"
__date__ ="$Oct 29, 2014 10:43:14 AM$"

#!/usr/bin/python
#locth2@vng.com.vn

import pwd, os, re, glob, subprocess, string, sys, socket, os, time, datetime

def _get_current_time():
    try:
        ret = subprocess.Popen("date",shell=True, stdout=subprocess.PIPE) # run bash date
        output = ret.stdout.read()
        if len(output.strip()) != 0:
            return output.strip()
        else:
            return None
    except Exception, ex:
        print ex
    return None

def _get_primary_ip(): # connect to some where to get primary ip 
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        s.connect(('10.30.8.1',80))
        result = s.getsockname()[0]
        s.close()
        return result
    except Exception, ex:
        print ex
        try:
            s.close()
        except Exception:
            pass
        return None
    
def _get_all_ip():
    cmd1 = "ifconfig | grep 'inet' | grep -v 'inet6'| grep -v '127.0.0.1' | tr  ':' ' ' | tr -d 'addr' | awk '{print $2}'"
    ret = subprocess.Popen(cmd1,shell=True, stdout=subprocess.PIPE)
    output = ret.stdout.read().replace('\n',' ')
    array1 = output.split()
    cmd2 = "ip a | grep -w 'inet' | awk -F 'brd' '{print $1}' | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'| grep -v '127.0.0.1'"
    ret = subprocess.Popen(cmd2,shell=True, stdout=subprocess.PIPE)
    output = ret.stdout.read().replace('\n',' ')
    array2 = output.split()
    listIp = list(set(array1 + array2))
    if not listIp:
        return None
    else:
#        return ', '.join(listIp)
        return listIp
    
def _redis_import_mapping():
    json_mapping={}
    json_mapping['time'] = _get_current_time()
    json_mapping['hostname'] = HOSTNAME
    for ip in _get_all_ip():
        r.set("mapping_"+ip,HOSTNAME)
        
def _redis_import_connection(data):
    r.set("server_"+HOSTNAME, data)
    return

if __name__ == '__main__':
    FILE = ['/proc/net/tcp','/proc/net/tcp6']
    REDIS_HOST = '10.30.8.69'
    REDIS_PORT = 6379
    AGENT_VERSION = '14.11.01'
    HOSTNAME = os.uname()[1]
    os.environ['PATH'] = "/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin"
    
    # Check version & import psutil , if not compatible , exit """
    """ check python server and import psutil """
    if sys.version_info >= (2,4) and sys.version_info <= (2,5):
        sys.path.append('psutil24')
        sys.path.append('json24')
    elif sys.version_info >= (2,6) and sys.version_info <= (2,7):
        sys.path.append('psutil26')
    elif sys.version_info >= (2,7) and sys.version_info <= (2,8):
        sys.path.append('psutil27')
    else:
        print '[Error] Only run with python 2.4 2.6 2.7 - Your version: ', sys.version_info ,"."
        sys.exit(2)
        
    try:
        if sys.version_info >= (2,4) and sys.version_info <= (2,5):
            import simplejson as json
        else:
            import json
        import psutil
    except Exception:
        print "[Error] Please cd to project directory :). If still error please contact locth2@vng.com.vn."
        sys.exit(2)
    
    # Parse connection , create json_string
    result = []
    json_string={}
    listen_array = []
    established_aray = []
    mapping = {}
    connections = psutil.net_connections()
    for conn in connections:
        if conn[5] == 'LISTEN':
            listen_array.append(conn[3][1])
            mapping[conn[3][1]] = str(conn[6])
    print listen_array


    for listen in listen_array:
        for conn in connections:
            if conn[5] == 'ESTABLISHED' and conn[3][1] == listen:
                print mapping[listen], "\t" ,listen,"\t",conn[4]



        #if conn[5] == 'ESTABLISHED':
        #    tmp ['laddr'] = conn[3]
        #    tmp ['raddr'] = conn[4]
        #    pid = str(conn[6])
        #    tmp ['pid'] = pid
        #    try:
        #        tmp ['exe'] = os.readlink('/proc/'+pid+'/exe')
        #    except Exception:
        #        tmp ['exe'] = None
        #    try:
        #        tmp ['pwdx'] = os.readlink('/proc/'+pid+'/cwd')
        #    except Exception:
        #        tmp ['pwdx'] = None
        #    try:
        #        tmp ['cmd'] = open("/proc/"+pid+"/cmdline").read().replace('\x00', ' ').rstrip()
        #    except Exception:
        #        tmp ['cmd'] = None
        #    established_aray.append(tmp)
    

