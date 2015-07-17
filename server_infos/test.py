__author__ = 'nhanpt5'
import glob, os, re, pwd

FILE = ['/proc/net/tcp','/proc/net/tcp6']

def _load_listen_state(file):
    ''' Read the table of tcp connections & remove header  '''
    f = open(file, 'r')
    content = f.readlines()
    content.pop(0)
    conn_listen = []
    for line in content:
        line_array = _remove_empty(line.split(' '))
        if re.search("0A",line_array[3]):
                conn_listen.append(line)
    f.close()
    return conn_listen
def _hex2dec(s):
    return str(int(s,16))

def _ip(s):
    ip = [(_hex2dec(s[6:8])),(_hex2dec(s[4:6])),(_hex2dec(s[2:4])),(_hex2dec(s[0:2]))]
    return '.'.join(ip)

def _remove_empty(array):
    return [x for x in array if x !='']

def _convert_ip_port(array):
    host,port = array.split(':')
    return _ip(host),_hex2dec(port)

def _get_pid_of_inode(inode):
    '''
    To retrieve the process pid, check every running process and look for one using
    the given inode.
    '''
    for item in glob.glob('/proc/[0-9]*/fd/[0-9]*'):
        try:
            if re.search(inode,os.readlink(item)):
                return item.split('/')[2]
        except:
            pass
    return None


def netstat(file):
    '''
    Function to return a list with status of tcp connections at linux systems
    To get pid of all network process running on system, you must run this script
    as superuser
    '''
    content =_load_listen_state(file)
    result = []
    for line in content:
        line_array = _remove_empty(line.split(' '))
        l_host,l_port = _convert_ip_port(line_array[1])
        uid = pwd.getpwuid(int(line_array[7]))[0]
        inode = line_array[9]
        pid = _get_pid_of_inode(inode)
        if pid is None:
            nline = uid, l_host+':'+l_port, '-', '-', '-', '-'
            result.append(nline)
        else:
            try:
                exe = os.readlink('/proc/'+pid+'/exe')
            except OSError:
                exe = None
            try:
                cwd = os.readlink('/proc/'+pid+'/cwd')
            except OSError:
                cwd = None
            try:
                cmdline = open("/proc/"+pid+"/cmdline").read().replace('\x00', ' ').rstrip()
            except OSError:
                cmdline = None
            nline = uid, l_host+':'+l_port, pid, re.sub('[(),]','',exe), re.sub('[(),]','',cwd), re.sub('[(),]','',cmdline)
            result.append(nline)
    return result
if __name__ == '__main__':
    for file in FILE:
        if os.path.isfile(file):
            for conn in netstat(file):
                print conn
