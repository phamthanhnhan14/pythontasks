__author__ = 'nhanpt5'
import subprocess, platform, sys, time, os
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import logging
from urllib2 import urlopen

logging.basicConfig(filename='svrlog.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger('Server Info Log')

# define protocol
AD = "-"
AF_INET6 = getattr(socket, 'AF_INET6', object())
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}

def get_all_ips():
    ip_list = set()
    for itf in netifaces.interfaces():
        if itf in ['lo']: continue  # not get loopback interfaces
        for proto, addr in netifaces.ifaddresses(itf).iteritems():
            if proto == 2:  # 2 is protocol AF_INET (normal Internet addresses)
                for ip in addr:
                    ip_list.add(ip['addr'])
    return list(ip_list)

def get_primary_ip():  # connect to some where to get primary ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        result = s.getsockname()[0]
        s.close()
        return json.dumps(result)
    except Exception, ex:
        log.exception(ex)
        print ex
        try:
            s.close()
        except Exception, ex1:
            log.info(ex1)
            pass
        return None

def get_public_ip():
    try:
        my_ip = urlopen('http://ip.42.pl/raw').read()
        return json.dumps(my_ip)
    except Exception, ex:
        log.exception(ex)

def get_secondary_ip():
    ip_list = set()
    ret = subprocess.Popen("ip a | grep secondary | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
    output = ret.stdout.read()
    if len(output.rstrip()) == 0:
        return None
    else:
        for i in output.split('\n'):
            ip_list.add(i.split("/")[0])
            iplist = [ip for ip in list(ip_list) if ip]
        return json.dump(iplist)

def get_current_time():
    cmd = 'date +%Y/%m/%d-%H:%M:%S'
    try:
        ret = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.strip()) != 0:
            return output.strip()
        else:
            return None
    except Exception, ex:
        log.exception(ex)
        print ex

def get_os_info():
    def linux_distribution():
        try:
            return platform.linux_distribution()
        except:
            return 'N/A'
    result = {}
    result['Dist'] = str(platform.dist())
    result['Linux Distribution'] = linux_distribution()
    result['System'] = platform.system()
    result['Machine'] = platform.machine()
    result['Platform'] = platform.platform()
    result['Uname'] = platform.uname()
    result['Version'] = platform.version()
    #result['Mac_Ver'] = platform.mac_ver()
    return json.dumps(result, indent=2)

def get_mem_info():
    virt = psutil.virtual_memory()
    swap = psutil.swap_memory()
    result = {}
    result['Mem'] = {
        'Total': int(virt.total),
        'Used': int(virt.used),
        'Free': int(virt.free),
        'Shared': int(getattr(virt, 'shared', 0)),
        'Buffers': int(getattr(virt, 'buffers', 0)),
        'Cached': int(getattr(virt, 'cached', 0)),
        'Percent': virt.percent
    }

    result['Swap'] = {
        'Total': int(swap.total),
        'Used': int(swap.used),
        'Free': int(swap.free),
        'Percent': swap.percent
    }

    return json.dumps(result, indent=2)

def get_cpu_usage():
    percs = psutil.cpu_percent(interval=0, percpu=True)
    cpu_time = psutil.cpu_times(True)
    result = {}
    for cpu_num, perc in enumerate(percs):
        metric_name = 'cpu' + str(cpu_num)
        result[metric_name] = {}
        result[metric_name]['user'] = cpu_time[cpu_num].user
        if hasattr(cpu_time[cpu_num], 'nice'):
            result[metric_name]['nice'] = cpu_time[cpu_num].nice
        result[metric_name]['system'] = cpu_time[cpu_num].system
        result[metric_name]['idle'] = cpu_time[cpu_num].idle
        result[metric_name]['percs'] = perc
        result[metric_name]['iowait'] = cpu_time[cpu_num].iowait
        result[metric_name]['irq'] = cpu_time[cpu_num].irq
       # result[metric_name]['softirq'] = cpu_time[cpu_num].softirq
       # result[metric_name]['steal'] = cpu_time[cpu_num].steal
       # result[metric_name]['guest'] = cpu_time[cpu_num].guest
       # result[metric_name]['guest_nice'] = cpu_time[cpu_num].guest_nice
    return json.dumps(result, indent=2)

def get_disk_info():
    result = {}
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or part.fstype == '':
                continue
        usage = psutil.disk_usage(part.mountpoint)
        result[part.mountpoint]=dict(Device=part.device,Total=int(usage.total),Used=int(usage.used),Free=int(usage.free),
                    Use=int(usage.percent),Type=part.fstype,Options=part.opts)
        return json.dumps(result, indent=2)

def write_to_file_disk(info):
    filename = 'disk.txt'
    f = open(filename, 'wb')
    f.write(info)
    f.close()

def _init_disk_growup():
    '''run in first time to initial'''
    result = {}
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or part.fstype == '':
                continue
        usage = psutil.disk_usage(part.mountpoint)
        result[part.mountpoint]=dict(Device=part.device,Total=usage.total,Used=usage.used,
                                     Free=int(usage.free),Use=int(usage.percent),Type=part.fstype,Time=get_current_time())

    return write_to_file_disk(json.dumps(result, indent=2))

def read_disk_gu():
    filename = "disk.txt"
    f = open(filename)
    try:
        line = json.load(f)
    except Exception, ex:
        log.exception(ex)
        _init_disk_growup()
        sys.exit('Run command again after init data!')
    tmp = {}
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or part.fstype == '':
                continue
        usage = psutil.disk_usage(part.mountpoint)
        tmp[part.mountpoint]=dict(Device=part.device,Total=usage.total,Used=usage.used,
                                  Free=int(usage.free),Use=int(usage.percent),Type=part.fstype,Time=get_current_time())
    result = {}
    for key in line:
        k = str(key)
        if k not in tmp:
            continue
        result[k] = {}
        result[k]['delta'] = int(line[k]['Free']-tmp[k]['Free'])
        result[k]['Time'] = tmp[k]['Time']
    write_to_file_disk(json.dumps(tmp, indent=2))
    return json.dumps(result)

def write_to_file(info):
    filename = 'traffic.txt'
    f = open(filename, 'wb')
    f.write(info)
    f.close()

def _init_net_io():
    '''run in first time to initial'''
    tot_now = psutil.net_io_counters()
    pnic_now = psutil.net_io_counters(pernic=True)
    tmp = dict(Total_bytes_sent=tot_now.bytes_sent, Total_bytes_recv=tot_now.bytes_recv,
                Total_packets_sent=tot_now.packets_sent,Total_packets_recv=tot_now.packets_recv,Time=get_current_time())

    nic_names = list(pnic_now.keys())
    for name in nic_names:
        stats_now = pnic_now[name]
        tmp[name]= dict(bytes_sent=stats_now.bytes_sent,bytes_recv=stats_now.bytes_recv,
                       packets_sent=stats_now.packets_sent,packets_recv=stats_now.packets_recv)

    return write_to_file(json.dumps(tmp,indent=2))

def read_net_io_counter():
    filename = "traffic.txt"
    if not os.path.isfile(filename):
        _init_net_io()
        return "{}"
    f = open(filename)
    try:
        line = json.load(f)
    except Exception, ex:
        log.exception(ex)
        _init_net_io()
        sys.exit('Init first')
    res = {}
    tot_now = psutil.net_io_counters()
    pnic_now = psutil.net_io_counters(pernic=True)
    tmp = dict(Total_bytes_sent=tot_now.bytes_sent, Total_bytes_recv=tot_now.bytes_recv,
                Total_packets_sent=tot_now.packets_sent,Total_packets_recv=tot_now.packets_recv,Time=get_current_time())

    nic_names = list(pnic_now.keys())
    for name in nic_names:
        stats_now = pnic_now[name]
        tmp[name]= dict(bytes_sent=stats_now.bytes_sent,bytes_recv=stats_now.bytes_recv,
                       packets_sent=stats_now.packets_sent,packets_recv=stats_now.packets_recv)

        if name not in line.keys():
            print name + ' is missing, Please check!'
            continue
        key_list = ['bytes_sent','bytes_recv','packets_sent','packets_recv']
        res[name] = {}
        for key in key_list:
            res[name][key] = int(tmp[name][key] - line[name][key])
    keys_list = ['Total_bytes_sent', 'Total_bytes_recv', 'Total_packets_sent','Total_packets_recv']
    for keys in keys_list:
        res[keys] = int(tmp[keys] - line[keys])
        res['Time'] = tmp['Time']
    write_to_file(json.dumps(tmp,indent=2))
    return json.dumps(res, indent=2)

def get_hosts():
    filename = "/etc/hosts"
    if not os.path.isfile(filename):
        return "{}"
    f = open(filename)
    lines = f.readlines()
    f.close()
    line = '\n'.join(_line.strip().replace('\t', ' ') for _line in lines if not _line.startswith("#") and _line.strip())
    return line

def get_resolve():
    filename = "/etc/resolv.conf"
    if not os.path.isfile(filename):
        return "{}"
    f = open(filename)
    lines = f.readlines()
    f.close()
    line = '\n'.join(_line.strip().replace('\t', ' ') for _line in lines if not _line.startswith("#") and _line.strip())
    return line

def _get_all_user():
    import pwd
    user = [usr[0] for usr in pwd.getpwall()]
    return user

def get_server_cron_tab():
    users = _get_all_user()
    result = {}
    for usr in users:
        ret = subprocess.Popen(["crontab", "-u", usr, "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = ret.stdout.readlines()
        lines = [line.strip() for line in lines if not line.startswith("#")]
        result[usr] = [line for line in lines if line]

    return json.dumps(result, indent=2)

def get_authorize_key():
    users = _get_all_user()
    auth_keys = ""
    for usr in users:
        if str(usr) == 'root':
            filename = "/root/.ssh/authorized_keys"
        else:
            filename = "/home/"+ usr +"/.ssh/authorized_keys"
        if os.path.isfile(filename):
            f = open(filename)
            lines = f.readlines()
            f.close()
            line = ''.join(_line for _line in lines if not _line.startswith("#") and _line.strip())
            auth_keys = auth_keys + "Key for: " + str(usr) + '\n' + line
    return auth_keys

def check_os():
    if platform.dist()[0] == 'redhat' or platform.dist()[0] == 'centos':
        return 1
    elif platform.dist()[0] == 'Ubuntu' or platform.dist()[0] == 'debian':
        return -1
    return 0

def get_server_rc_local():
    if check_os() == -1: #ubuntu or debian
        filename = "/etc/rc.local"
        if not os.path.isfile(filename):
            return "{}"
        f = open(filename)
        lines = f.readlines()
        f.close()
        line = ''.join(_line for _line in lines if not (_line.startswith("#") or _line.startswith(" ")
                                                        or _line.startswith("exit")) and _line.strip())
        return line

def get_update_rc_info_debian():
    if check_os() == -1: #ubuntu or debian
        try:
            result = {}
            ret = subprocess.Popen(["service", "--status-all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = ret.stdout.read() + ret.stderr.read()
            if len(output.rstrip()) == 0:
                return None
            else:
                lines = [line.strip() for line in output.split('\n') if line]
                for line in lines:
                    result[line[7:]] = line[:6].strip()
                return json.dumps(result, indent=2)
        except Exception, ex:
            log.exception(ex)
            return None
    else:
        print 'Not run with this distro (Centos or Redhat)'
        return "{}"

def get_status_all_service_RH():
    if check_os() == 1:
        try:
            result = {}
            ret = subprocess.Popen(["service", "--status-all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = ret.stdout.read() + ret.stderr.read()
            if len(output.rstrip()) == 0:
                return None
            else:
                lines = [line.strip() for line in output.split('\n') if line]
                return json.dumps(lines, indent=2)
        except Exception, ex:
            log.exception(ex)
            return None
    else:
        print 'Not run with this distro (Ubuntu or Debian)'
        return "{}"

def chkconfig_info_RH():
    if check_os() == 1:
        try:
            result = {}
            ret = subprocess.Popen(["chkconfig", "--list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = ret.stdout.read()
            if len(output.rstrip()) == 0:
                return None
            else:
                lines = [line.strip().replace('\t', ' ') for line in output.split('\n') if line]
                for line in lines:
                    _line = line.split()
                    result[_line[0]] = _line[1:]
                return json.dumps(result, indent=2)
        except Exception, ex:
            log.exception(ex)
            return None
    else:
        print 'Not run with this distro (Ubuntu or Debian)'
        return "{}"

def get_sysctl_info_file():
    filename = "/etc/sysctl.conf"
    if not os.path.isfile(filename):
        return "{}"
    f = open(filename)
    lines = f.readlines()
    f.close()
    line = ''.join(_line for _line in lines if not (_line.startswith("#") or _line.startswith(" ")) and _line.strip())
    return line

def get_sysctl_info_all():
    try:
        result = {}
        ret = subprocess.Popen(["sysctl", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.rstrip()) == 0:
            return None
        else:
            lines = [line for line in output.split('\n') if line]
            for line in lines:
                _line = line.strip().split('=')
                result[_line[0]] = _line[1]
            return json.dumps(result, indent=2)
    except Exception, ex:
        log.exception(ex)
        return None

def _remove_comment(output):
    lines = []
    for line in output.split('\n'):
        if not ((line.startswith("|") or line.startswith("Desired")) or line.startswith("++")) and line:
            lines.append(line.strip())
    return lines

def dpkg_info():
    if check_os() == -1:
        try:
            result = {}
            ret = subprocess.Popen(["dpkg", "--list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = ret.stdout.read()
            if len(output.rstrip()) == 0:
                return None
            else:
                lines = _remove_comment(output)
                for line in lines:
                    _line = line.split(None,4)
                    result[_line[1]] = dict(version=_line[2],type=_line[3],discription=_line[4])
                return json.dumps(result, indent=2)
        except Exception, ex:
            log.exception(ex)
            return None
    else:
        print 'Not run with this distro (Centos or Redhat)'
        return "{}"

def rpm_info_RH():
    if check_os() == 1:
        try:
            ret = subprocess.Popen(["rpm", "-qa"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = ret.stdout.read()
            if len(output.rstrip()) == 0:
                return False
            else:
                lines = output.split()
                line = '\n'.join(_line for _line in lines if _line.strip())
                return line
        except Exception, ex:
            log.exception(ex)
            return None
    else:
        print 'Not run with this distro (Ubuntu or Debian)'
        return "{}"

def get_all_process():
    result = {}
    try:
        for p in psutil.process_iter():
            try:
                result[p.pid] = p.name()
            except psutil.Error:
                pass
        return json.dumps(result, indent=2)
    except Exception, ex:
        log.exception(ex)
        print ex

def get_net_stat_listen():
    proc_names = {}
    result = {}
    try:
        for p in psutil.process_iter():
            try:
                proc_names[p.pid] = p.name
            except psutil.Error:
                pass
        for c in psutil.net_connections(kind='inet'):
            laddr = "%s:%s" % (c.laddr)
            raddr = ""
            if c.raddr:
                raddr = "%s:%s" % (c.raddr)
            if c.status == 'LISTEN':
                pro = str(c.pid)
                result[pro] = {}
                result[pro]['Proto'] = proto_map[(c.family, c.type)]
                result[pro]['Local Address'] = laddr
                result[pro]['Remote Address'] = raddr or AD
                result[pro]['PID'] = c.pid or AD
                result[pro]['Program Name'] = p.name()
        return json.dumps(result, indent=2)
    except Exception, ex:
        log.exception(ex)
        print ex

def get_route_table():
    try:
        result = {}
        ret = subprocess.Popen(["route", "-n"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.rstrip()) == 0:
            return None
        else:
            lines = output.split('\n')
            line = '\n'.join(_line for _line in lines if not (_line.startswith("Dest") or _line.startswith("Kern")) and _line.strip())
            return line
    except Exception, ex:
        log.exception(ex)
        return None

def get_iptables_info():
    if check_os() == 1:
        filename = "/etc/sysconfig/iptables"
    elif check_os() == -1:
        #another file for Ubuntu
        filename = "/etc/sysconfig/iptables"
    if not os.path.isfile(filename):
        try:
            result = {}
            ret = subprocess.Popen(["iptables", "-S"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = ret.stdout.read()
            if len(output.rstrip()) == 0:
                return False
            else:
                lines = output.split('\n')
                line = '\n'.join(_line for _line in lines)
                return line
        except Exception, ex:
            log.exception(ex)
            return None
    f = open(filename)
    lines = f.readlines()
    f.close()
    line = ""
    if lines:
        for _line in lines:
            line = line + _line
    return line

def check_mk():
    filename = "/etc/check_mk/mrpe.cfg"
    if not os.path.isfile(filename):
        return "{}"
    f = open(filename)
    lines = f.readlines()
    f.close()
    line = ''.join(_line for _line in lines if not (_line.startswith("#") or _line.startswith(" ")))
    return line

def main(funcs):
    for func in funcs:
        if sys.argv[1] == func:
            print eval(func + '()')
        else:
            pass

if __name__ == '__main__':
     # Check version & import lib,if not compatible, exit """
    if sys.version_info >= (2,4) and sys.version_info <= (2,5):
        sys.path.append('psutil24')
        sys.path.append('json24')
    elif sys.version_info >= (2,6) and sys.version_info <= (2,7):
        sys.path.append('psutil26')
    elif sys.version_info >= (2,7) and sys.version_info <= (2,8):
        sys.path.append('psutil27')
    else:
        sys.exit('[Error] Only run with python 2.4 2.6 2.7 - Your version: ' + sys.version_info + '.')
    try:
        if sys.version_info >= (2,4) and sys.version_info <= (2,5):
            import simplejson as json
        else:
            import json
        import psutil
        sys.path.append('netifaces')
        sys.path.append('argparse')
        import netifaces
        import argparse
    except Exception, ex:
        print ex

    funcs = ['get_all_ips', 'get_primary_ip', 'get_public_ip', 'get_secondary_ip', 'get_current_time', 'get_os_info', 'get_mem_info',
         'get_cpu_usage', 'get_disk_info', 'read_disk_gu', 'read_net_io_counter', 'get_hosts', 'get_resolve', 'get_server_cron_tab',
         'get_authorize_key', 'get_server_rc_local', 'get_update_rc_info_debian', 'get_status_all_service_RH', 'chkconfig_info_RH',
         'get_sysctl_info_file', 'get_sysctl_info_all', 'dpkg_info', 'rpm_info_RH', 'get_all_process', 'get_net_stat_listen',
         'get_route_table', 'get_iptables_info', 'check_mk']

    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description='Server_infos Tool usages')
        parser.add_argument('command', help='command must be:' + str(funcs))
        args = parser.parse_args()
        main(funcs)
    else:
         json_str = {}
         result = []
         json_str['ip'] = get_primary_ip()
         json_str['mem'] = get_mem_info()
         json_str['cpu'] = get_cpu_usage()
         json_str['disk_gu'] = json.dumps(read_disk_gu())
         json_str['net_io'] = json.dumps(read_net_io_counter())
         json_str['hosts'] = json.dumps(get_hosts())
         json_str['resolve'] = json.dumps(get_resolve())
         json_str['auth_key'] = json.dumps(get_authorize_key())
         json_str['ip_table'] = json.dumps(get_iptables_info())
         json_str['process'] = json.dumps(get_all_process())
         json_str['net_stat'] = json.dumps(get_net_stat_listen())
         json_str['check_mk'] = json.dumps(check_mk())
         result.append(json_str)
         print result
