__author__ = 'nhanpt5'
import subprocess, platform, sys, time, os
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import logging


logging.basicConfig(filename='example.log', level=logging.DEBUG,
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


def bytes2human(n):
    # http://code.activestate.com/recipes/578019
    # >>> bytes2human(10000)
    # '9.8K'
    # >>> bytes2human(100001221)
    # '95.4M'
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.1f%s' % (value, s)
    return "%sB" % n


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
        return result
    except Exception as ex:
        log.exception(ex)
        print ex
        try:
            s.close()
        except Exception as ex1:
            log.info(ex1)
            pass
        return None


def get_secondary_ip():
    ip_list = set()
    ret = subprocess.Popen("ip a | grep secondary | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
    output = ret.stdout.read()
    if len(output.rstrip()) == 0:
        return False
    else:
        for i in output.split('\n'):
            ip_list.add(i.split("/")[0])
            iplist = [ip for ip in list(ip_list) if ip]
        return iplist


def get_current_time():
    try:
        ret = subprocess.Popen("date", shell=True, stdout=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.strip()) != 0:
            return output.strip()
        else:
            return None
    except Exception, ex:
        log.exception(ex)
        print ex
    return None


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
        'Total': bytes2human(virt.total),
        'Used': bytes2human(virt.used),
        'Free': bytes2human(virt.free),
        'Shared': bytes2human(getattr(virt, 'shared', 0)),
        'Buffers': bytes2human(getattr(virt, 'buffers', 0)),
        'Cached': bytes2human(getattr(virt, 'cached', 0)),
        'Percent': virt.percent
    }

    result['Swap'] = {
        'Total': bytes2human(swap.total),
        'Used': bytes2human(swap.used),
        'Free': bytes2human(swap.free),
        'Percent': swap.percent
    }

    return json.dumps(result, indent=2)


def get_pid_process():
    listen_array = []
    established_array = []

    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name'])
            for conn in proc.get_connections():
                if conn.status == 'LISTEN':
                    port = conn.local_address
                    pinfo['port'] = port
                    pinfo['status'] = conn.status
                    listen_array.append(pinfo)
                if conn.status == 'ESTABLISHED':
                    port = conn.local_address
                    pinfo['port'] = port
                    established_array.append(pinfo)
        except psutil.NoSuchProcess:
            pass
    return json.dumps(listen_array, indent=2)


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
        result[metric_name]['softirq'] = cpu_time[cpu_num].softirq
        result[metric_name]['steal'] = cpu_time[cpu_num].steal
        result[metric_name]['guest'] = cpu_time[cpu_num].guest
        result[metric_name]['guest_nice'] = cpu_time[cpu_num].guest_nice
    return json.dumps(result, indent=2)


def get_disk_info():
    result = {}
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or part.fstype == '':
                continue
        usage = psutil.disk_usage(part.mountpoint)
        result[part.mountpoint]=dict(Device=part.device,Total=bytes2human(usage.total),Used=bytes2human(usage.used),Free=bytes2human(usage.free),
                    Use=int(usage.percent),Type=part.fstype,Options=part.opts)
        return json.dumps(result, indent=2)


def get_net_stat():
    proc_names = {}
    result = {}
    for p in psutil.process_iter():
        try:
            proc_names[p.pid] = p.name()
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
            result[pro]['Program Name'] = proc_names.get(c.pid, '?')[:15]
    return json.dumps(result, indent=2)


def get_server_rc_local():
    filename = "/etc/rc.local"
    sts = ""
    if not os.path.isfile(filename):
        return "Not found"
    f = open(filename)
    content = f.readline()
    f.close()
    if content:
        for line in content:
            sts = sts + line
        return sts
    else:
        return "Not note"


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


def get_hosts():
    filename = "/etc/hosts"
    if not os.path.isfile(filename):
        return "{}"
    f = open(filename)
    lines = f.readlines()
    f.close()
    lines = [line.strip().replace('\t', ' ') for line in lines if not line.startswith("#")]
    return json.dumps(lines, indent=2)


def get_update_rc_info():
    try:
        result = {}
        ret = subprocess.Popen(["service", "--status-all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read() + ret.stderr.read()
        if len(output.rstrip()) == 0:
            return False
        else:
            lines = [line.strip() for line in output.split('\n') if line]
            for line in lines:
                result[line[7:]] = line[:6].strip()
            return json.dumps(result, indent=2)
    except Exception as ex:
        log.exception(ex)
        return None


def chkconfig_info():
    try:
        result = {}
        ret = subprocess.Popen(["chkconfig", "--list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.rstrip()) == 0:
            return False
        else:
            lines = [line.strip().replace('\t', ' ') for line in output.split('\n') if line]
            for line in lines:
                line_ = line.split()
                result[line_[0]] = line_[1:]
            return json.dumps(result, indent=2)
    except Exception as ex:
        log.exception(ex)
        return None


def _remove_comment(output):
    lines = []
    for line in output.split('\n'):
        if not (line.startswith("Dest") or line.startswith("Kern")) and line:
            lines.append(line.strip())
    return lines


def get_route_table():
    try:
        result = {}
        ret = subprocess.Popen(["route", "-n"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.rstrip()) == 0:
            return False
        else:
            lines = _remove_comment(output)
            for line in lines:
                line_ = line.split()
                result[line_[0]] = dict(Destination=line_[0], Gateway=line_[1], Genmask=line_[2], Flags=line_[3],
                                        Metric=line_[4], Ref=line_[5], Use=line_[6], Iface=line_[7])
            return json.dumps(result, indent=2)
    except Exception as ex:
        log.exception(ex)
        return None


def test():
    filename = "input.txt"
    f = open(filename)
    result = {}
    lines = f.readlines()
    f.close()
    lines = [line.strip().split() for line in lines if line]
    for line in lines:
        result[line[0]] = line[1:8]
    return json.dumps(result, indent=2)


def get_resolv():
    filename = "/etc/resolv.conf"
    if not os.path.isfile(filename):
        return "{}"
    f = open(filename)
    lines = f.readlines()
    f.close()
    lines = [line.strip().replace('\t', ' ') for line in lines if not line.startswith("#")]
    return json.dumps(lines, indent=2)


def sysctl_info():
    try:
        result = {}
        ret = subprocess.Popen(["sysctl", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.rstrip()) == 0:
            return False
        else:
            lines = [line for line in output.split('\n') if line]
            for line in lines:
                _line = line.strip().split('=')
                result[_line[0]] = _line[1]
            return json.dumps(result, indent=2)
    except Exception as ex:
        log.exception(ex)
        return None


def write_to_file(info):
    filename = 'temp3.txt'
    f = open(filename, 'wb')
    f.write(info)
    f.close()


def init_traffic():
    '''run in first time to initial'''
    tot_now = psutil.net_io_counters()
    pnic_now = psutil.net_io_counters(pernic=True)
    tmp = dict(Total_bytes_sent=tot_now.bytes_sent, Total_bytes_recv=tot_now.bytes_recv,
                Total_packets_sent=tot_now.packets_sent,Total_packets_recv=tot_now.packets_recv)

    nic_names = list(pnic_now.keys())
    for name in nic_names:
        stats_now = pnic_now[name]
        tmp[name]= dict(bytes_sent=stats_now.bytes_sent,bytes_recv=stats_now.bytes_recv,
                       packets_sent=stats_now.packets_sent,packets_recv=stats_now.packets_recv)

    return write_to_file(json.dumps(tmp))

def read_traffic_info():
    filename = "temp3.txt"
    f = open(filename)
    try:
        line = json.load(f)
    except Exception as ex:
        log.exception(ex)
        print 'Init first'
        init_traffic()
    res = {}
    tot_now = psutil.net_io_counters()
    pnic_now = psutil.net_io_counters(pernic=True)
    tmp = dict(Total_bytes_sent=tot_now.bytes_sent, Total_bytes_recv=tot_now.bytes_recv,
                Total_packets_sent=tot_now.packets_sent,Total_packets_recv=tot_now.packets_recv)

    nic_names = list(pnic_now.keys())
    for name in nic_names:
        stats_now = pnic_now[name]
        tmp[name]= dict(bytes_sent=stats_now.bytes_sent,bytes_recv=stats_now.bytes_recv,
                       packets_sent=stats_now.packets_sent,packets_recv=stats_now.packets_recv)

        if name not in line.keys():
            print name + 'is missing'
            continue
        key_list = ['bytes_sent','bytes_recv','packets_sent','packets_recv']
        res[name] = {}
        for key in key_list:
            res[name][key] = bytes2human(tmp[name][key] - line[name][key])
    keys_list = ['Total_bytes_sent', 'Total_bytes_recv', 'Total_packets_sent','Total_packets_recv']
    for keys in keys_list:
        res[keys] = bytes2human(tmp[keys] - line[keys])
    write_to_file(json.dumps(tmp))
    return json.dumps(res, indent=2)


def _remove_comment_2(output):
    lines = []
    for line in output.split('\n'):
        if not ((line.startswith("|") or line.startswith("Desired")) or line.startswith("++")) and line:
            lines.append(line.strip())
    return lines


def dpkg_info():
    try:
        result = {}
        ret = subprocess.Popen(["dpkg", "--list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.rstrip()) == 0:
            return False
        else:
            lines = _remove_comment_2(output)
            for line in lines:
                line_ = line.split(None,4)
                result[line_[1]] = dict(version=line_[2],type=line_[3],discription=line_[4])
            return json.dumps(result, indent=2)
    except Exception as ex:
        log.exception(ex)
        return False


def rpm_info():
    try:
        result = {}
        ret = subprocess.Popen(["rpm", "-qa"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ret.stdout.read()
        if len(output.rstrip()) == 0:
            return False
        else:
            for line in output:
                line_ = line.split()
                result[line] = line_
            return json.dumps(result, indent=2)
    except Exception as ex:
        log.exception(ex)
        return None

def write_to_file_disk(info):
    filename = 'disk.txt'
    f = open(filename, 'wb')
    f.write(info)
    f.close()

def disk_growup():
    result = {}
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or part.fstype == '':
                continue
        usage = psutil.disk_usage(part.mountpoint)
        result[part.mountpoint]=dict(Device=part.device,Total=usage.total,Used=usage.used,
                                     Free=int(usage.free),Use=int(usage.percent),Type=part.fstype)

    return write_to_file_disk(json.dumps(result, indent=2))

def read_disk_gu():
    filename = "disk.txt"
    f = open(filename)
    try:
        line = json.load(f)
    except Exception as ex:
        log.exception(ex)
    tmp = {}
    for part in psutil.disk_partitions(all=False):
        if os.name == 'nt':
            if 'cdrom' in part.opts or part.fstype == '':
                continue
        usage = psutil.disk_usage(part.mountpoint)
        tmp[part.mountpoint]=dict(Device=part.device,Total=usage.total,Used=usage.used,
                                  Free=int(usage.free),Use=int(usage.percent),Type=part.fstype)
    res = {}
    for key in line:
        k = str(key)
        if k not in tmp:
            continue
        res[k]={}
        res[k]['delta'] = bytes2human(line[k]['Free']-tmp[k]['Free'])

    return res


if __name__ == '__main__':
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
        print '[Error] Only run with python 2.4 2.6 2.7 - Your version: ', sys.version_info,"."
        sys.exit(2)
    try:
        if sys.version_info >= (2,4) and sys.version_info <= (2,5):
            import simplejson as json
        else:
            import json
        import psutil
        sys.path.append('netifaces')
        import netifaces
    except Exception:
        print "[Error] Please cd to project directory :). If still error please contact nhanpt5@vng.com.vn."
        sys.exit(2)

    print 'Server ' + get_primary_ip() + ' all informations at ' + get_current_time()
    print 'IP list', get_all_ips()
    print get_os_info()
    print get_pid_process()
    print 'Memory Infos ' + get_mem_info()
    print 'CPU Infos' + get_cpu_usage()
    print get_secondary_ip()
    print get_net_stat()
    print get_disk_info()
    print get_server_rc_local()
    print get_server_cron_tab()
    print get_hosts()
    print chkconfig_info()
    print get_update_rc_info()
    print get_resolv()
    print sysctl_info()
    print get_route_table()

    print dpkg_info()
    print read_traffic_info()
    print read_disk_gu()
