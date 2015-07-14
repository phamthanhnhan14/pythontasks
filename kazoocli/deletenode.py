import sys
import time
import datetime
try:
    sys.path.append('kazoolib')
    from kazoo.client import KazooClient
except Exception:
        print "[Error] Please cd to project directory :). If still error please contact nhanpt5@vng.com.vn."
        sys.exit(2)
#server = '10.30.14.50:2183'
#node = '/dbg/trans/atm/'
node = '/nhanpt5/'
server = 'localhost:2181'

def check(a):
    value = time.strptime(a,'%Y%m%d%H%M%S%f')
    now = time.localtime()
    delta = time.mktime(now) - time.mktime(value)
    # kiem tra node da ton tai hon 7 ngay
    res = datetime.timedelta(seconds=delta).days
    if res >= 7:
	return  True

try:
    zk = KazooClient(hosts=server)
    zk.start()
    for child in zk.get_children(node):
	if check(child):
	    print child
	    #zk.delete(node + child)
    zk.stop()
except Exception as ex:
    print ex
    
