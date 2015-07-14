import sys
sys.path.append('kazoolib')
from kazoo.client import KazooClient
server = '10.30.14.50:2183'
node = '/dbg/trans/atm/'
try:
    zk = KazooClient(hosts=server)
    zk.start()
    for child in zk.get_children(node):
        print child
	#zk.delete(node + child)
    zk.stop()
except Exception as ex:
    print ex
    
