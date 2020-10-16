#!/usr/bin/env python3
import socket
import sys
import threading
import time

from atomicwrites import atomic_write

class LookupThread(threading.Thread):
    def run(self):
        while True:
            ips = dict()
            for target in self.targets:
                addrs = ips.get(target, [])

                try:
                    res = socket.getaddrinfo(target, 0, proto=socket.IPPROTO_UDP)
                    addrs = [item[4][0] for item in res]
                except socket.gaierror as e:
                    if e.errno in (socket.EAI_NODATA, socket.EAI_NONAME):
                        addrs = []

                ips[target] = addrs

            with atomic_write(self.fname, overwrite=True) as out:
                out.write('return {\n')
                for name,addrs in ips.items():
                    out.write('  ["{}"]='.format(name) + '{\n')
                    for addr in addrs:
                        out.write('    "{}",\n'.format(addr))
                    out.write('  },\n')
                out.write('}\n')

            time.sleep(1)

if __name__ == '__main__':
    lt = LookupThread()
    lt.setDaemon(True)
    lt.targets = []
    lt.fname = '/tmp/dnsdist-resolver.out'
    lt.start()
    for line in sys.stdin:
        print(line.split())
        lt.targets=line.split()
