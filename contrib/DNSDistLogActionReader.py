#!/usr/bin/env python

import socket
import struct
import sys

def readRecord(fp, withTimestamp):

    if withTimestamp:
        data = fp.read(12)
        if not data:
            return False
        tv_sec, tv_nsec = struct.unpack("QI", data)

    data = fp.read(2)
    if not data:
        return False

    queryID = struct.unpack("!H", data)[0]
    qname = ''
    while True:
        labelLen = struct.unpack("B", fp.read(1))[0]
        if labelLen == 0:
            break
        label = fp.read(labelLen)
        if qname != '':
            qname = qname + '.'
        qname = qname + label.decode()

    qtype = struct.unpack("H", fp.read(2))[0]
    addrType = struct.unpack("H", fp.read(2))[0]
    addr = None
    if addrType == socket.AF_INET:
        addr = socket.inet_ntop(socket.AF_INET, fp.read(4))
    elif addrType == socket.AF_INET6:
        addr = socket.inet_ntop(socket.AF_INET6, fp.read(16))
    else:
        print('Unsupported address type %d, skipping this record' % (int(addrType)))
        return False
    port = struct.unpack("!H", fp.read(2))[0]

    if withTimestamp:
        print('[%u.%u] Packet from %s:%d for %s %s with id %d' % (tv_sec, tv_nsec, addr, port, qname, qtype, queryID))
    else:
        print('Packet from %s:%d for %s %s with id %d' % (addr, port, qname, qtype, queryID))

    return True

def readLogFile(filename, withTimestamps):
    with open(filename, mode='rb') as fp:
        while True:
            if not readRecord(fp, withTimestamps):
                break

if __name__ == "__main__":
    if len(sys.argv) != 2 and (len(sys.argv) != 3 or sys.argv[2] != 'with-timestamps'):
        sys.exit('Usage: %s <path to log file> [with-timestamps]' % (sys.argv[0]))

    readLogFile(sys.argv[1], len(sys.argv) == 3)

    sys.exit(0)
