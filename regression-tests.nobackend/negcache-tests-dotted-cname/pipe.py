#!/usr/bin/env python

import sys

line = sys.stdin.readline()
# TOLO
print('OK\tTest backend firing up')

while True:
    line = sys.stdin.readline()
    items = line.split('\t')
    sys.stderr.write(line)
    if len(items) < 6:
        print('LOG\tGot an unparseable line')
        print('LOG\t%s' % line)
        print('END')
        continue

    what, qname, qclass, qtype, id, ip = items

    if qtype in ['SOA', 'ANY'] and qname == 'example2.com':
        print('DATA\t%s\t%s\tSOA\t300\t-1\tns1.example.com ahu.example.com 2008080300 1800 3600 604800 3600' % (qname, qclass))

    if qtype in ['NS', 'ANY'] and qname == 'example2.com':
        print('DATA\t%s\t%s\tNS\t3600\t-1\tns1.example.com' % (qname, qclass))
        print('DATA\t%s\t%s\tNS\t3600\t-1\tns2.example.com' % (qname, qclass))

    if qtype in ['A', 'ANY'] and qname.endswith('example2.com'):
        # We were asked a specific record
        print('DATA\t%s\t%s\tCNAME\t3600\t-1\twww.example.com.' % (qname, qclass))

    print('END')
