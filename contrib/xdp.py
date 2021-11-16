#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct
import netaddr
import socket

# Constants
QTYPES = {'LOC': 29, '*': 255, 'IXFR': 251, 'UINFO': 100, 'NSEC3': 50, 'AAAA': 28, 'CNAME': 5, 'MINFO': 14, 'EID': 31, 'GPOS': 27, 'X25': 19, 'HINFO': 13, 'CAA': 257, 'NULL': 10, 'DNSKEY': 48, 'DS': 43, 'ISDN': 20, 'SOA': 6, 'RP': 17, 'UID': 101, 'TALINK': 58, 'TKEY': 249, 'PX': 26, 'NSAP-PTR': 23, 'TXT': 16, 'IPSECKEY': 45, 'DNAME': 39, 'MAILA': 254, 'AFSDB': 18, 'SSHFP': 44, 'NS': 2, 'PTR': 12, 'SPF': 99, 'TA': 32768, 'A': 1, 'NXT': 30, 'AXFR': 252, 'RKEY': 57, 'KEY': 25, 'NIMLOC': 32, 'A6': 38, 'TLSA': 52, 'MG': 8, 'HIP': 55, 'NSEC': 47, 'GID': 102, 'SRV': 33, 'DLV': 32769, 'NSEC3PARAM': 51, 'UNSPEC': 103, 'TSIG': 250, 'ATMA': 34, 'RRSIG': 46, 'OPT': 41, 'MD': 3, 'NAPTR': 35, 'MF': 4, 'MB': 7, 'DHCID': 49, 'MX': 15, 'MAILB': 253, 'CERT': 37, 'NINFO': 56, 'APL': 42, 'MR': 9, 'SIG': 24, 'WKS': 11, 'KX': 36, 'NSAP': 22, 'RT': 21, 'SINK': 40}
INV_QTYPES = {v: k for k, v in QTYPES.items()}
ACTIONS = {1 : 'DROP', 2 : 'TC'}

DROP_ACTION = 1
TC_ACTION = 2

# The interface on wich the filter will be attached 
DEV = "eth0"

# The list of blocked IPv4, IPv6 and QNames
# IP format : (IPAddress, Action)
# QName format : (QName, QType, Action)
blocked_ipv4 = [("192.0.2.1", TC_ACTION)]
blocked_ipv6 = [("2001:db8::1", TC_ACTION)]
blocked_qnames = [("localhost", "A", DROP_ACTION), ("test.com", "*", TC_ACTION)]

# Main
xdp = BPF(src_file="xdp-filter.ebpf.src")

fn = xdp.load_func("xdp_dns_filter", BPF.XDP)
xdp.attach_xdp(DEV, fn, 0)

v4filter = xdp.get_table("v4filter")
v6filter = xdp.get_table("v6filter")
qnamefilter = xdp.get_table("qnamefilter")

for ip in blocked_ipv4:
  print(f"Blocking {ip}")
  key = v4filter.Key(int(netaddr.IPAddress(ip[0]).value))
  leaf = v4filter.Leaf()
  leaf.counter = 0
  leaf.action = ip[1]
  v4filter[key] = leaf

for ip in blocked_ipv6:
  print(f"Blocking {ip}")
  ipv6_int = int(netaddr.IPAddress(ip[0]).value)
  ipv6_bytes = bytearray([(ipv6_int & (255 << 8*(15-i))) >> (8*(15-i)) for i in range(16)])
  key = (ct.c_uint8 * 16).from_buffer(ipv6_bytes)
  leaf = v6filter.Leaf()
  leaf.counter = 0
  leaf.action = ip[1]
  v6filter[key] = leaf

for qname in blocked_qnames:
  print(f"Blocking {qname}")
  key = qnamefilter.Key()
  qn = bytearray()
  for sub in qname[0].split('.'):
    qn.append(len(sub))
    for ch in sub:
      qn.append(ord(ch))
  qn.extend((0,) * (255 - len(qn)))
  key.qname = (ct.c_ubyte * 255).from_buffer(qn)
  key.qtype = ct.c_uint16(QTYPES[qname[1]])
  leaf = qnamefilter.Leaf()
  leaf.counter = 0
  leaf.action = qname[2]
  qnamefilter[key] = leaf

print("Filter is ready")
try:
  xdp.trace_print() 
except KeyboardInterrupt:
  pass

for item in v4filter.items():
  print(f"{str(netaddr.IPAddress(item[0].value))} ({ACTIONS[item[1].action]}): {item[1].counter}")
for item in v6filter.items():
  print(f"{str(socket.inet_ntop(socket.AF_INET6, item[0]))} ({ACTIONS[item[1].action]}): {item[1].counter}")
for item in qnamefilter.items():
  print(f"{''.join(map(chr, item[0].qname)).strip()}/{INV_QTYPES[item[0].qtype]} ({ACTIONS[item[1].action]}): {item[1].counter}")

xdp.remove_xdp(DEV, 0)
