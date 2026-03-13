#!/usr/bin/env python3

from bcc import BPF
import ctypes as ct
import netaddr
import socket


class DNSQuery(ct.Structure):
    _fields_ = [("qname", ct.c_uint8 * 255), ("qtype", ct.c_uint16)]


class PacketInfo(ct.Structure):
    _fields_ = [("ipv4_src", ct.c_uint32), ("ipv6_src", ct.c_uint8 * 16), ("query", DNSQuery)]


def decode_qname(qname_array):
    qname = ""
    length = 0
    for qname_byte in qname_array:
        if length == 0:
            if int(qname_byte) == 0:
                break
            else:
                length = int(qname_byte)
                if qname != "":
                    qname += "."
        else:
            qname += chr(int(qname_byte))
            length -= 1
    return qname


def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(PacketInfo)).contents
    if event.ipv4_src != 0:
        src_ip = str(netaddr.IPAddress(socket.htonl(event.ipv4_src)))
    else:
        src_ip = str(netaddr.IPAddress(sum([byte << 8 * (15 - index) for index, byte in enumerate(event.ipv6_src)]), 6))
    qtype = INV_QTYPES[socket.htons(event.query.qtype)]
    qname = decode_qname(event.query.qname)
    print(f"{src_ip}|{qtype}|{qname}")


QTYPES = {
    "LOC": 29,
    "*": 255,
    "IXFR": 251,
    "UINFO": 100,
    "NSEC3": 50,
    "AAAA": 28,
    "CNAME": 5,
    "MINFO": 14,
    "EID": 31,
    "GPOS": 27,
    "X25": 19,
    "HINFO": 13,
    "CAA": 257,
    "NULL": 10,
    "DNSKEY": 48,
    "DS": 43,
    "ISDN": 20,
    "SOA": 6,
    "RP": 17,
    "UID": 101,
    "TALINK": 58,
    "TKEY": 249,
    "PX": 26,
    "NSAP-PTR": 23,
    "TXT": 16,
    "IPSECKEY": 45,
    "DNAME": 39,
    "MAILA": 254,
    "AFSDB": 18,
    "SSHFP": 44,
    "NS": 2,
    "PTR": 12,
    "SPF": 99,
    "TA": 32768,
    "A": 1,
    "NXT": 30,
    "AXFR": 252,
    "RKEY": 57,
    "KEY": 25,
    "NIMLOC": 32,
    "A6": 38,
    "TLSA": 52,
    "MG": 8,
    "HIP": 55,
    "NSEC": 47,
    "GID": 102,
    "SRV": 33,
    "DLV": 32769,
    "NSEC3PARAM": 51,
    "UNSPEC": 103,
    "TSIG": 250,
    "ATMA": 34,
    "RRSIG": 46,
    "OPT": 41,
    "MD": 3,
    "NAPTR": 35,
    "MF": 4,
    "MB": 7,
    "DHCID": 49,
    "MX": 15,
    "MAILB": 253,
    "CERT": 37,
    "NINFO": 56,
    "APL": 42,
    "MR": 9,
    "SIG": 24,
    "WKS": 11,
    "KX": 36,
    "NSAP": 22,
    "RT": 21,
    "SINK": 40,
}
INV_QTYPES = {v: k for k, v in QTYPES.items()}

# Main
xdp = BPF(src_file="xdp-logging-middleware.ebpf.src")

fn_drop = xdp.load_func("log_drop", BPF.XDP)
fn_tc = xdp.load_func("log_tc", BPF.XDP)

progs = xdp.get_table("progsarray")
events = xdp.get_table("events")

progs[ct.c_int(0)] = ct.c_int(fn_drop.fd)
progs[ct.c_int(1)] = ct.c_int(fn_tc.fd)

events.open_perf_buffer(print_event)

print("Filter is ready")
while True:
    try:
        xdp.perf_buffer_poll()
    except KeyboardInterrupt:
        break

if progs[ct.c_int(0)]:
    del progs[ct.c_int(0)]
if progs[ct.c_int(1)]:
    del progs[ct.c_int(1)]
