#!/usr/bin/env python
import copy
import dns
import socket
import struct
import sys

from proxyprotocol import ProxyProtocol

def ProxyProtocolUDPResponder(port, fromQueue, toQueue):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except socket.error as e:
        print("Error binding in the Proxy Protocol UDP responder: %s" % str(e))
        sys.exit(1)

    while True:
        data, addr = sock.recvfrom(4096)

        proxy = ProxyProtocol()
        if len(data) < proxy.HEADER_SIZE:
            continue

        if not proxy.parseHeader(data):
            continue

        if proxy.local:
            # likely a healthcheck
            data = data[proxy.HEADER_SIZE:]
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            wire = response.to_wire()
            sock.settimeout(2.0)
            sock.sendto(wire, addr)
            sock.settimeout(None)

            continue

        payload = data[:(proxy.HEADER_SIZE + proxy.contentLen)]
        dnsData = data[(proxy.HEADER_SIZE + proxy.contentLen):]
        toQueue.put([payload, dnsData], True, 2.0)
        # computing the correct ID for the response
        request = dns.message.from_wire(dnsData)
        response = copy.deepcopy(fromQueue.get(True, 2.0))
        response.id = request.id

        sock.settimeout(2.0)
        sock.sendto(response.to_wire(), addr)
        sock.settimeout(None)

    sock.close()

def ProxyProtocolTCPResponder(port, fromQueue, toQueue):
    # be aware that this responder will not accept a new connection
    # until the last one has been closed. This is done on purpose to
    # to check for connection reuse, making sure that a lot of connections
    # are not opened in parallel.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except socket.error as e:
        print("Error binding in the TCP responder: %s" % str(e))
        sys.exit(1)

    sock.listen(100)
    while True:
        (conn, _) = sock.accept()
        conn.settimeout(5.0)
        # try to read the entire Proxy Protocol header
        proxy = ProxyProtocol()
        header = conn.recv(proxy.HEADER_SIZE)
        if not header:
            conn.close()
            continue

        if not proxy.parseHeader(header):
            conn.close()
            continue

        proxyContent = conn.recv(proxy.contentLen)
        if not proxyContent:
            conn.close()
            continue

        payload = header + proxyContent
        while True:
          try:
            data = conn.recv(2)
          except socket.timeout:
            data = None

          if not data:
            conn.close()
            break

          (datalen,) = struct.unpack("!H", data)
          data = conn.recv(datalen)

          toQueue.put([payload, data], True, 2.0)

          response = copy.deepcopy(fromQueue.get(True, 2.0))
          if not response:
            conn.close()
            break

          # computing the correct ID for the response
          request = dns.message.from_wire(data)
          response.id = request.id

          wire = response.to_wire()
          conn.send(struct.pack("!H", len(wire)))
          conn.send(wire)

        conn.close()

    sock.close()
