#!/usr/bin/env python2

import binascii
import datetime
import socket
import struct
import sys
import threading

# run: protoc -I=../pdns/ --python_out=. ../pdns/dnsmessage.proto
# to generate dnsmessage_pb2
import dnsmessage_pb2

class PDNSPBConnHandler(object):

    def __init__(self, conn):
        self._conn = conn

    def run(self):
        while True:
            data = self._conn.recv(2)
            if not data:
                break
            (datalen,) = struct.unpack("!H", data)
            data = self._conn.recv(datalen)

            msg = dnsmessage_pb2.PBDNSMessage()
            msg.ParseFromString(data)
            if msg.type == dnsmessage_pb2.PBDNSMessage.DNSQueryType:
                self.printQueryMessage(msg)
            elif msg.type == dnsmessage_pb2.PBDNSMessage.DNSResponseType:
                self.printResponseMessage(msg)
            elif msg.type == dnsmessage_pb2.PBDNSMessage.DNSOutgoingQueryType:
                self.printOutgoingQueryMessage(msg)
            elif msg.type == dnsmessage_pb2.PBDNSMessage.DNSIncomingResponseType:
                self.printIncomingResponseMessage(msg)
            else:
                print('Discarding unsupported message type %d' % (msg.type))

        self._conn.close()

    def printQueryMessage(self, message):
        self.printSummary(message, 'Query')
        self.printQuery(message)

    def printOutgoingQueryMessage(self, message):
        self.printSummary(message, 'Query (O)')
        self.printQuery(message)

    def printResponseMessage(self, message):
        self.printSummary(message, 'Response')
        self.printQuery(message)
        self.printResponse(message)

    def printIncomingResponseMessage(self, message):
        self.printSummary(message, 'Response (I)')
        self.printQuery(message)
        self.printResponse(message)

    def printQuery(self, message):
        if message.HasField('question'):
            qclass = 1
            if message.question.HasField('qClass'):
                qclass = message.question.qClass
            print("- Question: %d, %d, %s" % (qclass,
                                              message.question.qType,
                                              message.question.qName))

    @staticmethod
    def getAppliedPolicyTypeAsString(polType):
        if polType == dnsmessage_pb2.PBDNSMessage.UNKNOWN:
            return 'Unknown'
        elif polType == dnsmessage_pb2.PBDNSMessage.QNAME:
            return 'QName'
        elif polType == dnsmessage_pb2.PBDNSMessage.CLIENTIP:
            return 'Client IP'
        elif polType == dnsmessage_pb2.PBDNSMessage.RESPONSEIP:
            return 'Response IP'
        elif polType == dnsmessage_pb2.PBDNSMessage.NSDNAME:
            return 'NS DName'
        elif polType == dnsmessage_pb2.PBDNSMessage.NSIP:
            return 'NS IP'

    def printResponse(self, message):
        if message.HasField('response'):
            response = message.response

            if response.HasField('queryTimeSec'):
                datestr = datetime.datetime.fromtimestamp(response.queryTimeSec).strftime('%Y-%m-%d %H:%M:%S')
                if response.HasField('queryTimeUsec'):
                    datestr = datestr + '.' + str(response.queryTimeUsec)
                print("- Query time: %s" % (datestr))

            policystr = ''
            if response.HasField('appliedPolicy') and response.appliedPolicy:
                policystr = ', Applied policy: ' + response.appliedPolicy
                if response.HasField('appliedPolicyType'):
                    policystr = policystr + ' (' + self.getAppliedPolicyTypeAsString(response.appliedPolicyType) + ')'

            tagsstr = ''
            if response.tags:
                tagsstr = ', Tags: ' + ','.join(response.tags)

            rrscount = len(response.rrs)

            print("- Response Code: %d, RRs: %d%s%s" % (response.rcode,
                                                      rrscount,
                                                      policystr,
                                                      tagsstr))

            for rr in response.rrs:
                rrclass = 1
                rdatastr = ''
                if rr.HasField('class'):
                    rrclass = getattr(rr, 'class')
                rrtype = rr.type
                if (rrclass == 1 or rrclass == 255) and rr.HasField('rdata'):
                    if rrtype == 1:
                        rdatastr = socket.inet_ntop(socket.AF_INET, rr.rdata)
                    elif rrtype == 5:
                        rdatastr = rr.rdata
                    elif rrtype == 28:
                        rdatastr = socket.inet_ntop(socket.AF_INET6, rr.rdata)

                print("\t - %d, %d, %s, %d, %s" % (rrclass,
                                                   rrtype,
                                                   rr.name,
                                                   rr.ttl,
                                                   rdatastr))

    def printSummary(self, msg, typestr):
        datestr = datetime.datetime.fromtimestamp(msg.timeSec).strftime('%Y-%m-%d %H:%M:%S')
        if msg.HasField('timeUsec'):
            datestr = datestr + '.' + str(msg.timeUsec)
        ipfromstr = 'N/A'
        iptostr = 'N/A'
        fromvalue = getattr(msg, 'from')
        if msg.socketFamily == dnsmessage_pb2.PBDNSMessage.INET:
            if msg.HasField('from'):
                ipfromstr = socket.inet_ntop(socket.AF_INET, fromvalue)
            if msg.HasField('to'):
                iptostr = socket.inet_ntop(socket.AF_INET, msg.to)
        else:
            if msg.HasField('from'):
                ipfromstr = socket.inet_ntop(socket.AF_INET6, fromvalue)
            if msg.HasField('to'):
                iptostr = socket.inet_ntop(socket.AF_INET6, msg.to)

        if msg.socketProtocol == dnsmessage_pb2.PBDNSMessage.UDP:
            protostr = 'UDP'
        else:
            protostr = 'TCP'

        messageidstr = binascii.hexlify(bytearray(msg.messageId))

        serveridstr = 'N/A'
        if msg.HasField('serverIdentity'):
            serveridstr = msg.serverIdentity

        initialrequestidstr = ''
        if msg.HasField('initialRequestId'):
            initialrequestidstr = ', initial uuid: %s ' % (binascii.hexlify(bytearray(msg.initialRequestId)))

        requestorstr = ''
        requestor = self.getRequestorSubnet(msg)
        if requestor:
            requestorstr = ' (' + requestor + ')'

        deviceId = binascii.hexlify(bytearray(msg.deviceId))
        requestorId = msg.requestorId

        print('[%s] %s of size %d: %s%s -> %s (%s), id: %d, uuid: %s%s '
                  'requestorid: %s deviceid: %s serverid: %s' % (datestr,
                                                    typestr,
                                                    msg.inBytes,
                                                    ipfromstr,
                                                    requestorstr,
                                                    iptostr,
                                                    protostr,
                                                    msg.id,
                                                    messageidstr,
                                                    initialrequestidstr,
                                                    requestorId,
                                                    deviceId,
                                                    serveridstr))

    def getRequestorSubnet(self, msg):
        requestorstr = None
        if msg.HasField('originalRequestorSubnet'):
            if len(msg.originalRequestorSubnet) == 4:
                requestorstr = socket.inet_ntop(socket.AF_INET,
                                                msg.originalRequestorSubnet)
            elif len(msg.originalRequestorSubnet) == 16:
                requestorstr = socket.inet_ntop(socket.AF_INET6,
                                                msg.originalRequestorSubnet)
        return requestorstr

class PDNSPBListener(object):

    def __init__(self, addr, port):
        res = socket.getaddrinfo(addr, port, socket.AF_UNSPEC,
                                 socket.SOCK_STREAM, 0,
                                 socket.AI_PASSIVE)
        if len(res) != 1:
            print("Error parsing the supplied address")
            sys.exit(1)
        family, socktype, _, _, sockaddr = res[0]
        self._sock = socket.socket(family, socktype)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            self._sock.bind(sockaddr)
        except socket.error as exp:
            print("Error while binding: %s" % str(exp))
            sys.exit(1)

        self._sock.listen(100)

    def run(self):
        while True:
            (conn, _) = self._sock.accept()

            handler = PDNSPBConnHandler(conn)
            thread = threading.Thread(name='Connection Handler',
                                      target=PDNSPBConnHandler.run,
                                      args=[handler])
            thread.setDaemon(True)
            thread.start()

        self._sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit('Usage: %s <address> <port>' % (sys.argv[0]))

    PDNSPBListener(sys.argv[1], sys.argv[2]).run()
    sys.exit(0)
