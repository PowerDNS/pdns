#!/usr/bin/env python

import copy
import socket
import struct

class ProxyProtocol(object):
    MAGIC = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
    # Header is magic + versioncommand (1) + family (1) + content length (2)
    HEADER_SIZE = len(MAGIC) + 1 + 1 + 2
    PORT_SIZE = 2

    def consumed(self):
        return self.offset

    def parseHeader(self, data):
        if len(data) < self.HEADER_SIZE:
            return False

        if data[:len(self.MAGIC)] != self.MAGIC:
            return False

        value = struct.unpack('!B', bytes(bytearray([data[12]])))[0]
        self.version = value >> 4
        if self.version != 0x02:
            return False

        self.command = value & ~0x20
        self.local = False
        self.offset = self.HEADER_SIZE

        if self.command == 0x00:
            self.local = True
        elif self.command == 0x01:
            value = struct.unpack('!B', bytes(bytearray([data[13]])))[0]
            self.family = value >> 4
            if self.family == 0x01:
                self.addrSize = 4
            elif self.family == 0x02:
                self.addrSize = 16
            else:
                return False

            self.protocol = value & ~0xF0
            if self.protocol == 0x01:
                self.tcp = True
            elif self.protocol == 0x02:
                self.tcp = False
            else:
                return False
        else:
            return False

        self.contentLen = struct.unpack("!H", data[14:16])[0]

        if not self.local:
            if self.contentLen < (self.addrSize * 2 + self.PORT_SIZE * 2):
                return False

        return True

    def getAddr(self, data):
        if len(data) < (self.consumed() + self.addrSize):
            return False

        value = None
        if self.family == 0x01:
            value = socket.inet_ntop(socket.AF_INET, data[self.offset:self.offset + self.addrSize])
        else:
            value = socket.inet_ntop(socket.AF_INET6, data[self.offset:self.offset + self.addrSize])

        self.offset = self.offset + self.addrSize
        return value

    def getPort(self, data):
        if len(data) < (self.consumed() + self.PORT_SIZE):
            return False

        value = struct.unpack('!H', data[self.offset:self.offset + self.PORT_SIZE])[0]
        self.offset = self.offset + self.PORT_SIZE
        return value

    def parseAddressesAndPorts(self, data):
        if self.local:
            return True

        if len(data) < (self.consumed() + self.addrSize * 2 + self.PORT_SIZE * 2):
            return False

        self.source = self.getAddr(data)
        self.destination = self.getAddr(data)
        self.sourcePort = self.getPort(data)
        self.destinationPort = self.getPort(data)
        return True

    def parseAdditionalValues(self, data):
        self.values = []
        if self.local:
            return True

        if len(data) < (self.HEADER_SIZE + self.contentLen):
            return False

        remaining = self.HEADER_SIZE + self.contentLen - self.consumed()
        if len(data) < remaining:
            return False

        while remaining >= 3:
            valueType = struct.unpack("!B", bytes(bytearray([data[self.offset]])))[0]
            self.offset = self.offset + 1
            valueLen = struct.unpack("!H", data[self.offset:self.offset+2])[0]
            self.offset = self.offset + 2

            remaining = remaining - 3
            if valueLen > 0:
                if valueLen > remaining:
                    return False
                self.values.append([valueType, data[self.offset:self.offset+valueLen]])
                self.offset = self.offset + valueLen
                remaining = remaining - valueLen

            else:
                self.values.append([valueType, ""])

        return True

    @classmethod
    def getPayload(cls, local, tcp, v6, source, destination, sourcePort, destinationPort, values):
        payload = copy.deepcopy(cls.MAGIC)
        version = 0x02

        if local:
            command = 0x00
        else:
            command = 0x01

        value = struct.pack('!B', (version << 4) + command)
        payload = payload + value

        addrSize = 0
        family = 0x00
        protocol = 0x00
        if not local:
            if tcp:
                protocol = 0x01
            else:
                protocol = 0x02
            # sorry but compatibility with python 2 is awful for this,
            # not going to waste time on it
            if not v6:
                family = 0x01
                addrSize = 4
            else:
                family = 0x02
                addrSize = 16

        value = struct.pack('!B', (family << 4)  + protocol)
        payload = payload + value

        contentSize = 0
        if not local:
            contentSize = contentSize + addrSize * 2 + cls.PORT_SIZE *2

        valuesSize = 0
        for value in values:
            valuesSize = valuesSize + 3 + len(value[1])

        contentSize = contentSize + valuesSize

        value = struct.pack('!H', contentSize)
        payload = payload +  value

        if not local:
            if family == 0x01:
                af = socket.AF_INET
            else:
                af = socket.AF_INET6

            value = socket.inet_pton(af, source)
            payload = payload + value
            value = socket.inet_pton(af, destination)
            payload = payload + value
            value = struct.pack('!H', sourcePort)
            payload = payload + value
            value = struct.pack('!H', destinationPort)
            payload = payload + value

        for value in values:
            valueType = struct.pack('!B', value[0])
            valueLen = struct.pack('!H', len(value[1]))
            payload = payload + valueType + valueLen + value[1]

        return payload
