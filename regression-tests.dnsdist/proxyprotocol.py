#!/usr/bin/env python

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
