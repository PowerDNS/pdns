#!/usr/bin/env python2
import socket
import struct
import time
import dns
import dns.message
import libnacl
import libnacl.utils
import binascii
from builtins import bytes

class DNSCryptResolverCertificate(object):
    DNSCRYPT_CERT_MAGIC = b'\x44\x4e\x53\x43'
    DNSCRYPT_ES_VERSION = b'\x00\x01'
    DNSCRYPT_PROTOCOL_MIN_VERSION = b'\x00\x00'

    def __init__(self, serial, validFrom, validUntil, publicKey, clientMagic):
        self.serial = serial
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.publicKey = publicKey
        self.clientMagic = clientMagic

    def isValid(self):
        now = time.time()
        return self.validFrom <= now and self.validUntil >= now

    @staticmethod
    def fromBinary(binary, providerFP):
        if len(binary) != 124:
            raise Exception("Invalid binary certificate")

        certMagic = binary[0:4]
        esVersion = binary[4:6]
        protocolMinVersion = binary[6:8]

        if certMagic != DNSCryptResolverCertificate.DNSCRYPT_CERT_MAGIC or esVersion != DNSCryptResolverCertificate.DNSCRYPT_ES_VERSION or protocolMinVersion != DNSCryptResolverCertificate.DNSCRYPT_PROTOCOL_MIN_VERSION:
            raise Exception("Invalid binary certificate")

        orig = libnacl.crypto_sign_open(binary[8:124], providerFP)

        resolverPK = orig[0:32]
        clientMagic = orig[32:40]
        serial = struct.unpack_from("!I", orig[40:44])[0]
        validFrom = struct.unpack_from("!I", orig[44:48])[0]
        validUntil = struct.unpack_from("!I", orig[48:52])[0]
        return DNSCryptResolverCertificate(serial, validFrom, validUntil, resolverPK, clientMagic)

class DNSCryptClient(object):
    DNSCRYPT_NONCE_SIZE = 24
    DNSCRYPT_MAC_SIZE = 16
    DNSCRYPT_PADDED_BLOCK_SIZE = 64
    DNSCRYPT_MIN_UDP_LENGTH = 256
    DNSCRYPT_RESOLVER_MAGIC = b'\x72\x36\x66\x6e\x76\x57\x6a\x38'

    @staticmethod
    def _addrToSocketType(addr):
        result = None
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            result = socket.AF_INET6
        except socket.error:
            socket.inet_pton(socket.AF_INET, addr)
            result = socket.AF_INET

        return result

    def __init__(self, providerName, providerFingerprint, resolverAddress, resolverPort=443, timeout=2):
        self._providerName = providerName
        self._providerFingerprint = binascii.unhexlify(providerFingerprint.lower().replace(':', ''))
        self._resolverAddress = resolverAddress
        self._resolverPort = resolverPort
        self._resolverCertificates = []
        self._publicKey, self._privateKey = libnacl.crypto_box_keypair()
        self._timeout = timeout

        addrType = self._addrToSocketType(self._resolverAddress)
        self._sock = socket.socket(addrType, socket.SOCK_DGRAM)
        self._sock.settimeout(timeout)
        self._sock.connect((self._resolverAddress, self._resolverPort))

    def _sendQuery(self, queryContent, tcp=False):
        if tcp:
            addrType = self._addrToSocketType(self._resolverAddress)
            sock = socket.socket(addrType, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            sock.connect((self._resolverAddress, self._resolverPort))
            sock.send(struct.pack("!H", len(queryContent)))
        else:
            sock = self._sock

        sock.send(queryContent)

        data = None
        if tcp:
            got = sock.recv(2)
            if got:
                (rlen,) = struct.unpack("!H", got)
                data = sock.recv(rlen)
        else:
            data = sock.recv(4096)

        return data

    def _hasValidResolverCertificate(self):

        for cert in self._resolverCertificates:
            if cert.isValid():
                return True

        return False

    def clearExpiredResolverCertificates(self):
        newCerts = []

        for cert in self._resolverCertificates:
            if cert.isValid():
                newCerts.append(cert)

        self._resolverCertificates = newCerts

    def refreshResolverCertificates(self):
        self.clearExpiredResolverCertificates()

        query = dns.message.make_query(self._providerName, dns.rdatatype.TXT, dns.rdataclass.IN)
        data = self._sendQuery(query.to_wire())

        response = dns.message.from_wire(data)
        if response.rcode() != dns.rcode.NOERROR or len(response.answer) != 1:
            raise Exception("Invalid response to public key request")

        an = response.answer[0]
        if an.rdclass != dns.rdataclass.IN or an.rdtype != dns.rdatatype.TXT or len(an.items) == 0:
            raise Exception("Invalid response to public key request")

        self._resolverCertificates = []

        for item in an.items:
            if len(item.strings) != 1:
                continue

            cert = DNSCryptResolverCertificate.fromBinary(item.strings[0], self._providerFingerprint)
            if cert.isValid():
                self._resolverCertificates.append(cert)

    def getResolverCertificate(self):
        certs = self._resolverCertificates
        result = None
        for cert in certs:
            if cert.isValid():
                if result is None or cert.serial > result.serial:
                    result = cert

        return result

    def getAllResolverCertificates(self, onlyValid=False):
        certs = self._resolverCertificates
        result = []
        for cert in certs:
            if not onlyValid or cert.isValid():
                result.append(cert)

        return result

    @staticmethod
    def _generateNonce():
        nonce = libnacl.utils.rand_nonce()
        return nonce[:int(DNSCryptClient.DNSCRYPT_NONCE_SIZE / 2)]

    def _encryptQuery(self, queryContent, resolverCert, nonce, tcp=False):
        header = resolverCert.clientMagic + self._publicKey + nonce
        requiredSize = len(header) + self.DNSCRYPT_MAC_SIZE + len(queryContent)
        paddingSize = self.DNSCRYPT_PADDED_BLOCK_SIZE - (len(queryContent) % self.DNSCRYPT_PADDED_BLOCK_SIZE)
        # padding size should be DNSCRYPT_PADDED_BLOCK_SIZE <= padding size <= 4096
        if not tcp and requiredSize < self.DNSCRYPT_MIN_UDP_LENGTH:
            paddingSize += self.DNSCRYPT_MIN_UDP_LENGTH - requiredSize
            requiredSize = self.DNSCRYPT_MIN_UDP_LENGTH

        padding = b'\x80'
        idx = 0
        while idx < (paddingSize - 1):
            padding = padding + b'\x00'
            idx += 1

        data = queryContent + padding
        nonce = nonce + (b'\x00'*int(self.DNSCRYPT_NONCE_SIZE / 2))
        box = libnacl.crypto_box(data, nonce, resolverCert.publicKey, self._privateKey)
        return header + box

    def _decryptResponse(self, encryptedResponse, resolverCert, clientNonce):
        resolverMagic = encryptedResponse[:8]
        if resolverMagic != self.DNSCRYPT_RESOLVER_MAGIC:
            raise Exception("Invalid encrypted response: bad resolver magic")

        nonce = encryptedResponse[8:32]
        if nonce[0:int(self.DNSCRYPT_NONCE_SIZE / 2)] != clientNonce:
            raise Exception("Invalid encrypted response: bad nonce")

        cleartext = libnacl.crypto_box_open(encryptedResponse[32:], nonce, resolverCert.publicKey, self._privateKey)
        cleartextBytes = bytes(cleartext)
        idx = len(cleartextBytes) - 1
        while idx > 0:
            if cleartextBytes[idx] != 0:
                break
            idx -= 1

        if idx == 0 or cleartextBytes[idx] != 128:
            raise Exception("Invalid encrypted response: invalid padding")

        idx -= 1
        paddingLen = len(cleartextBytes) - idx

        return cleartext[:idx+1]

    def query(self, queryContent, tcp=False):

        if not self._hasValidResolverCertificate():
            self.refreshResolverCertificates()

        nonce = self._generateNonce()
        resolverCert = self.getResolverCertificate()
        if resolverCert is None:
            raise Exception("No valid certificate found")
        encryptedQuery = self._encryptQuery(queryContent, resolverCert, nonce, tcp)
        encryptedResponse = self._sendQuery(encryptedQuery, tcp)
        response = self._decryptResponse(encryptedResponse, resolverCert, nonce)
        return response
