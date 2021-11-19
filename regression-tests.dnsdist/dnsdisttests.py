#!/usr/bin/env python2

import copy
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import unittest

import clientsubnetoption

import dns
import dns.message

import libnacl
import libnacl.utils

import h2.connection
import h2.events
import h2.config

from eqdnsmessage import AssertEqualDNSMessageMixin
from proxyprotocol import ProxyProtocol

# Python2/3 compatibility hacks
try:
  from queue import Queue
except ImportError:
  from Queue import Queue

try:
  range = xrange
except NameError:
  pass


class DNSDistTest(AssertEqualDNSMessageMixin, unittest.TestCase):
    """
    Set up a dnsdist instance and responder threads.
    Queries sent to dnsdist are relayed to the responder threads,
    who reply with the response provided by the tests themselves
    on a queue. Responder threads also queue the queries received
    from dnsdist on a separate queue, allowing the tests to check
    that the queries sent from dnsdist were as expected.
    """
    _dnsDistPort = 5340
    _dnsDistListeningAddr = "127.0.0.1"
    _testServerPort = 5350
    _toResponderQueue = Queue()
    _fromResponderQueue = Queue()
    _queueTimeout = 1
    _dnsdistStartupDelay = 2.0
    _dnsdist = None
    _responsesCounter = {}
    _config_template = """
    """
    _config_params = ['_testServerPort']
    _acl = ['127.0.0.1/32']
    _consolePort = 5199
    _consoleKey = None
    _healthCheckName = 'a.root-servers.net.'
    _healthCheckCounter = 0
    _answerUnexpected = True
    _checkConfigExpectedOutput = None
    _verboseMode = False
    _skipListeningOnCL = False
    _backgroundThreads = {}
    _UDPResponder = None
    _TCPResponder = None

    @classmethod
    def startResponders(cls):
        print("Launching responders..")

        cls._UDPResponder = threading.Thread(name='UDP Responder', target=cls.UDPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._UDPResponder.setDaemon(True)
        cls._UDPResponder.start()
        cls._TCPResponder = threading.Thread(name='TCP Responder', target=cls.TCPResponder, args=[cls._testServerPort, cls._toResponderQueue, cls._fromResponderQueue])
        cls._TCPResponder.setDaemon(True)
        cls._TCPResponder.start()

    @classmethod
    def startDNSDist(cls):
        print("Launching dnsdist..")
        confFile = os.path.join('configs', 'dnsdist_%s.conf' % (cls.__name__))
        params = tuple([getattr(cls, param) for param in cls._config_params])
        print(params)
        with open(confFile, 'w') as conf:
            conf.write("-- Autogenerated by dnsdisttests.py\n")
            conf.write(cls._config_template % params)
            conf.write("setSecurityPollSuffix('')")

        if cls._skipListeningOnCL:
          dnsdistcmd = [os.environ['DNSDISTBIN'], '--supervised', '-C', confFile ]
        else:
          dnsdistcmd = [os.environ['DNSDISTBIN'], '--supervised', '-C', confFile,
                        '-l', '%s:%d' % (cls._dnsDistListeningAddr, cls._dnsDistPort) ]

        if cls._verboseMode:
            dnsdistcmd.append('-v')

        for acl in cls._acl:
            dnsdistcmd.extend(['--acl', acl])
        print(' '.join(dnsdistcmd))

        # validate config with --check-config, which sets client=true, possibly exposing bugs.
        testcmd = dnsdistcmd + ['--check-config']
        try:
            output = subprocess.check_output(testcmd, stderr=subprocess.STDOUT, close_fds=True)
        except subprocess.CalledProcessError as exc:
            raise AssertionError('dnsdist --check-config failed (%d): %s' % (exc.returncode, exc.output))
        if cls._checkConfigExpectedOutput is not None:
          expectedOutput = cls._checkConfigExpectedOutput
        else:
          expectedOutput = ('Configuration \'%s\' OK!\n' % (confFile)).encode()
        if not cls._verboseMode and output != expectedOutput:
            raise AssertionError('dnsdist --check-config failed: %s' % output)

        logFile = os.path.join('configs', 'dnsdist_%s.log' % (cls.__name__))
        with open(logFile, 'w') as fdLog:
          cls._dnsdist = subprocess.Popen(dnsdistcmd, close_fds=True, stdout=fdLog, stderr=fdLog)

        if 'DNSDIST_FAST_TESTS' in os.environ:
            delay = 0.5
        else:
            delay = cls._dnsdistStartupDelay

        time.sleep(delay)

        if cls._dnsdist.poll() is not None:
            cls._dnsdist.kill()
            sys.exit(cls._dnsdist.returncode)

    @classmethod
    def setUpSockets(cls):
        print("Setting up UDP socket..")
        cls._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls._sock.settimeout(2.0)
        cls._sock.connect(("127.0.0.1", cls._dnsDistPort))

    @classmethod
    def setUpClass(cls):

        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    @classmethod
    def tearDownClass(cls):
        if 'DNSDIST_FAST_TESTS' in os.environ:
            delay = 0.1
        else:
            delay = 1.0
        if cls._dnsdist:
            cls._dnsdist.terminate()
            if cls._dnsdist.poll() is None:
                time.sleep(delay)
                if cls._dnsdist.poll() is None:
                    cls._dnsdist.kill()
                cls._dnsdist.wait()

        # tell the background threads to stop, if any
        for backgroundThread in cls._backgroundThreads:
          cls._backgroundThreads[backgroundThread] = False

    @classmethod
    def _ResponderIncrementCounter(cls):
        if threading.currentThread().name in cls._responsesCounter:
            cls._responsesCounter[threading.currentThread().name] += 1
        else:
            cls._responsesCounter[threading.currentThread().name] = 1

    @classmethod
    def _getResponse(cls, request, fromQueue, toQueue, synthesize=None):
        response = None
        if len(request.question) != 1:
            print("Skipping query with question count %d" % (len(request.question)))
            return None
        healthCheck = str(request.question[0].name).endswith(cls._healthCheckName)
        if healthCheck:
            cls._healthCheckCounter += 1
            response = dns.message.make_response(request)
        else:
            cls._ResponderIncrementCounter()
            if not fromQueue.empty():
                toQueue.put(request, True, cls._queueTimeout)
                response = fromQueue.get(True, cls._queueTimeout)
                if response:
                  response = copy.copy(response)
                  response.id = request.id

        if synthesize is not None:
          response = dns.message.make_response(request)
          response.set_rcode(synthesize)

        if not response:
            if cls._answerUnexpected:
                response = dns.message.make_response(request)
                response.set_rcode(dns.rcode.SERVFAIL)

        return response

    @classmethod
    def UDPResponder(cls, port, fromQueue, toQueue, trailingDataResponse=False, callback=None):
        cls._backgroundThreads[threading.get_native_id()] = True
        # trailingDataResponse=True means "ignore trailing data".
        # Other values are either False (meaning "raise an exception")
        # or are interpreted as a response RCODE for queries with trailing data.
        # callback is invoked for every -even healthcheck ones- query and should return a raw response
        ignoreTrailing = trailingDataResponse is True

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("127.0.0.1", port))
        sock.settimeout(1.0)
        while True:
            try:
              data, addr = sock.recvfrom(4096)
            except socket.timeout:
              if cls._backgroundThreads.get(threading.get_native_id(), False) == False:
                del cls._backgroundThreads[threading.get_native_id()]
                break
              else:
                continue

            forceRcode = None
            try:
                request = dns.message.from_wire(data, ignore_trailing=ignoreTrailing)
            except dns.message.TrailingJunk as e:
                print('trailing data exception in UDPResponder')
                if trailingDataResponse is False or forceRcode is True:
                    raise
                print("UDP query with trailing data, synthesizing response")
                request = dns.message.from_wire(data, ignore_trailing=True)
                forceRcode = trailingDataResponse

            wire = None
            if callback:
              wire = callback(request)
            else:
              response = cls._getResponse(request, fromQueue, toQueue, synthesize=forceRcode)
              if response:
                wire = response.to_wire()

            if not wire:
              continue

            sock.sendto(wire, addr)

        sock.close()

    @classmethod
    def handleTCPConnection(cls, conn, fromQueue, toQueue, trailingDataResponse=False, multipleResponses=False, callback=None):
      ignoreTrailing = trailingDataResponse is True
      data = conn.recv(2)
      if not data:
        conn.close()
        return

      (datalen,) = struct.unpack("!H", data)
      data = conn.recv(datalen)
      forceRcode = None
      try:
        request = dns.message.from_wire(data, ignore_trailing=ignoreTrailing)
      except dns.message.TrailingJunk as e:
        if trailingDataResponse is False or forceRcode is True:
          raise
        print("TCP query with trailing data, synthesizing response")
        request = dns.message.from_wire(data, ignore_trailing=True)
        forceRcode = trailingDataResponse

      if callback:
        wire = callback(request)
      else:
        response = cls._getResponse(request, fromQueue, toQueue, synthesize=forceRcode)
        if response:
          wire = response.to_wire(max_size=65535)

      if not wire:
        conn.close()
        return

      conn.send(struct.pack("!H", len(wire)))
      conn.send(wire)

      while multipleResponses:
        # do not block, and stop as soon as the queue is empty, either the next response is already here or we are done
        # otherwise we might read responses intended for the next connection
        if fromQueue.empty():
          break

        response = fromQueue.get(False)
        if not response:
          break

        response = copy.copy(response)
        response.id = request.id
        wire = response.to_wire(max_size=65535)
        try:
          conn.send(struct.pack("!H", len(wire)))
          conn.send(wire)
        except socket.error as e:
          # some of the tests are going to close
          # the connection on us, just deal with it
          break

      conn.close()

    @classmethod
    def TCPResponder(cls, port, fromQueue, toQueue, trailingDataResponse=False, multipleResponses=False, callback=None, tlsContext=None, multipleConnections=False):
        cls._backgroundThreads[threading.get_native_id()] = True
        # trailingDataResponse=True means "ignore trailing data".
        # Other values are either False (meaning "raise an exception")
        # or are interpreted as a response RCODE for queries with trailing data.
        # callback is invoked for every -even healthcheck ones- query and should return a raw response

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the TCP responder: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        sock.settimeout(1.0)
        if tlsContext:
          sock = tlsContext.wrap_socket(sock, server_side=True)

        while True:
            try:
              (conn, _) = sock.accept()
            except ssl.SSLError:
              continue
            except ConnectionResetError:
              continue
            except socket.timeout:
              if cls._backgroundThreads.get(threading.get_native_id(), False) == False:
                 del cls._backgroundThreads[threading.get_native_id()]
                 break
              else:
                continue

            conn.settimeout(5.0)
            if multipleConnections:
              thread = threading.Thread(name='TCP Connection Handler',
                                        target=cls.handleTCPConnection,
                                        args=[conn, fromQueue, toQueue, trailingDataResponse, multipleResponses, callback])
              thread.setDaemon(True)
              thread.start()
            else:
              cls.handleTCPConnection(conn, fromQueue, toQueue, trailingDataResponse, multipleResponses, callback)

        sock.close()

    @classmethod
    def handleDoHConnection(cls, config, conn, fromQueue, toQueue, trailingDataResponse, multipleResponses, callback, tlsContext, useProxyProtocol):
        ignoreTrailing = trailingDataResponse is True
        h2conn = h2.connection.H2Connection(config=config)
        h2conn.initiate_connection()
        conn.sendall(h2conn.data_to_send())
        dnsData = {}

        if useProxyProtocol:
            # try to read the entire Proxy Protocol header
            proxy = ProxyProtocol()
            header = conn.recv(proxy.HEADER_SIZE)
            if not header:
                print('unable to get header')
                conn.close()
                return

            if not proxy.parseHeader(header):
                print('unable to parse header')
                print(header)
                conn.close()
                return

            proxyContent = conn.recv(proxy.contentLen)
            if not proxyContent:
                print('unable to get content')
                conn.close()
                return

            payload = header + proxyContent
            toQueue.put(payload, True, cls._queueTimeout)

        # be careful, HTTP/2 headers and data might be in different recv() results
        requestHeaders = None
        while True:
            data = conn.recv(65535)
            if not data:
                break

            events = h2conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    requestHeaders = event.headers
                if isinstance(event, h2.events.DataReceived):
                    h2conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if not event.stream_id in dnsData:
                      dnsData[event.stream_id] = b''
                    dnsData[event.stream_id] = dnsData[event.stream_id] + (event.data)
                    if event.stream_ended:
                        forceRcode = None
                        status = 200
                        try:
                            request = dns.message.from_wire(dnsData[event.stream_id], ignore_trailing=ignoreTrailing)
                        except dns.message.TrailingJunk as e:
                            if trailingDataResponse is False or forceRcode is True:
                                raise
                            print("DOH query with trailing data, synthesizing response")
                            request = dns.message.from_wire(dnsData[event.stream_id], ignore_trailing=True)
                            forceRcode = trailingDataResponse

                        if callback:
                            status, wire = callback(request, requestHeaders, fromQueue, toQueue)
                        else:
                            response = cls._getResponse(request, fromQueue, toQueue, synthesize=forceRcode)
                            if response:
                                wire = response.to_wire(max_size=65535)

                        if not wire:
                            conn.close()
                            conn = None
                            break

                        headers = [
                          (':status', str(status)),
                          ('content-length', str(len(wire))),
                          ('content-type', 'application/dns-message'),
                        ]
                        h2conn.send_headers(stream_id=event.stream_id, headers=headers)
                        h2conn.send_data(stream_id=event.stream_id, data=wire, end_stream=True)

                data_to_send = h2conn.data_to_send()
                if data_to_send:
                    conn.sendall(data_to_send)

            if conn is None:
                break

        if conn is not None:
            conn.close()

    @classmethod
    def DOHResponder(cls, port, fromQueue, toQueue, trailingDataResponse=False, multipleResponses=False, callback=None, tlsContext=None, useProxyProtocol=False):
        cls._backgroundThreads[threading.get_native_id()] = True
        # trailingDataResponse=True means "ignore trailing data".
        # Other values are either False (meaning "raise an exception")
        # or are interpreted as a response RCODE for queries with trailing data.
        # callback is invoked for every -even healthcheck ones- query and should return a raw response

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the TCP responder: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        sock.settimeout(1.0)
        if tlsContext:
            sock = tlsContext.wrap_socket(sock, server_side=True)

        config = h2.config.H2Configuration(client_side=False)

        while True:
            try:
                (conn, _) = sock.accept()
            except ssl.SSLError:
                continue
            except ConnectionResetError:
              continue
            except socket.timeout:
                if cls._backgroundThreads.get(threading.get_native_id(), False) == False:
                    del cls._backgroundThreads[threading.get_native_id()]
                    break
                else:
                    continue

            conn.settimeout(5.0)
            thread = threading.Thread(name='DoH Connection Handler',
                                      target=cls.handleDoHConnection,
                                      args=[config, conn, fromQueue, toQueue, trailingDataResponse, multipleResponses, callback, tlsContext, useProxyProtocol])
            thread.setDaemon(True)
            thread.start()

        sock.close()

    @classmethod
    def sendUDPQuery(cls, query, response, useQueue=True, timeout=2.0, rawQuery=False):
        if useQueue and response is not None:
            cls._toResponderQueue.put(response, True, timeout)

        if timeout:
            cls._sock.settimeout(timeout)

        try:
            if not rawQuery:
                query = query.to_wire()
            cls._sock.send(query)
            data = cls._sock.recv(4096)
        except socket.timeout:
            data = None
        finally:
            if timeout:
                cls._sock.settimeout(None)

        receivedQuery = None
        message = None
        if useQueue and not cls._fromResponderQueue.empty():
            receivedQuery = cls._fromResponderQueue.get(True, timeout)
        if data:
            message = dns.message.from_wire(data)
        return (receivedQuery, message)

    @classmethod
    def openTCPConnection(cls, timeout=None, port=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if timeout:
            sock.settimeout(timeout)

        if not port:
          port = cls._dnsDistPort

        sock.connect(("127.0.0.1", port))
        return sock

    @classmethod
    def openTLSConnection(cls, port, serverName, caCert=None, timeout=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if timeout:
            sock.settimeout(timeout)

        # 2.7.9+
        if hasattr(ssl, 'create_default_context'):
            sslctx = ssl.create_default_context(cafile=caCert)
            sslsock = sslctx.wrap_socket(sock, server_hostname=serverName)
        else:
            sslsock = ssl.wrap_socket(sock, ca_certs=caCert, cert_reqs=ssl.CERT_REQUIRED)

        sslsock.connect(("127.0.0.1", port))
        return sslsock

    @classmethod
    def sendTCPQueryOverConnection(cls, sock, query, rawQuery=False, response=None, timeout=2.0):
        if not rawQuery:
            wire = query.to_wire()
        else:
            wire = query

        if response:
            cls._toResponderQueue.put(response, True, timeout)

        sock.send(struct.pack("!H", len(wire)))
        sock.send(wire)

    @classmethod
    def recvTCPResponseOverConnection(cls, sock, useQueue=False, timeout=2.0):
        print("reading data")
        message = None
        data = sock.recv(2)
        if data:
            (datalen,) = struct.unpack("!H", data)
            print(datalen)
            data = sock.recv(datalen)
            if data:
                print(data)
                message = dns.message.from_wire(data)

        print(useQueue)
        if useQueue and not cls._fromResponderQueue.empty():
            receivedQuery = cls._fromResponderQueue.get(True, timeout)
            print("Got from queue")
            print(receivedQuery)
            return (receivedQuery, message)
        else:
            print("queue empty")
            return message

    @classmethod
    def sendTCPQuery(cls, query, response, useQueue=True, timeout=2.0, rawQuery=False):
        message = None
        if useQueue:
            cls._toResponderQueue.put(response, True, timeout)

        sock = cls.openTCPConnection(timeout)

        try:
            cls.sendTCPQueryOverConnection(sock, query, rawQuery)
            message = cls.recvTCPResponseOverConnection(sock)
        except socket.timeout as e:
            print("Timeout while sending or receiving TCP data: %s" % (str(e)))
        except socket.error as e:
            print("Network error: %s" % (str(e)))
        finally:
            sock.close()

        receivedQuery = None
        print(useQueue)
        if useQueue and not cls._fromResponderQueue.empty():
            print("Got from queue")
            print(receivedQuery)
            receivedQuery = cls._fromResponderQueue.get(True, timeout)
        else:
          print("queue is empty")

        return (receivedQuery, message)

    @classmethod
    def sendTCPQueryWithMultipleResponses(cls, query, responses, useQueue=True, timeout=2.0, rawQuery=False):
        if useQueue:
            for response in responses:
                cls._toResponderQueue.put(response, True, timeout)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if timeout:
            sock.settimeout(timeout)

        sock.connect(("127.0.0.1", cls._dnsDistPort))
        messages = []

        try:
            if not rawQuery:
                wire = query.to_wire()
            else:
                wire = query

            sock.send(struct.pack("!H", len(wire)))
            sock.send(wire)
            while True:
                data = sock.recv(2)
                if not data:
                    break
                (datalen,) = struct.unpack("!H", data)
                data = sock.recv(datalen)
                messages.append(dns.message.from_wire(data))

        except socket.timeout as e:
            print("Timeout while receiving multiple TCP responses: %s" % (str(e)))
        except socket.error as e:
            print("Network error: %s" % (str(e)))
        finally:
            sock.close()

        receivedQuery = None
        if useQueue and not cls._fromResponderQueue.empty():
            receivedQuery = cls._fromResponderQueue.get(True, timeout)
        return (receivedQuery, messages)

    def setUp(self):
        # This function is called before every test

        # Clear the responses counters
        self._responsesCounter.clear()

        self._healthCheckCounter = 0

        # Make sure the queues are empty, in case
        # a previous test failed
        self.clearResponderQueues()

        super(DNSDistTest, self).setUp()

    @classmethod
    def clearToResponderQueue(cls):
        while not cls._toResponderQueue.empty():
            cls._toResponderQueue.get(False)

    @classmethod
    def clearFromResponderQueue(cls):
        while not cls._fromResponderQueue.empty():
            cls._fromResponderQueue.get(False)

    @classmethod
    def clearResponderQueues(cls):
        cls.clearToResponderQueue()
        cls.clearFromResponderQueue()

    @staticmethod
    def generateConsoleKey():
        return libnacl.utils.salsa_key()

    @classmethod
    def _encryptConsole(cls, command, nonce):
        command = command.encode('UTF-8')
        if cls._consoleKey is None:
            return command
        return libnacl.crypto_secretbox(command, nonce, cls._consoleKey)

    @classmethod
    def _decryptConsole(cls, command, nonce):
        if cls._consoleKey is None:
            result = command
        else:
            result = libnacl.crypto_secretbox_open(command, nonce, cls._consoleKey)
        return result.decode('UTF-8')

    @classmethod
    def sendConsoleCommand(cls, command, timeout=1.0):
        ourNonce = libnacl.utils.rand_nonce()
        theirNonce = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if timeout:
            sock.settimeout(timeout)

        sock.connect(("127.0.0.1", cls._consolePort))
        sock.send(ourNonce)
        theirNonce = sock.recv(len(ourNonce))
        if len(theirNonce) != len(ourNonce):
            print("Received a nonce of size %d, expecting %d, console command will not be sent!" % (len(theirNonce), len(ourNonce)))
            if len(theirNonce) == 0:
                raise socket.error("Got EOF while reading a nonce of size %d, console command will not be sent!" % (len(ourNonce)))
            return None

        halfNonceSize = int(len(ourNonce) / 2)
        readingNonce = ourNonce[0:halfNonceSize] + theirNonce[halfNonceSize:]
        writingNonce = theirNonce[0:halfNonceSize] + ourNonce[halfNonceSize:]
        msg = cls._encryptConsole(command, writingNonce)
        sock.send(struct.pack("!I", len(msg)))
        sock.send(msg)
        data = sock.recv(4)
        if not data:
            raise socket.error("Got EOF while reading the response size")

        (responseLen,) = struct.unpack("!I", data)
        data = sock.recv(responseLen)
        response = cls._decryptConsole(data, readingNonce)
        return response

    def compareOptions(self, a, b):
        self.assertEqual(len(a), len(b))
        for idx in range(len(a)):
            self.assertEqual(a[idx], b[idx])

    def checkMessageNoEDNS(self, expected, received):
        self.assertEqual(expected, received)
        self.assertEqual(received.edns, -1)
        self.assertEqual(len(received.options), 0)

    def checkMessageEDNSWithoutOptions(self, expected, received):
        self.assertEqual(expected, received)
        self.assertEqual(received.edns, 0)
        self.assertEqual(expected.payload, received.payload)

    def checkMessageEDNSWithoutECS(self, expected, received, withCookies=0):
        self.assertEqual(expected, received)
        self.assertEqual(received.edns, 0)
        self.assertEqual(expected.payload, received.payload)
        self.assertEqual(len(received.options), withCookies)
        if withCookies:
            for option in received.options:
                self.assertEqual(option.otype, 10)
        else:
            for option in received.options:
                self.assertNotEqual(option.otype, 10)

    def checkMessageEDNSWithECS(self, expected, received, additionalOptions=0):
        self.assertEqual(expected, received)
        self.assertEqual(received.edns, 0)
        self.assertEqual(expected.payload, received.payload)
        self.assertEqual(len(received.options), 1 + additionalOptions)
        hasECS = False
        for option in received.options:
            if option.otype == clientsubnetoption.ASSIGNED_OPTION_CODE:
                hasECS = True
            else:
                self.assertNotEqual(additionalOptions, 0)

        self.compareOptions(expected.options, received.options)
        self.assertTrue(hasECS)

    def checkMessageEDNS(self, expected, received):
        self.assertEqual(expected, received)
        self.assertEqual(received.edns, 0)
        self.assertEqual(expected.payload, received.payload)
        self.assertEqual(len(expected.options), len(received.options))
        self.compareOptions(expected.options, received.options)

    def checkQueryEDNSWithECS(self, expected, received, additionalOptions=0):
        self.checkMessageEDNSWithECS(expected, received, additionalOptions)

    def checkQueryEDNS(self, expected, received):
        self.checkMessageEDNS(expected, received)

    def checkResponseEDNSWithECS(self, expected, received, additionalOptions=0):
        self.checkMessageEDNSWithECS(expected, received, additionalOptions)

    def checkQueryEDNSWithoutECS(self, expected, received):
        self.checkMessageEDNSWithoutECS(expected, received)

    def checkResponseEDNSWithoutECS(self, expected, received, withCookies=0):
        self.checkMessageEDNSWithoutECS(expected, received, withCookies)

    def checkQueryNoEDNS(self, expected, received):
        self.checkMessageNoEDNS(expected, received)

    def checkResponseNoEDNS(self, expected, received):
        self.checkMessageNoEDNS(expected, received)

    def generateNewCertificateAndKey(self):
        # generate and sign a new cert
        cmd = ['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-config', 'configServer.conf']
        output = None
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input='')
        except subprocess.CalledProcessError as exc:
            raise AssertionError('openssl req failed (%d): %s' % (exc.returncode, exc.output))
        cmd = ['openssl', 'x509', '-req', '-days', '1', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-in', 'server.csr', '-out', 'server.pem', '-extfile', 'configServer.conf', '-extensions', 'v3_req']
        output = None
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input='')
        except subprocess.CalledProcessError as exc:
            raise AssertionError('openssl x509 failed (%d): %s' % (exc.returncode, exc.output))

        with open('server.chain', 'w') as outFile:
            for inFileName in ['server.pem', 'ca.pem']:
                with open(inFileName) as inFile:
                    outFile.write(inFile.read())

    def checkMessageProxyProtocol(self, receivedProxyPayload, source, destination, isTCP, values=[], v6=False, sourcePort=None, destinationPort=None):
        proxy = ProxyProtocol()
        self.assertTrue(proxy.parseHeader(receivedProxyPayload))
        self.assertEqual(proxy.version, 0x02)
        self.assertEqual(proxy.command, 0x01)
        if v6:
            self.assertEqual(proxy.family, 0x02)
        else:
            self.assertEqual(proxy.family, 0x01)
        if not isTCP:
            self.assertEqual(proxy.protocol, 0x02)
        else:
            self.assertEqual(proxy.protocol, 0x01)
        self.assertGreater(proxy.contentLen, 0)

        self.assertTrue(proxy.parseAddressesAndPorts(receivedProxyPayload))
        self.assertEqual(proxy.source, source)
        self.assertEqual(proxy.destination, destination)
        if sourcePort:
            self.assertEqual(proxy.sourcePort, sourcePort)
        if destinationPort:
            self.assertEqual(proxy.destinationPort, destinationPort)
        else:
            self.assertEqual(proxy.destinationPort, self._dnsDistPort)

        self.assertTrue(proxy.parseAdditionalValues(receivedProxyPayload))
        proxy.values.sort()
        values.sort()
        self.assertEqual(proxy.values, values)
