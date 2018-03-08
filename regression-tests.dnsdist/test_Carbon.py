#!/usr/bin/env python
import threading
import socket
import sys
import time
from dnsdisttests import DNSDistTest, Queue

class TestCarbon(DNSDistTest):

    _serverCount = 3
    _serverUpCount = 2
    _baseUDPPort = 5350
    _serverTemplate = """newServer{address="127.0.0.1:%s"}"""
    _toResponderQueue1 = Queue()
    _fromResponderQueue1 = Queue()
    _carbonServer1Port = 8000
    _carbonServer1Name = "carbonname1"
    _carbonServer2Port = 8001
    _carbonServer2Name = "carbonname2"
    _carbonQueue1 = Queue()
    _carbonQueue2 = Queue()
    _carbonInterval = 2
    _carbonCounters = {}
    _config_params = ['_carbonServer1Port', '_carbonServer1Name', '_carbonInterval',
                      '_carbonServer2Port', '_carbonServer2Name', '_carbonInterval']
    _config_template = """
    carbonServer("127.0.0.1:%s", "%s", %s)
    carbonServer("127.0.0.1:%s", "%s", %s)
    """

    @classmethod
    def CarbonResponder(cls, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except socket.error as e:
            print("Error binding in the Carbon responder: %s" % str(e))
            sys.exit(1)

        sock.listen(100)
        while True:
            (conn, _) = sock.accept()
            conn.settimeout(2.0)
            lines = b''
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                lines += data

            if port == cls._carbonServer1Port:
                cls._carbonQueue1.put(lines, True, timeout=2.0)
            else:
                cls._carbonQueue2.put(lines, True, timeout=2.0)
            if threading.currentThread().name in cls._carbonCounters:
                cls._carbonCounters[threading.currentThread().name] += 1
            else:
                cls._carbonCounters[threading.currentThread().name] = 1

            conn.close()
        sock.close()

    @classmethod
    def UDPResponder(cls, port, fromQueue, toQueue):
        DNSDistTest.UDPResponder.im_func(cls, port, fromQueue, toQueue)

    @classmethod
    def startResponders(cls):
        cls.startUDPResponders(cls._serverCount, cls._serverUpCount)

        cls._CarbonResponder1 = threading.Thread(name='Carbon Responder 1', target=cls.CarbonResponder, args=[cls._carbonServer1Port])
        cls._CarbonResponder1.setDaemon(True)
        cls._CarbonResponder1.start()

        cls._CarbonResponder2 = threading.Thread(name='Carbon Responder 2', target=cls.CarbonResponder, args=[cls._carbonServer2Port])
        cls._CarbonResponder2.setDaemon(True)
        cls._CarbonResponder2.start()

    @classmethod
    def startUDPResponders(cls, servers, servers_up):
        if servers < servers_up:
            print('startUDPResponders failed: servers cannot be less than servers_up')
            sys.exit(1)

        serverCollectionTemplate = b''

        # set up a number of UDP servers
        # metric: dnsdist.{CARBON_SERVER_NAME}.main.pools._default_.servers {SERVERS} {TIME}
        for num in xrange(0, servers):
            ns = str(cls._baseUDPPort+num)
            serverCollectionTemplate += cls._serverTemplate % ns

        cls._config_template += serverCollectionTemplate

        # add a specific amount to the response queue marking them 'up'
        # metric: dnsdist.{CARBON_SERVER_NAME}.main.pools._default_.servers-up {SERVERS_UP} {TIME}
        for num in xrange(0, servers_up):
            port = cls._baseUDPPort+num
            cls._UDPResponder = threading.Thread(name='UDP Responder 1', target=cls.UDPResponder, args=[port, cls._toResponderQueue1, cls._fromResponderQueue1])
            cls._UDPResponder.setDaemon(True)
            cls._UDPResponder.start()

    def testCarbon(self):
        """
        Carbon: send data to 2 carbon servers
        """
        # wait for the carbon data to be sent
        time.sleep(self._carbonInterval + 1)

        # first server
        self.assertFalse(self._carbonQueue1.empty())
        data1 = self._carbonQueue1.get(False)
        # second server
        self.assertFalse(self._carbonQueue2.empty())
        data2 = self._carbonQueue2.get(False)
        after = time.time()

        self.assertTrue(data1)
        self.assertTrue(len(data1.splitlines()) > 1)
        expectedStart = b"dnsdist.%s.main." % self._carbonServer1Name.encode('UTF-8')
        for line in data1.splitlines():
            self.assertTrue(line.startswith(expectedStart))
            parts = line.split(b' ')
            self.assertEquals(len(parts), 3)
            self.assertTrue(parts[1].isdigit())
            self.assertTrue(parts[2].isdigit())
            self.assertTrue(int(parts[2]) <= int(after))

        self.assertTrue(data2)
        self.assertTrue(len(data2.splitlines()) > 1)
        expectedStart = b"dnsdist.%s.main." % self._carbonServer2Name.encode('UTF-8')
        for line in data2.splitlines():
            self.assertTrue(line.startswith(expectedStart))
            parts = line.split(b' ')
            self.assertEquals(len(parts), 3)
            self.assertTrue(parts[1].isdigit())
            self.assertTrue(parts[2].isdigit())
            self.assertTrue(int(parts[2]) <= int(after))

        # make sure every carbon server has received at least one connection
        for key in self._carbonCounters:
            value = self._carbonCounters[key]
            self.assertTrue(value >= 1)

    def testCarbonServerUp(self):
        # wait for the carbon data to be sent
        time.sleep(self._carbonInterval + 1)

        # first server
        self.assertFalse(self._carbonQueue1.empty())
        data1 = self._carbonQueue1.get(False)
        # second server
        self.assertFalse(self._carbonQueue2.empty())
        data2 = self._carbonQueue2.get(False)
        after = time.time()

        # check the first carbon server got both servers and
        # servers-up metrics and that they are the same as
        # configured in the class definition
        self.assertTrue(data1)
        self.assertTrue(len(data1.splitlines()) > 1)
        expectedStart = b"dnsdist.%s.main.pools._default_.servers" % self._carbonServer1Name.encode('UTF-8')
        for line in data1.splitlines():
            if expectedStart in line:
                parts = line.split(b' ')
                if 'servers-up' in line:
                    self.assertEquals(len(parts), 3)
                    self.assertTrue(parts[1].isdigit())
                    self.assertEquals(int(parts[1]), self._serverUpCount)
                    self.assertTrue(parts[2].isdigit())
                    self.assertTrue(int(parts[2]) <= int(after))
                else:
                    self.assertEquals(len(parts), 3)
                    self.assertTrue(parts[1].isdigit())
                    self.assertEquals(int(parts[1]), self._serverCount)
                    self.assertTrue(parts[2].isdigit())
                    self.assertTrue(int(parts[2]) <= int(after))

        # check the second carbon server got both servers and
        # servers-up metrics and that they are the same as
        # configured in the class definition and the same as
        # the first carbon server
        self.assertTrue(data2)
        self.assertTrue(len(data2.splitlines()) > 1)
        expectedStart = b"dnsdist.%s.main.pools._default_.servers" % self._carbonServer2Name.encode('UTF-8')
        for line in data2.splitlines():
            if expectedStart in line:
                parts = line.split(b' ')
                if 'servers-up' in line:
                    self.assertEquals(len(parts), 3)
                    self.assertTrue(parts[1].isdigit())
                    self.assertEquals(int(parts[1]), self._serverUpCount)
                    self.assertTrue(parts[2].isdigit())
                    self.assertTrue(int(parts[2]) <= int(after))
                else:
                    self.assertEquals(len(parts), 3)
                    self.assertTrue(parts[1].isdigit())
                    self.assertEquals(int(parts[1]), self._serverCount)
                    self.assertTrue(parts[2].isdigit())
                    self.assertTrue(int(parts[2]) <= int(after))
