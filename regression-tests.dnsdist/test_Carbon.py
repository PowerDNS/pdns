#!/usr/bin/env python
import Queue
import threading
import socket
import sys
import time
from dnsdisttests import DNSDistTest

class TestCarbon(DNSDistTest):

    _carbonServer1Port = 8000
    _carbonServer1Name = "carbonname1"
    _carbonServer2Port = 8001
    _carbonServer2Name = "carbonname2"
    _carbonQueue1 = Queue.Queue()
    _carbonQueue2 = Queue.Queue()
    _carbonInterval = 2
    _carbonCounters = {}
    _config_params = ['_carbonServer1Port', '_carbonServer1Name', '_carbonInterval', '_carbonServer2Port', '_carbonServer2Name', '_carbonInterval']
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
            lines = ""
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
    def startResponders(cls):
        cls._CarbonResponder1 = threading.Thread(name='Carbon Responder 1', target=cls.CarbonResponder, args=[cls._carbonServer1Port])
        cls._CarbonResponder1.setDaemon(True)
        cls._CarbonResponder1.start()

        cls._CarbonResponder2 = threading.Thread(name='Carbon Responder 2', target=cls.CarbonResponder, args=[cls._carbonServer2Port])
        cls._CarbonResponder2.setDaemon(True)
        cls._CarbonResponder2.start()

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
        expectedStart = "dnsdist." + self._carbonServer1Name + ".main."
        for line in data1.splitlines():
            self.assertTrue(line.startswith(expectedStart))
            parts = line.split(' ')
            self.assertEquals(len(parts), 3)
            self.assertTrue(parts[1].isdigit())
            self.assertTrue(parts[2].isdigit())
            self.assertTrue(int(parts[2]) <= int(after))

        self.assertTrue(data2)
        self.assertTrue(len(data2.splitlines()) > 1)
        expectedStart = "dnsdist." + self._carbonServer2Name + ".main."
        for line in data2.splitlines():
            self.assertTrue(line.startswith(expectedStart))
            parts = line.split(' ')
            self.assertEquals(len(parts), 3)
            self.assertTrue(parts[1].isdigit())
            self.assertTrue(parts[2].isdigit())
            self.assertTrue(int(parts[2]) <= int(after))

        # make sure every carbon server has received at least one connection
        for key in self._carbonCounters:
            value = self._carbonCounters[key]
            self.assertTrue(value >= 1)
