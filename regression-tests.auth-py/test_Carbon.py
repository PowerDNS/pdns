#!/usr/bin/env python
import threading
import socket
import sys
import time
from queue import Queue

from authtests import AuthTest

class TestCarbon(AuthTest):
    _carbonNamespace = 'NS'
    _carbonInstance = 'Instance'
    _carbonServerName = "carbonname1"
    _carbonInterval = 2
    _carbonServer1Port = 8000
    _carbonServer2Port = 8001
    _carbonQueue1 = Queue()
    _carbonQueue2 = Queue()
    _carbonCounters = {}
    _config_template = """
    launch={backend}
    carbon-namespace=%s
    carbon-instance=%s
    carbon-interval=%s
    carbon-ourname=%s
    carbon-server=127.0.0.1:%s,127.0.01:%s
    """ % (_carbonNamespace, _carbonInstance, _carbonInterval, _carbonServerName, _carbonServer1Port,  _carbonServer2Port)

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

        # check if the servers have received our data
        # we will block for a short while if the data is not already there,
        # and an exception will be raised after the timeout
        # first server
        data1 = self._carbonQueue1.get(block=True, timeout=2.0)
        # second server
        data2 = self._carbonQueue2.get(block=True, timeout=2.0)
        after = time.time()

        self.assertTrue(data1)
        self.assertTrue(len(data1.splitlines()) > 1)
        expectedStart = b"%s.%s.%s." % (self._carbonNamespace.encode('UTF8'), self._carbonServerName.encode('UTF-8'), self._carbonInstance.encode('UTF8'))
        for line in data1.splitlines():
            self.assertTrue(line.startswith(expectedStart))
            parts = line.split(b' ')
            self.assertEqual(len(parts), 3)
            self.assertTrue(parts[1].isdigit())
            self.assertTrue(parts[2].isdigit())
            self.assertTrue(int(parts[2]) <= int(after))

        self.assertTrue(data2)
        self.assertTrue(len(data2.splitlines()) > 1)
        expectedStart = b"%s.%s.%s." % (self._carbonNamespace.encode('UTF8'), self._carbonServerName.encode('UTF-8'), self._carbonInstance.encode('UTF8'))
        for line in data2.splitlines():
            self.assertTrue(line.startswith(expectedStart))
            parts = line.split(b' ')
            self.assertEqual(len(parts), 3)
            self.assertTrue(parts[1].isdigit())
            self.assertTrue(parts[2].isdigit())
            self.assertTrue(int(parts[2]) <= int(after))

        # make sure every carbon server has received at least one connection
        for key in self._carbonCounters:
            value = self._carbonCounters[key]
            self.assertTrue(value >= 1)

