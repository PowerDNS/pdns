#!/usr/bin/env python
import dns
import ssl
import threading
import time
import random

from dnsdisttests import DNSDistTest, pickAvailablePort

class TestOpenSSLErrorQueue(DNSDistTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()

    _config_template = """
    newServer{address="127.0.0.1:%d"}
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl"})
    """
    _config_params = ["_testServerPort", "_tlsServerPort", "_serverCert", "_serverKey"]

    def abortingWorker(self, ctx, duration):
        stop = time.time() + duration
        while time.time() < stop:
            try:
                conn = self.openTLSConnection(self._tlsServerPort, self._serverName, sslctx=ctx)
                time.sleep(random.uniform(0, 0.5))
                conn.sendall(b"\x00")
                time.sleep(random.uniform(0, 0.3))
                conn.close()
            except Exception:
                conn.close()
                pass

    def testSimple(self):
        """
        DoT: Test OpenSSL concurrent connections (see issue #18145)
        """
        name = "openssl-concurrent-connections.openssl-error-queue.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)

        # create the SSL context
        ctx = ssl.create_default_context(cafile=self._caCert)

        duration = 10 # 10 seconds
        workers = []
        # these threads are constantly opening and aborting TLS connections, to clobber the OpenSSL per-thread error queue
        for _ in range(40):
            worker = threading.Thread(target=self.abortingWorker, daemon=True, args=[ctx, duration])
            worker.start()
            workers.append(worker)

        closed = 0
        for run in range(8):
            conn = self.openTLSConnection(self._tlsServerPort, self._serverName, sslctx=ctx)
            for i in range(10):
                try:
                    self.sendTCPQueryOverConnection(conn, query, response=response, timeout=2)
                    (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True, timeout=2)
                    self.assertTrue(receivedQuery)
                    self.assertTrue(receivedResponse)
                    receivedQuery.id = query.id
                    self.assertEqual(query, receivedQuery)
                    self.assertEqual(response, receivedResponse)
                except Exception as e:
                    closed += 1
                    print(f"run {run}: connection closed by server before query {i}: {e}")
                    raise
                time.sleep(0.1)
            conn.close()
        print(f"{closed}/8 connections closed by server")
        self.assertEqual(closed, 0)

        [worker.join() for worker in workers]
