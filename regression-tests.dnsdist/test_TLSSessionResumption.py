#!/usr/bin/env python
import base64
import dns
import os
import requests
import shutil
import ssl
import subprocess
import tempfile
import time
import unittest
from dnsdisttests import DNSDistTest, pickAvailablePort

try:
    range = xrange
except NameError:
    pass


class DNSDistTLSSessionResumptionTest(DNSDistTest):
    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode("ascii")

    @classmethod
    def checkSessionResumed(cls, addr, port, serverName, caFile, ticketFileOut, ticketFileIn, allowNoTicket=False):
        outFile = tempfile.NamedTemporaryFile()

        # we force TLS 1.3 because the session file gets updated when an existing ticket encrypted with an older key gets re-encrypted with the active key
        # whereas in TLS 1.2 the existing ticket is written instead..
        testcmd = [
            "openssl",
            "s_client",
            "-tls1_3",
            "-CAfile",
            caFile,
            "-connect",
            "%s:%d" % (addr, port),
            "-servername",
            serverName,
            "-sess_out",
            outFile.name,
        ]
        if ticketFileIn and os.path.exists(ticketFileIn):
            testcmd = testcmd + ["-sess_in", ticketFileIn]

        output = None
        try:
            process = subprocess.Popen(
                testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True
            )
            # we need to wait just a bit so that the Post-Handshake New Session Ticket has the time to arrive..
            time.sleep(0.5)
            output = process.communicate(input=b"")
        except subprocess.CalledProcessError as exc:
            raise AssertionError("%s failed (%d): %s" % (testcmd, process.returncode, process.output))

        if process.returncode != 0:
            raise AssertionError("%s failed (%d): %s" % (testcmd, process.returncode, output))

        if os.stat(outFile.name).st_size == 0:
            # if tickets have been disabled, or if the session ticket encryption key is exactly the same, we might not get a new ticket
            if not allowNoTicket:
                raise AssertionError(
                    "%s failed (%d) to write a session to the output file: %s" % (testcmd, process.returncode, output)
                )
        else:
            shutil.copyfile(outFile.name, ticketFileOut)

        for line in output[0].decode().splitlines():
            if line.startswith("Reused, TLSv1."):
                return True

        return False

    @staticmethod
    def generateTicketKeysFile(numberOfTickets, outputFile):
        with open(outputFile, "wb") as fp:
            fp.write(os.urandom(numberOfTickets * 80))


@unittest.skipIf("SKIP_DOH_TESTS" in os.environ, "DNS over HTTPS tests are disabled")
class TestNoTLSSessionResumptionDOH(DNSDistTLSSessionResumptionTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _dohWithH2OServerPort = pickAvailablePort()
    _numberOfKeys = 0
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { numberOfTicketsKeys=%d, numberOfStoredSessions=0, sessionTickets=false, library='nghttp2' })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { numberOfTicketsKeys=%d, numberOfStoredSessions=0, sessionTickets=false, library='h2o' })
    """
    _config_params = [
        "_testServerPort",
        "_dohWithNGHTTP2ServerPort",
        "_serverCert",
        "_serverKey",
        "_numberOfKeys",
        "_dohWithH2OServerPort",
        "_serverCert",
        "_serverKey",
        "_numberOfKeys",
    ]

    def testNoSessionResumption(self):
        """
        Session Resumption: DoH (disabled)
        """
        for port in [self._dohWithNGHTTP2ServerPort, self._dohWithH2OServerPort]:
            self.assertFalse(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/no-session.out.doh",
                    None,
                    allowNoTicket=True,
                )
            )
            self.assertFalse(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/no-session.out.doh",
                    "/tmp/no-session.out.doh",
                    allowNoTicket=True,
                )
            )


@unittest.skipIf("SKIP_DOH_TESTS" in os.environ, "DNS over HTTPS tests are disabled")
class TestTLSSessionResumptionDOH(DNSDistTLSSessionResumptionTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _dohWithH2OServerPort = pickAvailablePort()
    _numberOfKeys = 5
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%d")
    newServer{address="127.0.0.1:%d"}

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { numberOfTicketsKeys=%d, library='nghttp2' })
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { numberOfTicketsKeys=%d, library='h2o' })
    """
    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_dohWithNGHTTP2ServerPort",
        "_serverCert",
        "_serverKey",
        "_numberOfKeys",
        "_dohWithH2OServerPort",
        "_serverCert",
        "_serverKey",
        "_numberOfKeys",
    ]

    def testSessionResumption(self):
        """
        Session Resumption: DoH
        """
        for port, bindIdx in [(self._dohWithNGHTTP2ServerPort, 0), (self._dohWithH2OServerPort, 1)]:
            self.assertFalse(
                self.checkSessionResumed("127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh", None)
            )
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/session.doh",
                    "/tmp/session.doh",
                    allowNoTicket=True,
                )
            )

            # rotate the TLS session ticket keys several times, but keep the previously active one around so we can resume
            for _ in range(self._numberOfKeys - 1):
                self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):rotateTicketsKey()")

            # the session should be resumed and a new ticket, encrypted with the newly active key, should be stored
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh", "/tmp/session.doh"
                )
            )

            # rotate the TLS session ticket keys several times, but keep the previously active one around so we can resume
            for _ in range(self._numberOfKeys - 1):
                self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):rotateTicketsKey()")

            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh", "/tmp/session.doh"
                )
            )

            # rotate the TLS session ticket keys several times, not keeping any key around this time!
            for _ in range(self._numberOfKeys):
                self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):rotateTicketsKey()")

            # we should not be able to resume
            self.assertFalse(
                self.checkSessionResumed(
                    "127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh", "/tmp/session.doh"
                )
            )

            # generate a file containing _numberOfKeys ticket keys
            self.generateTicketKeysFile(self._numberOfKeys, "/tmp/ticketKeys.1")
            self.generateTicketKeysFile(self._numberOfKeys - 1, "/tmp/ticketKeys.2")
            # load all ticket keys from the file
            self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):loadTicketsKeys('/tmp/ticketKeys.1')")

            # create a new session, resume it
            self.assertFalse(
                self.checkSessionResumed("127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh", None)
            )
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/session.doh",
                    "/tmp/session.doh",
                    allowNoTicket=True,
                )
            )

            # reload the same keys
            self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):loadTicketsKeys('/tmp/ticketKeys.1')")

            # should still be able to resume
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/session.doh",
                    "/tmp/session.doh",
                    allowNoTicket=True,
                )
            )

            # rotate the TLS session ticket keys several times, but keep the previously active one around so we can resume
            for _ in range(self._numberOfKeys - 1):
                self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):rotateTicketsKey()")
            # should still be able to resume
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh", "/tmp/session.doh"
                )
            )

            # reload the same keys
            self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):loadTicketsKeys('/tmp/ticketKeys.1')")
            # since the last key was only present in memory, we should not be able to resume
            self.assertFalse(
                self.checkSessionResumed(
                    "127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh", "/tmp/session.doh"
                )
            )

            # but now we can
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/session.doh",
                    "/tmp/session.doh",
                    allowNoTicket=True,
                )
            )

            # generate a file with only _numberOfKeys - 1 keys, so the last active one should still be around after loading that one
            self.generateTicketKeysFile(self._numberOfKeys - 1, "/tmp/ticketKeys.2")
            self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):loadTicketsKeys('/tmp/ticketKeys.2')")
            # we should be able to resume, and the ticket should be re-encrypted with the new key (NOTE THAT we store into a new file!!)
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh.2", "/tmp/session.doh"
                )
            )
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/session.doh.2",
                    "/tmp/session.doh.2",
                    allowNoTicket=True,
                )
            )

            # rotate all keys, we should not be able to resume
            for _ in range(self._numberOfKeys):
                self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):rotateTicketsKey()")
            self.assertFalse(
                self.checkSessionResumed(
                    "127.0.0.1", port, self._serverName, self._caCert, "/tmp/session.doh.3", "/tmp/session.doh.2"
                )
            )

            # reload from file 1, the old session should resume
            self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):loadTicketsKeys('/tmp/ticketKeys.1')")
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/session.doh",
                    "/tmp/session.doh",
                    allowNoTicket=True,
                )
            )

            # reload from file 2, the latest session should resume
            self.sendConsoleCommand(f"getDOHFrontend({bindIdx}):loadTicketsKeys('/tmp/ticketKeys.2')")
            self.assertTrue(
                self.checkSessionResumed(
                    "127.0.0.1",
                    port,
                    self._serverName,
                    self._caCert,
                    "/tmp/session.doh.2",
                    "/tmp/session.doh.2",
                    allowNoTicket=True,
                )
            )


class TestNoTLSSessionResumptionDOT(DNSDistTLSSessionResumptionTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _numberOfKeys = 0
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { numberOfTicketsKeys=%d, numberOfStoredSessions=0, sessionTickets=false })
    """
    _config_params = ["_testServerPort", "_tlsServerPort", "_serverCert", "_serverKey", "_numberOfKeys"]

    def testNoSessionResumption(self):
        """
        Session Resumption: DoT (disabled)
        """
        self.assertFalse(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/no-session.out.dot",
                None,
                allowNoTicket=True,
            )
        )
        self.assertFalse(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/no-session.out.dot",
                "/tmp/no-session.out.dot",
                allowNoTicket=True,
            )
        )


class TestTLSSessionResumptionDOT(DNSDistTLSSessionResumptionTest):
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _numberOfKeys = 5
    _config_template = """
    setKey("%s")
    controlSocket("127.0.0.1:%s")
    newServer{address="127.0.0.1:%d"}

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl", numberOfTicketsKeys=%d })
    """
    _config_params = [
        "_consoleKeyB64",
        "_consolePort",
        "_testServerPort",
        "_tlsServerPort",
        "_serverCert",
        "_serverKey",
        "_numberOfKeys",
    ]

    def testSessionResumption(self):
        """
        Session Resumption: DoT
        """
        self.assertFalse(
            self.checkSessionResumed(
                "127.0.0.1", self._tlsServerPort, self._serverName, self._caCert, "/tmp/session.dot", None
            )
        )
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot",
                "/tmp/session.dot",
                allowNoTicket=True,
            )
        )

        # rotate the TLS session ticket keys several times, but keep the previously active one around so we can resume
        for _ in range(self._numberOfKeys - 1):
            self.sendConsoleCommand("getTLSFrontend(0):rotateTicketsKey()")

        # the session should be resumed and a new ticket, encrypted with the newly active key, should be stored
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1", self._tlsServerPort, self._serverName, self._caCert, "/tmp/session.dot", "/tmp/session.dot"
            )
        )

        # rotate the TLS session ticket keys several times, but keep the previously active one around so we can resume
        for _ in range(self._numberOfKeys - 1):
            self.sendConsoleCommand("getTLSFrontend(0):rotateTicketsKey()")

        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1", self._tlsServerPort, self._serverName, self._caCert, "/tmp/session.dot", "/tmp/session.dot"
            )
        )

        # rotate the TLS session ticket keys several times, not keeping any key around this time!
        for _ in range(self._numberOfKeys):
            self.sendConsoleCommand("getTLSFrontend(0):rotateTicketsKey()")

        # we should not be able to resume
        self.assertFalse(
            self.checkSessionResumed(
                "127.0.0.1", self._tlsServerPort, self._serverName, self._caCert, "/tmp/session.dot", "/tmp/session.dot"
            )
        )

        # generate a file containing _numberOfKeys ticket keys
        self.generateTicketKeysFile(self._numberOfKeys, "/tmp/ticketKeys.1")
        self.generateTicketKeysFile(self._numberOfKeys - 1, "/tmp/ticketKeys.2")
        # load all ticket keys from the file
        self.sendConsoleCommand("getTLSFrontend(0):loadTicketsKeys('/tmp/ticketKeys.1')")

        # create a new session, resume it
        self.assertFalse(
            self.checkSessionResumed(
                "127.0.0.1", self._tlsServerPort, self._serverName, self._caCert, "/tmp/session.dot", None
            )
        )
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot",
                "/tmp/session.dot",
                allowNoTicket=True,
            )
        )

        # reload the same keys
        self.sendConsoleCommand("getTLSFrontend(0):loadTicketsKeys('/tmp/ticketKeys.1')")

        # should still be able to resume
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot",
                "/tmp/session.dot",
                allowNoTicket=True,
            )
        )

        # rotate the TLS session ticket keys several times, but keep the previously active one around so we can resume
        for _ in range(self._numberOfKeys - 1):
            self.sendConsoleCommand("getTLSFrontend(0):rotateTicketsKey()")
        # should still be able to resume
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1", self._tlsServerPort, self._serverName, self._caCert, "/tmp/session.dot", "/tmp/session.dot"
            )
        )

        # reload the same keys
        self.sendConsoleCommand("getTLSFrontend(0):loadTicketsKeys('/tmp/ticketKeys.1')")
        # since the last key was only present in memory, we should not be able to resume
        self.assertFalse(
            self.checkSessionResumed(
                "127.0.0.1", self._tlsServerPort, self._serverName, self._caCert, "/tmp/session.dot", "/tmp/session.dot"
            )
        )

        # but now we can
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot",
                "/tmp/session.dot",
                allowNoTicket=True,
            )
        )

        # generate a file with only _numberOfKeys - 1 keys, so the last active one should still be around after loading that one
        self.generateTicketKeysFile(self._numberOfKeys - 1, "/tmp/ticketKeys.2")
        self.sendConsoleCommand("getTLSFrontend(0):loadTicketsKeys('/tmp/ticketKeys.2')")
        # we should be able to resume, and the ticket should be re-encrypted with the new key (NOTE THAT we store into a new file!!)
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot.2",
                "/tmp/session.dot",
            )
        )
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot.2",
                "/tmp/session.dot.2",
                allowNoTicket=True,
            )
        )

        # rotate all keys, we should not be able to resume
        for _ in range(self._numberOfKeys):
            self.sendConsoleCommand("getTLSFrontend(0):rotateTicketsKey()")
        self.assertFalse(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot.3",
                "/tmp/session.dot.2",
            )
        )

        # reload from file 1, the old session should resume
        self.sendConsoleCommand("getTLSFrontend(0):loadTicketsKeys('/tmp/ticketKeys.1')")
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot",
                "/tmp/session.dot",
                allowNoTicket=True,
            )
        )

        # reload from file 2, the latest session should resume
        self.sendConsoleCommand("getTLSFrontend(0):loadTicketsKeys('/tmp/ticketKeys.2')")
        self.assertTrue(
            self.checkSessionResumed(
                "127.0.0.1",
                self._tlsServerPort,
                self._serverName,
                self._caCert,
                "/tmp/session.dot.2",
                "/tmp/session.dot.2",
                allowNoTicket=True,
            )
        )


class TestTLSSessionResumptionDOTIdenticalFrontends(DNSDistTest):
    """
    Check that identical frontends share the same TLS session ticket encryption key
    """

    _webTimeout = 2.0
    _webServerPort = pickAvailablePort()
    _webServerBasicAuthPassword = "secret"
    _webServerAPIKey = "apisecret"
    _webServerBasicAuthPasswordHashed = (
        "$scrypt$ln=10,p=1,r=8$6DKLnvUYEeXWh3JNOd3iwg==$kSrhdHaRbZ7R74q3lGBqO1xetgxRxhmWzYJ2Qvfm7JM="
    )
    _webServerAPIKeyHashed = (
        "$scrypt$ln=10,p=1,r=8$9v8JxDfzQVyTpBkTbkUqYg==$bDQzAOHeK1G9UvTPypNhrX48w974ZXbFPtRKS34+aso="
    )
    _serverKey = "server.key"
    _serverCert = "server.chain"
    _serverName = "tls.tests.dnsdist.org"
    _caCert = "ca.pem"
    _tlsServerPort = pickAvailablePort()
    _numberOfIdenticalFrontends = 10
    _config_template = ""
    _config_params = []
    _yaml_config_template = """---
webserver:
  listen_addresses:
    - "127.0.0.1:%d"
  password: "%s"
  api_key: "%s"
  acl:
    - 127.0.0.0/8
backends:
  - address: "127.0.0.1:%d"
    protocol: "Do53"
binds:
  - listen_address: "127.0.0.1:%d"
    reuseport: true
    protocol: "DoT"
    threads: %d
    tls:
      certificates:
        - certificate: "%s"
          key: "%s"
      provider: "openssl"
    """
    _yaml_config_params = [
        "_webServerPort",
        "_webServerBasicAuthPasswordHashed",
        "_webServerAPIKeyHashed",
        "_testServerPort",
        "_tlsServerPort",
        "_numberOfIdenticalFrontends",
        "_serverCert",
        "_serverKey",
    ]

    def testTLSSessionResumptionAcrossIdenticalFrontends(self):
        """
        TCP Session Resumption: Check that identical frontends share the same STEK
        """
        name = "identical-frontends.tls-session-resumption.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        response = dns.message.make_response(query)

        session = None
        sslctx = ssl.create_default_context(cafile=self._caCert)
        nb_connections = self._numberOfIdenticalFrontends * 20
        for idx in range(nb_connections):
            conn = self.openTLSConnection(
                self._tlsServerPort, self._serverName, self._caCert, timeout=1, sslctx=sslctx, session=session
            )
            self.sendTCPQueryOverConnection(conn, query, response=response, timeout=1)
            (receivedQuery, receivedResponse) = self.recvTCPResponseOverConnection(conn, useQueue=True, timeout=1)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)
            if idx == 0:
                self.assertFalse(conn.session_reused)
                session = conn.session
            else:
                self.assertTrue(conn.session_reused)

        headers = {"x-api-key": self._webServerAPIKey}
        url = "http://127.0.0.1:" + str(self._webServerPort) + "/api/v1/servers/localhost"
        r = requests.get(url, headers=headers, timeout=self._webTimeout)
        self.assertTrue(r)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json())
        content = r.json()
        self.assertTrue(len(content["frontends"]), self._numberOfIdenticalFrontends + 2)

        new_sessions = 0
        resumed_sessions = 0
        tls_frontends_seen = {}
        for frontend in content["frontends"]:
            if frontend["type"] != "TCP (DNS over TLS)":
                continue
            new_sessions = new_sessions + int(frontend["tlsNewSessions"])
            resumed_sessions = resumed_sessions + int(frontend["tlsResumptions"])
            if int(frontend["tlsNewSessions"]) > 0 or int(frontend["tlsResumptions"]) > 0:
                tls_frontends_seen[frontend["id"]] = True

        self.assertEqual(new_sessions, 1)
        self.assertEqual(resumed_sessions, nb_connections - new_sessions)
        self.assertGreater(len(tls_frontends_seen), 1)
