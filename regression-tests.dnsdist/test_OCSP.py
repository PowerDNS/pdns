#!/usr/bin/env python
import base64
import os
import subprocess
import unittest
from dnsdisttests import DNSDistTest, pickAvailablePort

class DNSDistOCSPStaplingTest(DNSDistTest):

    @classmethod
    def checkOCSPStaplingStatus(cls, addr, port, serverName, caFile):
        testcmd = ['openssl', 's_client', '-CAfile', caFile, '-connect', '%s:%d' % (addr, port), '-status', '-servername', serverName ]
        output = None
        try:
            process = subprocess.Popen(testcmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
            output = process.communicate(input='')
        except subprocess.CalledProcessError as exc:
            raise AssertionError('openssl s_client failed (%d): %s' % (exc.returncode, exc.output))

        return output[0].decode()

    @classmethod
    def getOCSPSerial(cls, output):
        serialNumber = None
        for line in output.splitlines():
            line = line.strip()
            print(line)
            if line.startswith('Serial Number:'):
                (_, serialNumber) = line.split(':')
                break

        return serialNumber

    def getTLSProvider(self):
        return self.sendConsoleCommand("getBind(0):getEffectiveTLSProvider()").rstrip()

    @classmethod
    def setUpClass(cls):
        cls.generateNewCertificateAndKey('server-ocsp')
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

@unittest.skipIf('SKIP_DOH_TESTS' in os.environ, 'DNS over HTTPS tests are disabled')
class TestOCSPStaplingDOH(DNSDistOCSPStaplingTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server-ocsp.key'
    _serverCert = 'server-ocsp.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _ocspFile = 'server.ocsp'
    _caCert = 'ca.pem'
    _caKey = 'ca.key'
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _dohWithH2OServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    -- generate an OCSP response file for our certificate, valid one day
    generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { ocspResponses={"%s"}, library='nghttp2'})
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { ocspResponses={"%s"}, library='h2o'})
    """
    _config_params = ['_testServerPort', '_consoleKeyB64', '_consolePort', '_serverCert', '_caCert', '_caKey', '_ocspFile', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_ocspFile', '_dohWithH2OServerPort', '_serverCert', '_serverKey', '_ocspFile']

    @classmethod
    def setUpClass(cls):

        # for some reason, @unittest.skipIf() is not applied to derived classes with some versions of Python
        if 'SKIP_DOH_TESTS' in os.environ:
            raise unittest.SkipTest('DNS over HTTPS tests are disabled')

        cls.generateNewCertificateAndKey('server-ocsp')
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testOCSPStapling(self):
        """
        OCSP Stapling: DOH
        """
        for port in [self._dohWithNGHTTP2ServerPort, self._dohWithH2OServerPort]:
            output = self.checkOCSPStaplingStatus('127.0.0.1', port, self._serverName, self._caCert)
            self.assertIn('OCSP Response Status: successful (0x0)', output)

            serialNumber = self.getOCSPSerial(output)
            self.assertTrue(serialNumber)

            self.generateNewCertificateAndKey('server-ocsp')
            self.sendConsoleCommand("generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)" % (self._serverCert, self._caCert, self._caKey, self._ocspFile))
            self.sendConsoleCommand("reloadAllCertificates()")

            output = self.checkOCSPStaplingStatus('127.0.0.1', port, self._serverName, self._caCert)
            self.assertIn('OCSP Response Status: successful (0x0)', output)
            serialNumber2 = self.getOCSPSerial(output)
            self.assertTrue(serialNumber2)
            self.assertNotEqual(serialNumber, serialNumber2)

class TestBrokenOCSPStaplingDoH(DNSDistOCSPStaplingTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server-ocsp.key'
    _serverCert = 'server-ocsp.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    # invalid OCSP file!
    _ocspFile = '/dev/null'
    _dohWithNGHTTP2ServerPort = pickAvailablePort()
    _dohWithH2OServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { ocspResponses={"%s"}, library='nghttp2'})
    addDOHLocal("127.0.0.1:%d", "%s", "%s", { "/" }, { ocspResponses={"%s"}, library='h2o'})

    """
    _config_params = ['_testServerPort', '_consoleKeyB64', '_consolePort', '_dohWithNGHTTP2ServerPort', '_serverCert', '_serverKey', '_ocspFile', '_dohWithH2OServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testBrokenOCSPStapling(self):
        """
        OCSP Stapling: Broken (DoH)
        """
        for port in [self._dohWithNGHTTP2ServerPort, self._dohWithH2OServerPort]:
            output = self.checkOCSPStaplingStatus('127.0.0.1', port, self._serverName, self._caCert)
            self.assertNotIn('OCSP Response Status: successful (0x0)', output)

class TestOCSPStaplingTLSGnuTLS(DNSDistOCSPStaplingTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server-ocsp.key'
    _serverCert = 'server-ocsp.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _ocspFile = 'server.ocsp'
    _caCert = 'ca.pem'
    _caKey = 'ca.key'
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    -- generate an OCSP response file for our certificate, valid one day
    generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="gnutls", ocspResponses={"%s"}})
    """
    _config_params = ['_testServerPort', '_consoleKeyB64', '_consolePort', '_serverCert', '_caCert', '_caKey', '_ocspFile', '_tlsServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testOCSPStapling(self):
        """
        OCSP Stapling: TLS (GnuTLS)
        """
        output = self.checkOCSPStaplingStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertIn('OCSP Response Status: successful (0x0)', output)
        self.assertEqual(self.getTLSProvider(), "gnutls")

        serialNumber = self.getOCSPSerial(output)
        self.assertTrue(serialNumber)

        self.generateNewCertificateAndKey('server-ocsp')
        self.sendConsoleCommand("generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)" % (self._serverCert, self._caCert, self._caKey, self._ocspFile))
        self.sendConsoleCommand("reloadAllCertificates()")

        output = self.checkOCSPStaplingStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertIn('OCSP Response Status: successful (0x0)', output)
        serialNumber2 = self.getOCSPSerial(output)
        self.assertTrue(serialNumber2)
        self.assertNotEqual(serialNumber, serialNumber2)

class TestBrokenOCSPStaplingTLSGnuTLS(DNSDistOCSPStaplingTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server-ocsp.key'
    _serverCert = 'server-ocsp.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    # invalid OCSP file!
    _ocspFile = '/dev/null'
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="gnutls", ocspResponses={"%s"}})
    """
    _config_params = ['_testServerPort', '_consoleKeyB64', '_consolePort', '_tlsServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testBrokenOCSPStapling(self):
        """
        OCSP Stapling: Broken (GnuTLS)
        """
        output = self.checkOCSPStaplingStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertNotIn('OCSP Response Status: successful (0x0)', output)
        self.assertEqual(self.getTLSProvider(), "gnutls")

class TestOCSPStaplingTLSOpenSSL(DNSDistOCSPStaplingTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server-ocsp.key'
    _serverCert = 'server-ocsp.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _ocspFile = 'server.ocsp'
    _caCert = 'ca.pem'
    _caKey = 'ca.key'
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    -- generate an OCSP response file for our certificate, valid one day
    generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)
    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl", ocspResponses={"%s"}})
    """
    _config_params = ['_testServerPort', '_consoleKeyB64', '_consolePort', '_serverCert', '_caCert', '_caKey', '_ocspFile', '_tlsServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testOCSPStapling(self):
        """
        OCSP Stapling: TLS (OpenSSL)
        """
        output = self.checkOCSPStaplingStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertIn('OCSP Response Status: successful (0x0)', output)
        self.assertEqual(self.getTLSProvider(), "openssl")

        serialNumber = self.getOCSPSerial(output)
        self.assertTrue(serialNumber)

        self.generateNewCertificateAndKey('server-ocsp')
        self.sendConsoleCommand("generateOCSPResponse('%s', '%s', '%s', '%s', 1, 0)" % (self._serverCert, self._caCert, self._caKey, self._ocspFile))
        self.sendConsoleCommand("reloadAllCertificates()")

        output = self.checkOCSPStaplingStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertIn('OCSP Response Status: successful (0x0)', output)
        serialNumber2 = self.getOCSPSerial(output)
        self.assertTrue(serialNumber2)
        self.assertNotEqual(serialNumber, serialNumber2)

class TestBrokenOCSPStaplingTLSOpenSSL(DNSDistOCSPStaplingTest):

    _consoleKey = DNSDistTest.generateConsoleKey()
    _consoleKeyB64 = base64.b64encode(_consoleKey).decode('ascii')
    _serverKey = 'server-ocsp.key'
    _serverCert = 'server-ocsp.chain'
    _serverName = 'tls.tests.dnsdist.org'
    _caCert = 'ca.pem'
    # invalid OCSP file!
    _ocspFile = '/dev/null'
    _tlsServerPort = pickAvailablePort()
    _config_template = """
    newServer{address="127.0.0.1:%d"}
    setKey("%s")
    controlSocket("127.0.0.1:%d")

    addTLSLocal("127.0.0.1:%d", "%s", "%s", { provider="openssl", ocspResponses={"%s"}})
    """
    _config_params = ['_testServerPort', '_consoleKeyB64', '_consolePort', '_tlsServerPort', '_serverCert', '_serverKey', '_ocspFile']

    def testBrokenOCSPStapling(self):
        """
        OCSP Stapling: Broken (OpenSSL)
        """
        output = self.checkOCSPStaplingStatus('127.0.0.1', self._tlsServerPort, self._serverName, self._caCert)
        self.assertNotIn('OCSP Response Status: successful (0x0)', output)
        self.assertEqual(self.getTLSProvider(), "openssl")
