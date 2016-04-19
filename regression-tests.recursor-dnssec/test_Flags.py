from recursortests import RecursorTest
import dns
import os
import socket
import unittest

class TestFlags(RecursorTest):
    _confdir = 'Flags'
    _config_template = """dnssec=%s"""
    _config_params = ['_dnssec_setting']
    _dnssec_setting = None
    _recursors = {}

    _dnssec_setting_ports = {'off': 5300, 'process': 5301, 'validate': 5302}

    @classmethod
    def setUp(self):
        for setting in self._dnssec_setting_ports:
            confdir = os.path.join('configs', self._confdir, setting)
            self.wipeRecursorCache(confdir)

    @classmethod
    def setUpClass(self):
        self.setUpSockets()
        confdir = os.path.join('configs', self._confdir)
        self.createConfigDir(confdir)

        self.generateAllAuthConfig(confdir)
        self.startAllAuth(confdir)

        for dnssec_setting, port in self._dnssec_setting_ports.items():
            self._dnssec_setting = dnssec_setting
            recConfdir = os.path.join(confdir, dnssec_setting)
            self.createConfigDir(recConfdir)
            self.generateRecursorConfig(recConfdir)
            self.startRecursor(recConfdir, port)
            self._recursors[dnssec_setting] = self._recursor

    @classmethod
    def setUpSockets(self):
        self._sock = {}
        for dnssec_setting, port in self._dnssec_setting_ports.items():
            print("Setting up UDP socket..")
            self._sock[dnssec_setting] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock[dnssec_setting].settimeout(2.0)
            self._sock[dnssec_setting].connect(("127.0.0.1", port))

    @classmethod
    def sendUDPQuery(self, query, dnssec_setting, timeout=2.0):
        if timeout:
            self._sock[dnssec_setting].settimeout(timeout)

        try:
            self._sock[dnssec_setting].send(query.to_wire())
            data = self._sock[dnssec_setting].recv(4096)
        except socket.timeout:
            data = None
        finally:
            if timeout:
                self._sock[dnssec_setting].settimeout(None)

        msg = None
        if data:
            msg = dns.message.from_wire(data)
        return msg

    @classmethod
    def tearDownClass(self):
        self.tearDownAuth()
        for _, recursor in self._recursors.items():
            self._recursor = recursor
            self.tearDownRecursor()

    def createQuery(self, name, rdtype, flags, ednsflags):
        """Helper function that creates the query with the specified flags.
        The flags need to be strings (no checking is performed atm)"""
        msg = dns.message.make_query(name, rdtype)
        msg.flags = dns.flags.from_text(flags)
        msg.flags += dns.flags.from_text('RD')
        msg.use_edns(edns=0, ednsflags=dns.flags.edns_from_text(ednsflags))
        return msg

    def getQueryForSecure(self, flags='', ednsflags=''):
        return self.createQuery('ns1.example.net.', 'A', flags, ednsflags)

    ##
    #   -AD -CD -DO
    ##
    def testOff_Secure_None(self):
        msg = self.getQueryForSecure()
        res = self.sendUDPQuery(msg, 'off')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcess_Secure_None(self):
        msg = self.getQueryForSecure()
        res = self.sendUDPQuery(msg, 'process')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testValidate_Secure_None(self):
        msg = self.getQueryForSecure()
        res = self.sendUDPQuery(msg, 'validate')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    ##
    # +AD -CD -DO
    ##
    @unittest.skip("See #3682")
    def testOff_Secure_AD(self):
        msg = self.getQueryForSecure('AD')
        res = self.sendUDPQuery(msg, 'off')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])

        # Raises because #3682
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testProcess_Secure_AD(self):
        msg = self.getQueryForSecure('AD')
        res = self.sendUDPQuery(msg, 'process')
        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD','QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testValidate_Secure_AD(self):
        msg = self.getQueryForSecure('AD')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'RD', 'RA', 'QR'])
        # Raises because #3682
        self.assertNoRRSIGsInAnswer(res)

    ##
    # +AD -CD +DO
    ##
    def testOff_Secure_ADDO(self):
        msg = self.getQueryForSecure('AD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testProcess_Secure_ADDO(self):
        msg = self.getQueryForSecure('AD', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Secure_ADDO(self):
        msg = self.getQueryForSecure('AD', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # +AD +CD +DO
    ##
    def testOff_Secure_ADDOCD(self):
        msg = self.getQueryForSecure('AD CD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])

    def testProcess_Secure_ADDOCD(self):
        msg = self.getQueryForSecure('AD CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Secure_ADDOCD(self):
        msg = self.getQueryForSecure('AD CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # -AD -CD +DO
    ##
    def testOff_Secure_DO(self):
        msg = self.getQueryForSecure('', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testProcess_Secure_DO(self):
        msg = self.getQueryForSecure('', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    @unittest.skip("See #3682")
    def testValidate_Secure_DO(self):
        msg = self.getQueryForSecure('', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # -AD +CD +DO
    ##
    @unittest.skip("See #3682")
    def testOff_Secure_DOCD(self):
        msg = self.getQueryForSecure('CD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testProcess_Secure_DOCD(self):
        msg = self.getQueryForSecure('CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    @unittest.skip("See #3682")
    def testValidate_Secure_DOCD(self):
        msg = self.getQueryForSecure('CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # -AD +CD -DO
    ##
    @unittest.skip("See #3682")
    def testOff_Secure_CD(self):
        msg = self.getQueryForSecure('CD')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testProcess_Secure_CD(self):
        msg = self.getQueryForSecure('CD')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    @unittest.skip("See #3682")
    def testValidate_Secure_CD(self):
        msg = self.getQueryForSecure('CD')
        expected = dns.rrset.from_text('ns1.example.net.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)
        self.assertNoRRSIGsInAnswer(res)
