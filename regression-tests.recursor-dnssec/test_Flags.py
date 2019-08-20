import os
import socket

import dns
from recursortests import RecursorTest


class TestFlags(RecursorTest):
    _confdir = 'Flags'
    _config_template = """dnssec=%s"""
    _config_params = ['_dnssec_setting']
    _dnssec_setting = None
    _recursors = {}

    _dnssec_setting_ports = {'off': 5300,
                             'process-no-validate': 5301,
                             'process': 5302,
                             'validate': 5303}

    @classmethod
    def setUp(cls):
        for setting in cls._dnssec_setting_ports:
            confdir = os.path.join('configs', cls._confdir, setting)
            cls.wipeRecursorCache(confdir)

    @classmethod
    def setUpClass(cls):
        cls.setUpSockets()
        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateAllAuthConfig(confdir)
        cls.startAllAuth(confdir)

        for dnssec_setting, port in cls._dnssec_setting_ports.items():
            cls._dnssec_setting = dnssec_setting
            recConfdir = os.path.join(confdir, dnssec_setting)
            cls.createConfigDir(recConfdir)
            cls.generateRecursorConfig(recConfdir)
            cls.startRecursor(recConfdir, port)
            cls._recursors[dnssec_setting] = cls._recursor

    @classmethod
    def setUpSockets(cls):
        cls._sock = {}
        for dnssec_setting, port in cls._dnssec_setting_ports.items():
            print("Setting up UDP socket..")
            cls._sock[dnssec_setting] = socket.socket(socket.AF_INET,
                                                      socket.SOCK_DGRAM)
            cls._sock[dnssec_setting].settimeout(2.0)
            cls._sock[dnssec_setting].connect(("127.0.0.1", port))

    @classmethod
    def sendUDPQuery(cls, query, dnssec_setting, timeout=2.0):
        if timeout:
            cls._sock[dnssec_setting].settimeout(timeout)

        try:
            cls._sock[dnssec_setting].send(query.to_wire())
            data = cls._sock[dnssec_setting].recv(4096)
        except socket.timeout:
            data = None
        finally:
            if timeout:
                cls._sock[dnssec_setting].settimeout(None)

        msg = None
        if data:
            msg = dns.message.from_wire(data)
        return msg

    @classmethod
    def tearDownClass(cls):
        cls.tearDownAuth()
        for _, recursor in cls._recursors.items():
            cls._recursor = recursor
            cls.tearDownRecursor()

    def getQueryForSecure(self, flags='', ednsflags=''):
        return self.createQuery('ns1.example.', 'A', flags, ednsflags)

    ##
    #   -AD -CD -DO
    ##
    def testOff_Secure_None(self):
        msg = self.getQueryForSecure()
        res = self.sendUDPQuery(msg, 'off')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Secure_None(self):
        msg = self.getQueryForSecure()
        res = self.sendUDPQuery(msg, 'process-no-validate')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcess_Secure_None(self):
        msg = self.getQueryForSecure()
        res = self.sendUDPQuery(msg, 'process')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testValidate_Secure_None(self):
        msg = self.getQueryForSecure()
        res = self.sendUDPQuery(msg, 'validate')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    ##
    # +AD -CD -DO
    ##
    def testOff_Secure_AD(self):
        msg = self.getQueryForSecure('AD')
        res = self.sendUDPQuery(msg, 'off')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])

        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Secure_AD(self):
        msg = self.getQueryForSecure('AD')
        res = self.sendUDPQuery(msg, 'process-no-validate')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcess_Secure_AD(self):
        msg = self.getQueryForSecure('AD')
        res = self.sendUDPQuery(msg, 'process')
        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testValidate_Secure_AD(self):
        msg = self.getQueryForSecure('AD')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'RD', 'RA', 'QR'])
        self.assertNoRRSIGsInAnswer(res)

    ##
    # +AD -CD +DO
    ##
    def testOff_Secure_ADDO(self):
        msg = self.getQueryForSecure('AD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Secure_ADDO(self):
        msg = self.getQueryForSecure('AD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testProcess_Secure_ADDO(self):
        msg = self.getQueryForSecure('AD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Secure_ADDO(self):
        msg = self.getQueryForSecure('AD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
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

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])

    def testProcessNoValidate_Secure_ADDOCD(self):
        msg = self.getQueryForSecure('AD CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testProcess_Secure_ADDOCD(self):
        msg = self.getQueryForSecure('AD CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageIsAuthenticated(res)
        self.assertMessageHasFlags(res, ['AD', 'CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Secure_ADDOCD(self):
        msg = self.getQueryForSecure('AD CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
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

    def testProcessNoValidate_Secure_DO(self):
        msg = self.getQueryForSecure('', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testProcess_Secure_DO(self):
        msg = self.getQueryForSecure('', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Secure_DO(self):
        msg = self.getQueryForSecure('', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # -AD +CD +DO
    ##
    def testOff_Secure_DOCD(self):
        msg = self.getQueryForSecure('CD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Secure_DOCD(self):
        msg = self.getQueryForSecure('CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testProcess_Secure_DOCD(self):
        msg = self.getQueryForSecure('CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Secure_DOCD(self):
        msg = self.getQueryForSecure('CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['AD', 'QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # -AD +CD -DO
    ##
    def testOff_Secure_CD(self):
        msg = self.getQueryForSecure('CD')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Secure_CD(self):
        msg = self.getQueryForSecure('CD')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    def testProcess_Secure_CD(self):
        msg = self.getQueryForSecure('CD')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    def testValidate_Secure_CD(self):
        msg = self.getQueryForSecure('CD')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)


    ### Bogus
    def getQueryForBogus(self, flags='', ednsflags=''):
        return self.createQuery('ted.bogus.example.', 'A', flags, ednsflags)

    ##
    #   -AD -CD -DO
    ##
    def testOff_Bogus_None(self):
        msg = self.getQueryForBogus()
        res = self.sendUDPQuery(msg, 'off')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Bogus_None(self):
        msg = self.getQueryForBogus()
        res = self.sendUDPQuery(msg, 'process-no-validate')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Bogus_None(self):
        msg = self.getQueryForBogus()
        res = self.sendUDPQuery(msg, 'process')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testValidate_Bogus_None(self):
        msg = self.getQueryForBogus()
        res = self.sendUDPQuery(msg, 'validate')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    ##
    # +AD -CD -DO
    ##
    def testOff_Bogus_AD(self):
        msg = self.getQueryForBogus('AD')
        res = self.sendUDPQuery(msg, 'off')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Bogus_AD(self):
        msg = self.getQueryForBogus('AD')
        res = self.sendUDPQuery(msg, 'process-no-validate')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Bogus_AD(self):
        msg = self.getQueryForBogus('AD')
        res = self.sendUDPQuery(msg, 'process')
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    def testValidate_Bogus_AD(self):
        msg = self.getQueryForBogus('AD')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['RD', 'RA', 'QR'])
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    ##
    # +AD -CD +DO
    ##
    def testOff_Bogus_ADDO(self):
        msg = self.getQueryForBogus('AD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Bogus_ADDO(self):
        msg = self.getQueryForBogus('AD', 'DO')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Bogus_ADDO(self):
        msg = self.getQueryForBogus('AD', 'DO')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    def testValidate_Bogus_ADDO(self):
        msg = self.getQueryForBogus('AD', 'DO')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)
    ##
    # +AD +CD +DO
    ##
    def testOff_Bogus_ADDOCD(self):
        msg = self.getQueryForBogus('AD CD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Bogus_ADDOCD(self):
        msg = self.getQueryForBogus('AD CD', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testProcess_Bogus_ADDOCD(self):
        msg = self.getQueryForBogus('AD CD', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Bogus_ADDOCD(self):
        msg = self.getQueryForBogus('AD CD', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # -AD -CD +DO
    ##
    def testOff_Bogus_DO(self):
        msg = self.getQueryForBogus('', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Bogus_DO(self):
        msg = self.getQueryForBogus('', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testProcess_Bogus_DO(self):
        msg = self.getQueryForBogus('', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    def testValidate_Bogus_DO(self):
        msg = self.getQueryForBogus('', 'DO')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertAnswerEmpty(res)

    ##
    # -AD +CD +DO
    ##
    def testOff_Bogus_DOCD(self):
        msg = self.getQueryForBogus('CD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Bogus_DOCD(self):
        msg = self.getQueryForBogus('CD', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testProcess_Bogus_DOCD(self):
        msg = self.getQueryForBogus('CD', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    def testValidate_Bogus_DOCD(self):
        msg = self.getQueryForBogus('CD', 'DO')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertMatchingRRSIGInAnswer(res, expected)

    ##
    # -AD +CD -DO
    ##
    def testOff_Bogus_CD(self):
        msg = self.getQueryForBogus('CD')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'off')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Bogus_CD(self):
        msg = self.getQueryForBogus('CD')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    def testProcess_Bogus_CD(self):
        msg = self.getQueryForBogus('CD')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'process')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)

    def testValidate_Bogus_CD(self):
        msg = self.getQueryForBogus('CD')
        expected = dns.rrset.from_text('ted.bogus.example.', 0, dns.rdataclass.IN, 'A', '192.0.2.1')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertRRsetInAnswer(res, expected)
        self.assertNoRRSIGsInAnswer(res)


    ## Insecure
    def getQueryForInsecure(self, flags='', ednsflags=''):
        return self.createQuery('node1.insecure.example.', 'A', flags, ednsflags)

    ##
    #   -AD -CD -DO
    ##
    def testOff_Insecure_None(self):
        msg = self.getQueryForInsecure()
        res = self.sendUDPQuery(msg, 'off')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcessNoValidate_Insecure_None(self):
        msg = self.getQueryForInsecure()
        res = self.sendUDPQuery(msg, 'process-no-validate')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testProcess_Insecure_None(self):
        msg = self.getQueryForInsecure()
        res = self.sendUDPQuery(msg, 'process')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    def testValidate_Insecure_None(self):
        msg = self.getQueryForInsecure()
        res = self.sendUDPQuery(msg, 'validate')
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)

    ##
    # +AD -CD -DO
    ##
    def testOff_Insecure_AD(self):
        msg = self.getQueryForInsecure('AD')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Insecure_AD(self):
        msg = self.getQueryForInsecure('AD')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Insecure_AD(self):
        msg = self.getQueryForInsecure('AD')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testValidate_Insecure_AD(self):
        msg = self.getQueryForInsecure('AD')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['RD', 'RA', 'QR'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    ##
    # +AD -CD +DO
    ##
    def testOff_Insecure_ADDO(self):
        msg = self.getQueryForInsecure('AD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Insecure_ADDO(self):
        msg = self.getQueryForInsecure('AD', 'DO')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Insecure_ADDO(self):
        msg = self.getQueryForInsecure('AD', 'DO')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testValidate_Insecure_ADDO(self):
        msg = self.getQueryForInsecure('AD', 'DO')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    ##
    # +AD +CD +DO
    ##
    def testOff_Insecure_ADDOCD(self):
        msg = self.getQueryForInsecure('AD CD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Insecure_ADDOCD(self):
        msg = self.getQueryForInsecure('AD CD', 'DO')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Insecure_ADDOCD(self):
        msg = self.getQueryForInsecure('AD CD', 'DO')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['CD', 'QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testValidate_Insecure_ADDOCD(self):
        msg = self.getQueryForInsecure('AD CD', 'DO')
        expected = dns.rrset.from_text('ns1.example.', 0, dns.rdataclass.IN, 'A', '{prefix}.10'.format(prefix=self._PREFIX))
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    ##
    # -AD -CD +DO
    ##
    def testOff_Insecure_DO(self):
        msg = self.getQueryForInsecure('', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Insecure_DO(self):
        msg = self.getQueryForInsecure('', 'DO')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Insecure_DO(self):
        msg = self.getQueryForInsecure('', 'DO')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testValidate_Insecure_DO(self):
        msg = self.getQueryForInsecure('', 'DO')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    ##
    # -AD +CD +DO
    ##
    def testOff_Insecure_DOCD(self):
        msg = self.getQueryForInsecure('CD', 'DO')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Insecure_DOCD(self):
        msg = self.getQueryForInsecure('CD', 'DO')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Insecure_DOCD(self):
        msg = self.getQueryForInsecure('CD', 'DO')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testValidate_Insecure_DOCD(self):
        msg = self.getQueryForInsecure('CD', 'DO')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'], ['DO'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    ##
    # -AD +CD -DO
    ##
    def testOff_Insecure_CD(self):
        msg = self.getQueryForInsecure('CD')
        res = self.sendUDPQuery(msg, 'off')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcessNoValidate_Insecure_CD(self):
        msg = self.getQueryForInsecure('CD')
        res = self.sendUDPQuery(msg, 'process-no-validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testProcess_Insecure_CD(self):
        msg = self.getQueryForInsecure('CD')
        res = self.sendUDPQuery(msg, 'process')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

    def testValidate_Insecure_CD(self):
        msg = self.getQueryForInsecure('CD')
        res = self.sendUDPQuery(msg, 'validate')

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD', 'CD'])
        self.assertNoRRSIGsInAnswer(res)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
