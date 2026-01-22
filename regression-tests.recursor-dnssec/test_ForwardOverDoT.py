import pytest
import dns
import os
import subprocess
from recursortests import RecursorTest

class SimpleForwardOverDoTTest(RecursorTest):
    """
    This is forwarding to DoT servers in a very basic way and is dependent on the forwards working for DoT
    """

    _confdir = 'SimpleForwardOverDoT'
    _config_template = """
dnssec=validate
forward-zones-recurse=.=1.1.1.1:853;8.8.8.8:853;9.9.9.9:853
devonly-regression-test-mode
    """

    @pytest.mark.external
    def testA(self):
        expected = dns.rrset.from_text('dns.google.', 0, dns.rdataclass.IN, 'A', '8.8.8.8', '8.8.4.4')
        query = dns.message.make_query('dns.google', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        confdir = 'configs/' + self._confdir
        ret = self.recControl(confdir, 'get', 'dot-outqueries')
        self.assertNotEqual(ret, 'UNKNOWN\n')
        self.assertNotEqual(ret, '0\n')

        ret = self.recControl(confdir, 'get', 'tcp-outqueries')
        self.assertEqual(ret, '0\n')

class ForwardOverDoTTest(RecursorTest):
    """
    This is forwarding to DoT servers with validation and is dependent on the forwards working for DoT
    """

    _confdir = 'ForwardOverDoT'
    _config_template = """
dnssec:
    validation: validate
outgoing:
    tls_configurations:
    - name: fwtopublic
      subnets: [1.1.1.1,9.9.9.9]
      validate_certificate: true
      verbose_logging: true
    - name: fwtogoogle
      subnets: [8.8.8.8]
      subject_name: dns.google
      validate_certificate: true
      verbose_logging: true
recursor:
    forward_zones_recurse:
    - zone: .
      forwarders: [1.1.1.1:853,8.8.8.8:853,9.9.9.9:853]
    devonly_regression_test_mode: true
    """

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ForwardOverDoTTest, cls).generateRecursorYamlConfig(confdir, False)

    @pytest.mark.external
    def testA(self):
        expected = dns.rrset.from_text('dns.google.', 0, dns.rdataclass.IN, 'A', '8.8.8.8', '8.8.4.4')
        query = dns.message.make_query('dns.google', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        confdir = 'configs/' + self._confdir
        ret = self.recControl(confdir, 'get', 'dot-outqueries')
        self.assertNotEqual(ret, 'UNKNOWN\n')
        self.assertNotEqual(ret, '0\n')

        ret = self.recControl(confdir, 'get', 'tcp-outqueries')
        self.assertEqual(ret, '0\n')

