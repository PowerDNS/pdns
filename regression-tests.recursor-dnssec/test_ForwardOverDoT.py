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
dnssec:
    validation: validate
recursor:
    forward_zones_recurse:
    - zone: .
      forwarders: [1.1.1.1:853,8.8.8.8:853,9.9.9.9:853]
    devonly_regression_test_mode: true
outgoing:
    tcp_max_queries: 1
    dont_throttle_netmasks: [0.0.0.0/0, '::/0']
"""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(SimpleForwardOverDoTTest, cls).generateRecursorYamlConfig(confdir, False)

    def reloadConfig(self, config):
      confdir = os.path.join('configs', SimpleForwardOverDoTTest._confdir)
      SimpleForwardOverDoTTest._config_template = config
      SimpleForwardOverDoTTest.generateRecursorYamlConfig(confdir, False)
      SimpleForwardOverDoTTest.recControl(confdir, 'reload-yaml')

    @pytest.mark.external
    def testBasic(self):
        confdir = 'configs/' + self._confdir
        self.reloadConfig(self._config_template)
        self.recControl(confdir, 'reload-zones')
        expected = dns.rrset.from_text('dns.google.', 0, dns.rdataclass.IN, 'A', '8.8.8.8', '8.8.4.4')
        query = dns.message.make_query('dns.google', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        ret = self.recControl(confdir, 'get', 'dot-outqueries')
        self.assertNotEqual(ret, 'UNKNOWN\n')
        self.assertNotEqual(ret, '0\n')

        ret = self.recControl(confdir, 'get', 'tcp-outqueries')
        self.assertEqual(ret, '0\n')

    _config_template_test2 = """
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
    tcp_max_queries: 1
    dont_throttle_netmasks: [0.0.0.0/0, '::/0']
recursor:
    forward_zones_recurse:
    - zone: .
      forwarders: [1.1.1.1:853,8.8.8.8:853,9.9.9.9:853]
    devonly_regression_test_mode: true
    """

    @pytest.mark.external
    def testWithVerify(self):
        confdir = 'configs/' + self._confdir
        self.reloadConfig(self._config_template_test2)
        self.recControl(confdir, 'reload-zones')
        expected = dns.rrset.from_text('dns.google.', 0, dns.rdataclass.IN, 'A', '8.8.8.8', '8.8.4.4')
        query = dns.message.make_query('dns.google', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

        ret = self.recControl(confdir, 'get', 'dot-outqueries')
        self.assertNotEqual(ret, 'UNKNOWN\n')
        self.assertNotEqual(ret, '0\n')

        ret = self.recControl(confdir, 'get', 'tcp-outqueries')
        self.assertEqual(ret, '0\n')

    _config_template_test3 = """
dnssec:
    validation: validate
outgoing:
    tls_configurations:
    - name: fwtopublic
      subnets: [1.1.1.1,9.9.9.9]
      validate_certificate: true
      verbose_logging: true
      subject_name: WRONG
    - name: fwtogoogle
      subnets: [8.8.8.8]
      subject_name: dns.googleXXX
      validate_certificate: true
      verbose_logging: true
    tcp_max_queries: 1
    dont_throttle_netmasks: [0.0.0.0/0, '::/0']
recursor:
    forward_zones_recurse:
    - zone: .
      forwarders: [1.1.1.1:853,8.8.8.8:853,9.9.9.9:853]
    devonly_regression_test_mode: true
    """

    @pytest.mark.external
    def testCertFailed(self):
        confdir = 'configs/' + self._confdir
        self.reloadConfig(self._config_template_test3)
        self.recControl(confdir, 'reload-zones')
        expected = dns.rrset.from_text('dns.google.', 0, dns.rdataclass.IN, 'A', '8.8.8.8', '8.8.4.4')
        query = dns.message.make_query('dns.google', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
