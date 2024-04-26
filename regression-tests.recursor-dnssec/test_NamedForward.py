import dns
import os
import unittest
import subprocess
import time
from recursortests import RecursorTest

class testNamedForward(RecursorTest):
    """
    This is forwarding test using a name as target
    """

    _confdir = 'NamedForward'
    _config_template = """
dnssec=validate
forward-zones-recurse=.=dns.quad9.net
system-resolver-ttl=10
    """

    @classmethod
    def setUpClass(cls):

        # we don't need all the auth stuff
        cls.setUpSockets()

        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)

        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    def testA(self):
        expected = dns.rrset.from_text('dns.google.', 0, dns.rdataclass.IN, 'A', '8.8.8.8', '8.8.4.4')
        query = dns.message.make_query('dns.google', 'A', want_dnssec=True)
        query.flags |= dns.flags.AD

        res = self.sendUDPQuery(query)

        self.assertMessageIsAuthenticated(res)
        self.assertRRsetInAnswer(res, expected)
        self.assertMatchingRRSIGInAnswer(res, expected)

@unittest.skipUnless('ENABLE_SUDO_TESTS' in os.environ, "sudo is not available")
class testNamedForwardWithChange(RecursorTest):
    """
    This is forwarding test using a name as target and a changing resolve
    """

    _confdir = 'NamedForwardWithChange'
    _config_template = """
dnssec=off
forward-zones-recurse=.=namedforwardtest
devonly-regression-test-mode
system-resolver-ttl=1
    """

    @classmethod
    def generateRecursorConfig(cls, confdir):
        subprocess.run(['sudo', 'sed', '-i', '-e', '/namedforwardtest/d', '/etc/hosts'])
        subprocess.run(['sudo', 'sh', '-c', 'echo ' + cls._PREFIX + '.10 namedforwardtest >> /etc/hosts'])
        super(testNamedForwardWithChange, cls).generateRecursorConfig(confdir)

    def testExampleNSQuery(self):
        query = dns.message.make_query('example', 'NS', want_dnssec=False)

        expectedNS = dns.rrset.from_text('example.', 0, 'IN', 'NS', 'ns1.example.', 'ns2.example.')

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expectedNS)

        subprocess.run(['sudo', 'sed', '-i', '-e', '/namedforwardtest/d', '/etc/hosts'])
        subprocess.run(['sudo', 'sh', '-c', 'echo ' + self._PREFIX + '.12 namedforwardtest >> /etc/hosts'])

        # the change should get picked up by the systemn resolver update thread and the reload flushes the caches
        time.sleep(2)
        res = self.sendUDPQuery(query)
        subprocess.run(['sudo', 'sed', '-i', '-e', '/namedforwardtest/d', '/etc/hosts'])
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
