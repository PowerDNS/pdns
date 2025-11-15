import dns
import sys
from unittest import SkipTest

from recursortests import RecursorTest

ednsBufferReactorRunning = False

class EDNSTest(RecursorTest):
    """
    These tests are designed to check if we respond correctly to EDNS queries
    from clients. Note that buffer-size tests go into test_EDNSBufferSize
    """
    _confdir = 'EDNS'

    def testEDNSUnknownOpt(self):
        """
        Ensure the recursor does not reply with an unknown option when one is
        sent in the query
        """
        unknownOpt = dns.edns.GenericOption(65005, b'1234567890')
        query = dns.message.make_query('version.bind.', 'TXT', 'CH', use_edns=0,
                                       payload=4096, options=[unknownOpt])
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)
        self.assertEqual(response.options, ())

    def testEDNSBadVers(self):
        """
        Ensure the rcode is BADVERS when we send an unsupported EDNS version and
        the query is not processed any further.
        """
        if sys.version_info >= (3, 11) and sys.version_info <= (3, 11, 3):
            raise SkipTest("Test skipped, see https://github.com/PowerDNS/pdns/pull/12912")
        query = dns.message.make_query('version.bind.', 'TXT', 'CH', use_edns=5,
                                       payload=4096)
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.BADVERS)
        self.assertEqual(response.answer, [])
