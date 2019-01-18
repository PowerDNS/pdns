import dns
import os
import socket
import struct
import threading
import time

from recursortests import RecursorTest
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

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
        query = dns.message.make_query('version.bind.', 'TXT', 'CH', use_edns=0,
                                       payload=4096)
        unknownOpt = dns.edns.GenericOption(65005, b'1234567890')
        query.options = [unknownOpt]
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.NOERROR)
        self.assertEqual(response.options, [])

    def testEDNSBadVers(self):
        """
        Ensure the rcode is BADVERS when we send an unsupported EDNS version and
        the query is not processed any further.
        """
        query = dns.message.make_query('version.bind.', 'TXT', 'CH', use_edns=5,
                                       payload=4096)
        response = self.sendUDPQuery(query)
        self.assertRcodeEqual(response, dns.rcode.BADVERS)
        self.assertEqual(response.answer, [])
