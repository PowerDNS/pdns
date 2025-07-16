#!/usr/bin/env python
import cdbx
import unittest
import dns
import os
import socket
import time
from dnsdisttests import DNSDistTest

def writeCDB(fname, variant=1):
    cdb = cdbx.CDB.make(fname+'.tmp')
    cdb.add(socket.inet_aton(f'127.0.0.{variant}'), b'this is the value of the source address tag')
    cdb.add(b'\x05qname\x03cdb\x05tests\x08powerdns\x03com\x00', b'this is the value of the qname tag')
    cdb.add(b'\x06suffix\x03cdb\x05tests\x08powerdns\x03com\x00', b'this is the value of the suffix tag')
    cdb.add(b'this is the value of the qname tag', b'this is the value of the second tag')
    cdb.commit().close()
    os.rename(fname+'.tmp', fname)
    cdb.close()

@unittest.skipIf('SKIP_CDB_TESTS' in os.environ, 'CDB tests are disabled')
class CDBTest(DNSDistTest):

    _cdbFileName = '/tmp/test-cdb-db'
    _cdbRefreshDelay = 1
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    kvs = newCDBKVStore('%s', %d)
    kvs:reload()
    kvs:lookup('does not exist, just testing that the lookup binding exists')
    kvs:lookupSuffix(newDNSName('dummy'))

    -- KVS lookups follow
    -- does a lookup in the CDB database using the source IP as key, and store the result into the 'kvs-sourceip-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySourceIP(), 'kvs-sourceip-result'))

    -- does a lookup in the CDB database using the qname in wire format as key, and store the result into the 'kvs-qname-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyQName(), 'kvs-qname-result'))

    -- if the value of the 'kvs-qname-result' tag is set to 'this is the value of the qname tag'
    -- does a lookup in the CDB database using the value of the 'kvs-qname-result' tag as key, and store the result into the 'kvs-tag-result' tag
    addAction(TagRule('kvs-qname-result', 'this is the value of the qname tag'), KeyValueStoreLookupAction(kvs, KeyValueLookupKeyTag('kvs-qname-result'), 'kvs-tag-result'))

    -- does a lookup in the CDB database using the source IP as key, and store the result into the 'kvs-sourceip-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySourceIP(), 'kvs-sourceip-result'))

    -- does a lookup in the CDB database using the qname in wire format as key, but this time does a suffix lookup, and store the result into the 'kvs-suffix-result' tag
    addAction(AllRule(), KeyValueStoreLookupAction(kvs, KeyValueLookupKeySuffix(), 'kvs-suffix-result'))

    -- Now we take action based on the result of the lookups
    -- if the value of the 'kvs-tag-result' is set to 'this is the value of the second tag', spoof a response
    addAction(TagRule('kvs-tag-result', 'this is the value of the second tag'), SpoofAction('1.2.3.4'))

    -- if the value of the 'kvs-suffix-result' is set to 'this is the value of the suffix tag', spoof a response
    addAction(TagRule('kvs-suffix-result', 'this is the value of the suffix tag'), SpoofAction('42.42.42.42'))

    -- if the value of the 'kvs-sourceip-result' is set to 'this is the value of the source address tag', spoof a response
    addAction(TagRule('kvs-sourceip-result', 'this is the value of the source address tag'), SpoofAction('5.6.7.8'))

    -- otherwise, spoof a different response
    addAction(AllRule(), SpoofAction('9.9.9.9'))
    """
    _config_params = ['_testServerPort', '_cdbFileName', '_cdbRefreshDelay']

class TestCDBSimple(CDBTest):

    @classmethod
    def setUpCDB(cls):
        writeCDB(cls._cdbFileName, 1)

    @classmethod
    def setUpClass(cls):

        cls.setUpCDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testCDBSource(self):
        """
        CDB: Match on source address
        """
        name = 'source-ip.cdb.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '5.6.7.8')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testCDBQNamePlusTagLookup(self):
        """
        CDB: Match on qname then does a second lookup using the value of the first lookup
        """
        name = 'qname.cdb.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '1.2.3.4')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

    def testCDBSuffixLookup(self):
        """
        CDB: Match on the qname via a suffix lookup
        """
        name = 'sub.sub.suffix.cdb.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '42.42.42.42')
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

class TestCDBReload(CDBTest):

    @classmethod
    def setUpCDB(cls):
        writeCDB(cls._cdbFileName, 1)

    @classmethod
    def setUpClass(cls):

        cls.setUpCDB()
        cls.startResponders()
        cls.startDNSDist()
        cls.setUpSockets()

        print("Launching tests..")

    def testCDBReload(self):
        """
        CDB: Test that the CDB is correctly reloaded
        """
        name = 'reload.cdb.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD
        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '5.6.7.8')
        expectedResponse.answer.append(rrset)

        # only the source address should match
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)

        # write a new CDB which has no entry for 127.0.0.1
        # first ensure that the mtime will change after writing
        # the new version
        time.sleep(1)
        writeCDB(self._cdbFileName, 2)
        # wait long enough for the CDB database to be reloaded
        time.sleep(self._cdbRefreshDelay + 1)

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '9.9.9.9')
        expectedResponse.answer.append(rrset)

        # nothing (qname, suffix or source IP) should match
        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertFalse(receivedQuery)
            self.assertTrue(receivedResponse)
            self.assertEqual(expectedResponse, receivedResponse)
