#!/usr/bin/env python
import unittest
import dns
import shutil
import socket
import time
from dnsdisttests import DNSDistTest

class CDBTest(DNSDistTest):

    _cdbFileName = '/tmp/test-cdb-db'
    _cdbRefreshDelay = 1
    _config_template = """
    newServer{address="127.0.0.1:%d"}

    kvs = newCDBKVStore('%s', %d)

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
        shutil.copyfile('kvs.cdb.1', cls._cdbFileName)

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
            self.assertEquals(expectedResponse, receivedResponse)

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
            self.assertEquals(expectedResponse, receivedResponse)

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
            self.assertEquals(expectedResponse, receivedResponse)

class TestCDBReload(CDBTest):

    @classmethod
    def setUpCDB(cls):
        shutil.copyfile('kvs.cdb.1', cls._cdbFileName)

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
            self.assertEquals(expectedResponse, receivedResponse)

        # switch to the second DB which has no entry for 127.0.0.1
        shutil.copyfile('kvs.cdb.2', self._cdbFileName)
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
            self.assertEquals(expectedResponse, receivedResponse)
