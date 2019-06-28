#!/usr/bin/env python
import dns
import time

from pysnmp.hlapi import *
from dnsdisttests import DNSDistTest

class TestSNMP(DNSDistTest):

    _snmpTimeout = 2.0
    _snmpServer = '127.0.0.1'
    _snmpPort = 161
    _snmpV2Community = 'secretcommunity'
    _snmpV3User = 'secretuser'
    _snmpV3AuthKey = 'mysecretauthkey'
    _snmpV3EncKey = 'mysecretenckey'
    _snmpOID = '1.3.6.1.4.1.43315.3'
    _queriesSent = 0
    _config_template = """
    newServer{address="127.0.0.1:%s", name="servername"}
    snmpAgent(true)
    """

    def _checkStatsValues(self, results, queriesCountersValue):
        for i in list(range(1, 5)) + list(range(6, 20)) + list(range(24, 35)) + [ 35 ] :
            oid = self._snmpOID + '.1.' + str(i) + '.0'
            self.assertTrue(oid in results)
            self.assertTrue(isinstance(results[oid], Counter64))

        for i in range(20, 23):
            oid = self._snmpOID + '.1.' + str(i) + '.0'
            self.assertTrue(isinstance(results[oid], OctetString))

        # check uptime > 0
        self.assertGreater(results['1.3.6.1.4.1.43315.3.1.24.0'], 0)
        # check memory usage > 0
        self.assertGreater(results['1.3.6.1.4.1.43315.3.1.25.0'], 0)

        # check that the queries, responses and rdQueries counters are now at queriesCountersValue
        for i in [1, 2, 28]:
            oid = self._snmpOID + '.1.' + str(i) + '.0'
            self.assertEquals(results[oid], queriesCountersValue)

        # the others counters (except for latency ones) should still be at 0
        for i in [3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 26, 27, 29, 30, 31, 35, 36]:
            oid = self._snmpOID + '.1.' + str(i) + '.0'
            self.assertEquals(results[oid], 0)

        # check the backend stats
        print(results)

        ## types
        for i in [3, 4, 5, 6, 7, 11, 12, 13]:
            oid = self._snmpOID + '.2.1.' + str(i) + '.0'
            self.assertTrue(isinstance(results[oid], Counter64))
        for i in [2, 8, 9, 10]:
            oid = self._snmpOID + '.2.1.' + str(i) + '.0'
            self.assertTrue(isinstance(results[oid], OctetString))

        ## name
        self.assertEquals(str(results['1.3.6.1.4.1.43315.3.2.1.2.0']), "servername")
        ## weight
        self.assertEquals(results['1.3.6.1.4.1.43315.3.2.1.4.0'], 1)
        ## outstanding
        self.assertEquals(results['1.3.6.1.4.1.43315.3.2.1.5.0'], 0)
        ## qpslimit
        self.assertEquals(results['1.3.6.1.4.1.43315.3.2.1.6.0'], 0)
        ## reused
        self.assertEquals(results['1.3.6.1.4.1.43315.3.2.1.7.0'], 0)
        ## state
        self.assertEquals(str(results['1.3.6.1.4.1.43315.3.2.1.8.0']), "up")
        ## address
        self.assertEquals(str(results['1.3.6.1.4.1.43315.3.2.1.9.0']), ("127.0.0.1:%s" % (self._testServerPort)))
        ## pools
        self.assertEquals(str(results['1.3.6.1.4.1.43315.3.2.1.10.0']), "")
        ## queries
        self.assertEquals(results['1.3.6.1.4.1.43315.3.2.1.12.0'], queriesCountersValue)
        ## order
        self.assertEquals(results['1.3.6.1.4.1.43315.3.2.1.13.0'], 1)

    def _getSNMPStats(self, auth):
        results = {}
        for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
                                                                            auth,
                                                                            UdpTransportTarget((self._snmpServer, self._snmpPort), timeout=self._snmpTimeout),
                                                                            ContextData(),
                                                                            ObjectType(ObjectIdentity(self._snmpOID)),
                                                                            lookupMib=False):
            self.assertFalse(errorIndication)
            self.assertFalse(errorStatus)
            self.assertTrue(varBinds)
            for key, value in varBinds:
                keystr = key.prettyPrint()
                if not keystr.startswith(self._snmpOID):
                    continue
                results[keystr] = value

        return results

    def _checkStats(self, auth, name):
        # wait 1s so that the uptime is > 0
        time.sleep(1)

        results = self._getSNMPStats(auth)
        self._checkStatsValues(results, self.__class__._queriesSent)

        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        # send a query
        (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
        self.assertTrue(receivedQuery)
        self.assertTrue(receivedResponse)
        receivedQuery.id = query.id
        self.assertEquals(query, receivedQuery)
        self.assertEquals(response, receivedResponse)
        self.__class__._queriesSent = self.__class__._queriesSent + 1

        results = self._getSNMPStats(auth)
        self._checkStatsValues(results, self.__class__._queriesSent)

    def testSNMPv2Stats(self):
        """
        SNMP: Retrieve statistics via SNMPv2c
        """

        auth = CommunityData(self._snmpV2Community, mpModel=1)
        name = 'simplea.snmpv2c.tests.powerdns.com.'
        self._checkStats(auth, name)

    def testSNMPv3Stats(self):
        """
        SNMP: Retrieve statistics via SNMPv3
        """

        auth = UsmUserData(self._snmpV3User,
                               authKey=self._snmpV3AuthKey,
                               privKey=self._snmpV3EncKey,
                               authProtocol=usmHMACSHAAuthProtocol,
                               privProtocol=usmAesCfb128Protocol)
        name = 'simplea.snmpv2.tests.powerdns.com.'
        self._checkStats(auth, name)
