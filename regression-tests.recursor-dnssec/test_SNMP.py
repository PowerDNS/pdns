import time

from pysnmp.hlapi import *

from recursortests import RecursorTest

class TestSNMP(RecursorTest):

    _snmpTimeout = 2.0
    _snmpServer = '127.0.0.1'
    _snmpPort = 161
    _snmpV2Community = 'secretcommunity'
    _snmpV3User = 'secretuser'
    _snmpV3AuthKey = 'mysecretauthkey'
    _snmpV3EncKey = 'mysecretenckey'
    _snmpOID = '1.3.6.1.4.1.43315.2'
    _queriesSent = 0
    _confdir = 'SNMP'
    _config_template = """
    snmp-agent=yes
    """

    def _checkStatsValues(self, results):
        for i in list(range(1, 93)):
            oid = self._snmpOID + '.1.' + str(i) + '.0'
            self.assertTrue(oid in results)
            self.assertTrue(isinstance(results[oid], Counter64))

        # check uptime > 0
        self.assertGreater(results['1.3.6.1.4.1.43315.2.1.75.0'], 0)
        # check memory usage > 0
        self.assertGreater(results['1.3.6.1.4.1.43315.2.1.76.0'], 0)

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

    def _checkStats(self, auth):
        # wait 1s so that the uptime is > 0
        time.sleep(1)

        results = self._getSNMPStats(auth)
        self._checkStatsValues(results)

    def testSNMPv2Stats(self):
        """
        SNMP: Retrieve statistics via SNMPv2c
        """

        auth = CommunityData(self._snmpV2Community, mpModel=1)
        self._checkStats(auth)

    def testSNMPv3Stats(self):
        """
        SNMP: Retrieve statistics via SNMPv3
        """

        auth = UsmUserData(self._snmpV3User,
                               authKey=self._snmpV3AuthKey,
                               privKey=self._snmpV3EncKey,
                               authProtocol=usmHMACSHAAuthProtocol,
                               privProtocol=usmAesCfb128Protocol)
        self._checkStats(auth)
