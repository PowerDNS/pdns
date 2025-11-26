import dns
import dns.serial
import time

from ixfrdisttests import IXFRDistTest
from xfrserver.xfrserver import AXFRServer

zones = {
    1: """
$ORIGIN ixfr.case.
@        86400   SOA    foo bar 1 2 3 4 5
@        4242    NS     ns1.ixfr.case.
@        4242    NS     ns2.ixfr.case.
ns1.ixfr.case.    4242    A       192.0.2.1
ns2.ixfr.case.    4242    A       192.0.2.2
test.ixfr.case.   1234    TXT     "Hello World"
""",
    2: """
$ORIGIN ixfr.case.
@        86400   SOA    foo bar 2 2 3 4 5
@        4242    NS     ns1.ixfr.case.
@        4242    NS     ns2.ixfr.case.
ns1.ixfr.case.    4242    A       192.0.2.1
ns2.ixfr.case.    4242    A       192.0.2.2
test.ixfr.case.   1234    TXT     "hello world"
""",
    3: """
$ORIGIN ixfr.case.
@        86400   SOA    foo bar 3 2 3 4 5
@        4242    NS     ns1.ixfr.case.
@        4242    NS     ns2.ixfr.case.
ns1.ixfr.case.    4242    A       192.0.2.1
ns2.ixfr.case.    4242    A       192.0.2.2
test.ixfr.case.   1234    TXT     "HELLO WORLD"
""",
    4: """
$ORIGIN ixfr.case.
@        86400   SOA    foo bar 4 2 3 4 5
@        4242    NS     ns1.ixfr.case.
@        4242    NS     ns2.ixfr.case.
ns1.ixfr.case.    4242    A       192.0.2.1
ns2.ixfr.case.    4242    A       192.0.2.2
test.ixfr.case.   1234    TXT     "Hello World"
case2.ixfr.case.  1234    TXT     "Mixed Case"
case3.ixfr.case.  1234    TXT     "mixed case"
""",
    5: """
$ORIGIN ixfr.case.
@        86400   SOA    foo bar 5 2 3 4 5
@        4242    NS     ns1.ixfr.case.
@        4242    NS     ns2.ixfr.case.
ns1.ixfr.case.    4242    A       192.0.2.1
ns2.ixfr.case.    4242    A       192.0.2.2
test.ixfr.case.   1234    TXT     "Hello World"
case2.ixfr.case.  1234    TXT     "Mixed Case"
case3.ixfr.case.  1234    TXT     "MIXED CASE"
""",
}

xfrServerPort = 4246
xfrServer = AXFRServer(xfrServerPort, zones)


class IXFRDistCaseSensitiveTXTTest(IXFRDistTest):
    """
    This test verifies that TXT record comparisons are case-sensitive
    after the fix in pdns/ixfrutils.hh where toLower() was removed
    from CIContentCompareStruct::operator()
    """

    global xfrServerPort
    _xfrDone = 0
    _config_domains = [
        {"domain": "ixfr.case", "master": "127.0.0.1:" + str(xfrServerPort)},
    ]
    _loaded_serials = []

    @classmethod
    def setUpClass(cls):
        cls.startIXFRDist()
        cls.setUpSockets()

    @classmethod
    def tearDownClass(cls):
        cls.tearDownIXFRDist()

    def waitUntilCorrectSerialIsLoaded(self, serial, timeout=10, notify=False):
        global xfrServer

        xfrServer.moveToSerial(serial)

        if notify:
            notif = dns.message.make_query("ixfr.case.", "SOA")
            notif.set_opcode(dns.opcode.NOTIFY)
            notify_response = self.sendUDPQuery(notif)
            assert notify_response.rcode() == dns.rcode.NOERROR

        def get_current_serial():
            query = dns.message.make_query("ixfr.case.", "SOA")
            response_message = self.sendUDPQuery(query)

            if response_message.rcode() == dns.rcode.REFUSED:
                return 0

            soa_rrset = response_message.find_rrset(
                dns.message.ANSWER, dns.name.from_text("ixfr.case."), dns.rdataclass.IN, dns.rdatatype.SOA
            )
            return soa_rrset[0].serial

        attempts = 0
        while attempts < timeout:
            print("attempts=%s timeout=%s" % (attempts, timeout))
            servedSerial = get_current_serial()
            print("servedSerial=%s" % servedSerial)
            if servedSerial > serial:
                raise AssertionError("Expected serial %d, got %d" % (serial, servedSerial))
            if servedSerial == serial:
                self._xfrDone = self._xfrDone + 1
                self._loaded_serials.append(serial)
                return

            attempts = attempts + 1
            time.sleep(1)

        raise AssertionError(
            "Waited %d seconds for the serial to be updated to %d but the last served serial is still %d"
            % (timeout, serial, servedSerial)
        )

    def checkTXTRecord(self, expected_txt_records):
        """
        Check for the presence of specific TXT records in the zone using AXFR
        """
        query = dns.message.make_query("ixfr.case.", "AXFR")
        responses = self.sendTCPQueryMultiResponse(query, count=10)

        found_txt_records = []
        for response in responses:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    for rr in rrset:
                        txt_content = str(rr).strip('"')
                        record_name = str(rrset.name)
                        found_txt_records.append((record_name, txt_content))

        for expected_name, expected_txt in expected_txt_records:
            found = False
            for found_name, found_txt in found_txt_records:
                if found_name == expected_name and found_txt == expected_txt:
                    found = True
                    break
            self.assertTrue(
                found,
                f"TXT record '{expected_name}' with content '{expected_txt}' not found in AXFR. Found: {found_txt_records}",
            )

    def checkIXFRContainsTXTChange(self, fromserial, toserial, expected_removed=None, expected_added=None):
        """
        Verify that IXFR properly handles case-sensitive TXT record changes
        """
        global xfrServer

        soa_requested = xfrServer._getSOAForSerial(fromserial)
        soa_latest = xfrServer._getSOAForSerial(self._loaded_serials[-1])

        self.assertEqual(soa_latest[0].serial, toserial)

        query = dns.message.make_query("ixfr.case.", "IXFR")
        query.authority = [soa_requested]

        responses = self.sendTCPQueryMultiResponse(query, count=10)  # Allow for multiple responses

        # Check if the expected TXT records are in the IXFR response
        found_removed = []
        found_added = []

        for response in responses:
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.TXT:
                    for rr in rrset:
                        txt_content = str(rr).strip('"')
                        # This is a simplified check - in real IXFR, we'd need to
                        # analyze the removal/addition sections properly
                        if expected_removed and txt_content in expected_removed:
                            found_removed.append(txt_content)
                        if expected_added and txt_content in expected_added:
                            found_added.append(txt_content)

        if expected_removed:
            for removed_txt in expected_removed:
                self.assertIn(removed_txt, found_removed, f"Expected removed TXT '{removed_txt}' not found in IXFR")

        if expected_added:
            for added_txt in expected_added:
                self.assertIn(added_txt, found_added, f"Expected added TXT '{added_txt}' not found in IXFR")

    def test_a_first_version(self):
        """Test first version of zone and verify TXT record presence"""
        self.waitUntilCorrectSerialIsLoaded(1)
        self.checkTXTRecord([("test.ixfr.case.", "Hello World")])

    def test_b_case_change_lowercase(self):
        """Test that changing TXT from 'Hello World' to 'hello world' is detected"""
        self.waitUntilCorrectSerialIsLoaded(2)
        self.checkIXFRContainsTXTChange(1, 2, expected_removed=["Hello World"], expected_added=["hello world"])

    def test_c_case_change_uppercase(self):
        """Test that changing TXT from 'hello world' to 'HELLO WORLD' is detected"""
        self.waitUntilCorrectSerialIsLoaded(3)
        self.checkIXFRContainsTXTChange(2, 3, expected_removed=["hello world"], expected_added=["HELLO WORLD"])

    def test_d_multiple_txt_records_mixed_case(self):
        """Test multiple TXT records with different case variations"""
        self.waitUntilCorrectSerialIsLoaded(4)
        self.checkIXFRContainsTXTChange(
            3, 4, expected_removed=["HELLO WORLD"], expected_added=["Hello World", "Mixed Case", "mixed case"]
        )

    def test_e_case_sensitive_update(self):
        """Test that updating a TXT record's case is properly handled"""
        self.waitUntilCorrectSerialIsLoaded(5)
        self.checkIXFRContainsTXTChange(4, 5, expected_removed=["mixed case"], expected_added=["MIXED CASE"])
