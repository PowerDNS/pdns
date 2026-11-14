#!/usr/bin/env python

from __future__ import print_function

import threading
import clientsubnetoption

import dns
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

from authtests import AuthTest

aliasUDPReactorRunning = False


class TestALIAS(AuthTest):
    _config_template = """
expand-alias=yes
resolver=%s.1:5301
any-to-tcp=no
launch={backend}
edns-subnet-processing=yes
logging-structured
"""

    _config_params = ["_PREFIX"]

    _zones = {
        "example.org": """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    {prefix}.10
ns2.example.org.             3600 IN A    {prefix}.11

noerror.example.org.         3600 IN ALIAS noerror.example.com.
nxd.example.org.             3600 IN ALIAS nxd.example.com.
servfail.example.org.        3600 IN ALIAS servfail.example.com.
subnet.example.org.          3600 IN ALIAS subnet.example.com.
subnetwrong.example.org.     3600 IN ALIAS subnetwrong.example.com.

othertypes.example.org.      3600 IN ALIAS noerror.example.com.
othertypes.example.org.      3600 IN MX   10 mail.example.org.
othertypes.example.org.      3600 IN TXT  "othertypes text"

oversized.example.org.       3600 IN ALIAS noerror.example.com.
oversized.example.org.       3600 IN TXT  "oversized text record 1, padded to sixty-four bytes............."
oversized.example.org.       3600 IN TXT  "oversized text record 2, padded to sixty-four bytes............."
oversized.example.org.       3600 IN TXT  "oversized text record 3, padded to sixty-four bytes............."
oversized.example.org.       3600 IN TXT  "oversized text record 4, padded to sixty-four bytes............."
oversized.example.org.       3600 IN TXT  "oversized text record 5, padded to sixty-four bytes............."
oversized.example.org.       3600 IN TXT  "oversized text record 6, padded to sixty-four bytes............."
oversized.example.org.       3600 IN TXT  "oversized text record 7, padded to sixty-four bytes............."
oversized.example.org.       3600 IN TXT  "oversized text record 8, padded to sixty-four bytes............."

withrealaddress.example.org. 3600 IN ALIAS noerror.example.com.
withrealaddress.example.org. 3600 IN A    192.0.2.100
withrealaddress.example.org. 3600 IN AAAA 2001:DB8::100
        """,
        "example.net": """
example.net.                 3600 IN SOA  {soa}
example.net.                 3600 IN NS   ns1.example.net.
example.net.                 3600 IN NS   ns2.example.net.
example.net.                 3600 IN ALIAS noerror.example.com.
example.net.                 3600 IN TXT  "apex text"
ns1.example.net.             3600 IN A    {prefix}.10
ns2.example.net.             3600 IN A    {prefix}.11
        """,
    }

    @classmethod
    def startResponders(cls):
        global aliasUDPReactorRunning

        address = cls._PREFIX + ".1"
        port = 5301

        if not aliasUDPReactorRunning:
            reactor.listenUDP(port, AliasUDPResponder(), interface=address)

            aliasUDPReactorRunning = True

        if not reactor.running:
            cls._ALIASResponder = threading.Thread(name="ALIAS Responder", target=reactor.run, args=(False,))
            cls._ALIASResponder.setDaemon(True)
            cls._ALIASResponder.start()

    def testNoError(self):
        expected_a = [dns.rrset.from_text("noerror.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1")]
        expected_aaaa = [dns.rrset.from_text("noerror.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")]

        query = dns.message.make_query("noerror.example.org", "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertEqual(len(res.options), 0)  # this checks that we don't invent ECS on non-ECS queries

        query = dns.message.make_query("noerror.example.org", "AAAA")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        query = dns.message.make_query("noerror.example.org", "ANY")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        # NODATA
        query = dns.message.make_query("noerror.example.org", "MX")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 0)

    def testNxDomain(self):
        query = dns.message.make_query("nxd.example.org", "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query("nxd.example.org", "AAAA")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        # TODO this should actually return SOA + NS?
        query = dns.message.make_query("nxd.example.org", "ANY")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testServFail(self):
        query = dns.message.make_query("servfail.example.org", "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query("servfail.example.org", "AAAA")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        # TODO this should actually return SOA + NS?
        query = dns.message.make_query("servfail.example.org", "ANY")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testNoErrorTCP(self):
        expected_a = [dns.rrset.from_text("noerror.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1")]
        expected_aaaa = [dns.rrset.from_text("noerror.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")]

        query = dns.message.make_query("noerror.example.org", "A")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)

        query = dns.message.make_query("noerror.example.org", "AAAA")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        query = dns.message.make_query("noerror.example.org", "ANY")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)

        # NODATA
        query = dns.message.make_query("noerror.example.org", "MX")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(len(res.answer), 0)

    def testNxDomainTCP(self):
        query = dns.message.make_query("nxd.example.org", "A")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query("nxd.example.org", "AAAA")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query("nxd.example.org", "ANY")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testServFailTCP(self):
        query = dns.message.make_query("servfail.example.org", "A")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query("servfail.example.org", "AAAA")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        query = dns.message.make_query("servfail.example.org", "ANY")
        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testECS(self):
        expected_a = [dns.rrset.from_text("subnet.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1")]
        expected_aaaa = [dns.rrset.from_text("subnet.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")]

        ecso = clientsubnetoption.ClientSubnetOption("1.2.3.0", 24)
        ecso2 = clientsubnetoption.ClientSubnetOption("1.2.3.0", 24, 22)
        query = dns.message.make_query("subnet.example.org", "A", use_edns=True, options=[ecso])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertEqual(res.options[0], ecso2)

        ecso = clientsubnetoption.ClientSubnetOption("2001:db8:db6:db5::", 64)
        ecso2 = clientsubnetoption.ClientSubnetOption("2001:db8:db6:db5::", 64, 48)
        query = dns.message.make_query("subnet.example.org", "AAAA", use_edns=True, options=[ecso])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)
        self.assertEqual(res.options[0], ecso2)

    def testECSWrong(self):
        expected_a = [dns.rrset.from_text("subnetwrong.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1")]
        expected_aaaa = [dns.rrset.from_text("subnetwrong.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")]

        ecso = clientsubnetoption.ClientSubnetOption(
            "1.2.3.0", 24
        )  # FIXME change all IPs to documentation space in this file
        ecso2 = clientsubnetoption.ClientSubnetOption("1.2.3.0", 24, 22)
        query = dns.message.make_query("subnetwrong.example.org", "A", use_edns=True, options=[ecso])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertEqual(res.options[0], ecso2)

        ecso = clientsubnetoption.ClientSubnetOption("2001:db8:db6:db5::", 64)
        ecso2 = clientsubnetoption.ClientSubnetOption("2001:db8:db6:db5::", 64, 48)
        query = dns.message.make_query("subnetwrong.example.org", "AAAA", use_edns=True, options=[ecso])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)
        self.assertEqual(res.options[0], ecso2)

    def testECSNone(self):
        expected_a = [dns.rrset.from_text("noerror.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1")]
        expected_aaaa = [dns.rrset.from_text("noerror.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")]

        ecso = clientsubnetoption.ClientSubnetOption("1.2.3.0", 24)
        ecso2 = clientsubnetoption.ClientSubnetOption("1.2.3.0", 24, 0)
        query = dns.message.make_query("noerror.example.org", "A", use_edns=True, options=[ecso])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_a)
        self.assertEqual(res.options[0], ecso2)

        ecso = clientsubnetoption.ClientSubnetOption("2001:db8:db6:db5::", 64)
        ecso2 = clientsubnetoption.ClientSubnetOption("2001:db8:db6:db5::", 64, 0)
        query = dns.message.make_query("noerror.example.org", "AAAA", use_edns=True, options=[ecso])
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected_aaaa)
        self.assertEqual(res.options[0], ecso2)

    def assertNoALIASInAnswer(self, msg):
        # 65401 is the PowerDNS-specific ALIAS type, dnspython has no name for it
        for rrset in msg.answer:
            self.assertNotEqual(rrset.rdtype, 65401, "ALIAS record found in answer:\n%s" % msg.to_text())

    def testANYWithOtherTypes(self):
        """
        ANY for a name with an ALIAS returns the expanded A and AAAA, plus the
        other records at that name, but not the ALIAS record itself (#18224)
        """
        expected_a = dns.rrset.from_text("othertypes.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1")
        expected_aaaa = dns.rrset.from_text("othertypes.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")
        expected_mx = dns.rrset.from_text("othertypes.example.org.", 0, dns.rdataclass.IN, "MX", "10 mail.example.org.")
        expected_txt = dns.rrset.from_text("othertypes.example.org.", 0, dns.rdataclass.IN, "TXT", '"othertypes text"')

        query = dns.message.make_query("othertypes.example.org", "ANY")

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertRRsetInAnswer(res, expected_aaaa)
        self.assertRRsetInAnswer(res, expected_mx)
        self.assertRRsetInAnswer(res, expected_txt)
        self.assertNoALIASInAnswer(res)
        self.assertEqual(len(res.answer), 4)

        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertRRsetInAnswer(res, expected_aaaa)
        self.assertRRsetInAnswer(res, expected_mx)
        self.assertRRsetInAnswer(res, expected_txt)
        self.assertNoALIASInAnswer(res)
        self.assertEqual(len(res.answer), 4)

        # Queries for a single type are not changed
        query = dns.message.make_query("othertypes.example.org", "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertEqual(len(res.answer), 1)

        query = dns.message.make_query("othertypes.example.org", "MX")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_mx)
        self.assertEqual(len(res.answer), 1)

    def testANYOversized(self):
        """
        An ANY answer for a name with an ALIAS that does not fit in 512 bytes is
        truncated over UDP without EDNS, and complete over TCP
        """
        expected_a = dns.rrset.from_text("oversized.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1")
        expected_aaaa = dns.rrset.from_text("oversized.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")
        expected_txt = dns.rrset.from_text(
            "oversized.example.org.",
            0,
            dns.rdataclass.IN,
            "TXT",
            '"oversized text record 1, padded to sixty-four bytes............."',
            '"oversized text record 2, padded to sixty-four bytes............."',
            '"oversized text record 3, padded to sixty-four bytes............."',
            '"oversized text record 4, padded to sixty-four bytes............."',
            '"oversized text record 5, padded to sixty-four bytes............."',
            '"oversized text record 6, padded to sixty-four bytes............."',
            '"oversized text record 7, padded to sixty-four bytes............."',
            '"oversized text record 8, padded to sixty-four bytes............."',
        )

        query = dns.message.make_query("oversized.example.org", "ANY", use_edns=False)

        raw = self.sendUDPQuery(query, decode=False)
        self.assertLessEqual(len(raw), 512)
        res = dns.message.from_wire(raw)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertTrue(res.flags & dns.flags.TC)

        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertFalse(res.flags & dns.flags.TC)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertRRsetInAnswer(res, expected_aaaa)
        self.assertRRsetInAnswer(res, expected_txt)
        self.assertNoALIASInAnswer(res)
        self.assertEqual(len(res.answer), 3)

    def testANYAtApex(self):
        """
        ANY for a zone apex with an ALIAS also returns the SOA and NS records
        """
        expected_soa = dns.rrset.from_text("example.net.", 0, dns.rdataclass.IN, "SOA", self._SOA)
        expected_ns = dns.rrset.from_text(
            "example.net.", 0, dns.rdataclass.IN, "NS", "ns1.example.net.", "ns2.example.net."
        )
        expected_a = dns.rrset.from_text("example.net.", 0, dns.rdataclass.IN, "A", "192.0.2.1")
        expected_aaaa = dns.rrset.from_text("example.net.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1")
        expected_txt = dns.rrset.from_text("example.net.", 0, dns.rdataclass.IN, "TXT", '"apex text"')

        query = dns.message.make_query("example.net", "ANY")

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_soa)
        self.assertRRsetInAnswer(res, expected_ns)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertRRsetInAnswer(res, expected_aaaa)
        self.assertRRsetInAnswer(res, expected_txt)
        self.assertNoALIASInAnswer(res)
        self.assertEqual(len(res.answer), 5)

        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_soa)
        self.assertRRsetInAnswer(res, expected_ns)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertRRsetInAnswer(res, expected_aaaa)
        self.assertRRsetInAnswer(res, expected_txt)
        self.assertNoALIASInAnswer(res)
        self.assertEqual(len(res.answer), 5)

    def testANYWithRealAddress(self):
        """
        ANY for a name with both an ALIAS and its own A and AAAA returns both,
        like outgoing-axfr-expand-alias does in AXFR
        """
        expected_a = dns.rrset.from_text(
            "withrealaddress.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.1", "192.0.2.100"
        )
        expected_aaaa = dns.rrset.from_text(
            "withrealaddress.example.org.", 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1", "2001:DB8::100"
        )

        query = dns.message.make_query("withrealaddress.example.org", "ANY")

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertRRsetInAnswer(res, expected_aaaa)
        self.assertNoALIASInAnswer(res)
        self.assertEqual(len(res.answer), 2)

        res = self.sendTCPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_a)
        self.assertRRsetInAnswer(res, expected_aaaa)
        self.assertNoALIASInAnswer(res)
        self.assertEqual(len(res.answer), 2)

        # A query for a single type still returns only the zone's own records
        expected_zone_a = dns.rrset.from_text("withrealaddress.example.org.", 0, dns.rdataclass.IN, "A", "192.0.2.100")
        query = dns.message.make_query("withrealaddress.example.org", "A")
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected_zone_a)
        self.assertEqual(len(res.answer), 1)


class AliasUDPResponder(DatagramProtocol):
    def datagramReceived(self, datagram, address):
        request = dns.message.from_wire(datagram)
        response = dns.message.make_response(request)
        response.use_edns(edns=False)
        response.flags |= dns.flags.RA

        question = request.question[0]
        name = question.name
        name_text = name.to_text()

        if name_text in ("noerror.example.com.", "subnet.example.com.", "subnetwrong.example.com."):
            do_ecs = False
            do_ecs_wrong = False
            if name_text == "subnet.example.com.":
                do_ecs = True
            elif name_text == "subnetwrong.example.com.":
                do_ecs = True
                do_ecs_wrong = True

            response.set_rcode(dns.rcode.NOERROR)
            if question.rdtype in [dns.rdatatype.A, dns.rdatatype.ANY]:
                response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.1"))

            if question.rdtype in [dns.rdatatype.AAAA, dns.rdatatype.ANY]:
                response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, "AAAA", "2001:DB8::1"))

            if do_ecs:
                if request.options[0].family == clientsubnetoption.FAMILY_IPV4:
                    ecso = clientsubnetoption.ClientSubnetOption("5.6.7.0" if do_ecs_wrong else "1.2.3.0", 24, 22)
                else:
                    ecso = clientsubnetoption.ClientSubnetOption(
                        "2600::" if do_ecs_wrong else "2001:db8:db6:db5::", 64, 48
                    )
                response.use_edns(edns=True, options=[ecso])

        if name_text == "nxd.example.com.":
            response.set_rcode(dns.rcode.NXDOMAIN)
            response.authority.append(
                dns.rrset.from_text(
                    "example.com.",
                    0,
                    dns.rdataclass.IN,
                    "SOA",
                    "ns1.example.com. hostmaster.example.com. 2018062101 1 2 3 4",
                )
            )

        if name_text == "servfail.example.com.":
            response.set_rcode(dns.rcode.SERVFAIL)

        self.transport.write(response.to_wire(max_size=65535), address)
