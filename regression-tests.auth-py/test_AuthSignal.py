#!/usr/bin/env python
import dns
import os

import pytest
from authtests import AuthTest


class TestAuthSignal(AuthTest):
    _backend = 'gsqlite3'

    _config_template_default = """
module-dir={PDNS_MODULE_DIR}
daemon=no
socket-dir={confdir}
cache-ttl=0
negquery-cache-ttl=0
query-cache-ttl=0
log-dns-queries=yes
log-dns-details=yes
loglevel=9
distributor-threads=1"""

    _config_template = """
launch=gsqlite3
gsqlite3-database=configs/auth/powerdns.sqlite
gsqlite3-pragma-foreign-keys=yes
gsqlite3-dnssec=yes
"""
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.signaling_domain = dns.name.from_text('_signal.ns1.example.net')
        cls.signaling_prefix = dns.name.from_text('_dsboot.cds-cdnskey.test').relativize(dns.name.root)
        cls.signaling_qname = cls.signaling_prefix.concatenate(cls.signaling_domain)

        os.system("$PDNSUTIL --config-dir=configs/auth create-zone _signal.ns1.example.net")
        os.system("$PDNSUTIL --config-dir=configs/auth set-signaling-zone _signal.ns1.example.net")
        query = dns.message.make_query('_signal.ns1.example.net', 'DNSKEY')
        res = cls.sendUDPQuery(query)
        cls.signaling_keytag = dns.dnssec.key_id(res.answer[0][0])

        os.system("$PDNSUTIL --config-dir=configs/auth create-zone cds-cdnskey.test")
        os.system("$PDNSUTIL --config-dir=configs/auth secure-zone cds-cdnskey.test")
        os.system("$PDNSUTIL --config-dir=configs/auth set-publish-cds cds-cdnskey.test 2 4")
        os.system("$PDNSUTIL --config-dir=configs/auth set-publish-cdnskey cds-cdnskey.test")

    def _signalingQuery(self, rdtype):
        query = dns.message.make_query('cds-cdnskey.test', rdtype)
        res1 = self.sendUDPQuery(query)

        query = dns.message.make_query(self.signaling_qname, rdtype, use_edns=True, want_dnssec=True)
        res2 = self.sendUDPQuery(query)

        return res1, res2

    def _testSignalingRRset(self, rdtype):
        res1, res2 = self._signalingQuery(rdtype)

        # Ensure no error in response
        self.assertRcodeEqual(res1, dns.rcode.NOERROR)
        self.assertRcodeEqual(res2, dns.rcode.NOERROR)

        # Ensure that signaling rdata were taken from the corresponding zone
        rrset1 = res1.answer[0]
        rrset2 = res2.find_rrset(dns.message.ANSWER, self.signaling_qname, rdclass=dns.rdataclass.IN, rdtype=rdtype)
        self.assertEqual(rrset1.to_rdataset(), rrset2.to_rdataset())

        # ... and signed by the signaling zone
        rrsig_correct = any(rrset.rdtype == dns.rdatatype.RRSIG and rrset.covers == rdtype and rrset[0].key_tag == self.signaling_keytag for rrset in res2.answer)
        self.assertTrue(rrsig_correct, f"RRSIG({rdtype}) with proper keytag not found")

    def testSignalingCDSQuery(self):
        self._testSignalingRRset(dns.rdatatype.CDS)

    def testSignalingCDNSKEYQuery(self):
        self._testSignalingRRset(dns.rdatatype.CDNSKEY)

    def testSignalingQueryNoSignal(self):
        os.system("$PDNSUTIL --config-dir=configs/auth create-zone no-signaling.test")
        os.system("$PDNSUTIL --config-dir=configs/auth secure-zone no-signaling.test")

        signaling_prefix = dns.name.from_text('_dsboot.no-signaling.test').relativize(dns.name.root)
        qname = signaling_prefix.concatenate(self.signaling_domain)
        for rdtype, nsec3windows in {
            dns.rdatatype.CDS: ((0, b'\x00\x00\x00\x00\x00\x02\x00\x08'),),  # RRSIG CDNSKEY
            dns.rdatatype.CDNSKEY: ((0, b'\x00\x00\x00\x00\x00\x02\x00\x10'),)  # RRSIG CDS
        }.items():
            query = dns.message.make_query(qname, rdtype, use_edns=True, want_dnssec=True)
            res = self.sendUDPQuery(query)

            # Verify that signaling RRset is not there
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            with self.assertRaises(KeyError):
                res.find_rrset(dns.message.ANSWER, qname, rdclass=dns.rdataclass.IN, rdtype=rdtype)

            # Verify that NSEC3 is present but does not disprove the other signaling record type
            nsec3_present = any(rrset.rdtype == dns.rdatatype.NSEC3 for rrset in res.authority)
            self.assertTrue(nsec3_present)
            for rrset in res.authority:
                if rrset.rdtype == dns.rdatatype.NSEC3:
                    self.assertEqual(rrset.to_rdataset()[0].windows, nsec3windows)

    def testSignalingQueryNXDOMAIN(self):
        signaling_prefix = dns.name.from_text('_dsboot.othername.test').relativize(dns.name.root)
        qname = signaling_prefix.concatenate(self.signaling_domain)
        for rdtype in (dns.rdatatype.CDS, dns.rdatatype.CDNSKEY):
            query = dns.message.make_query(qname, rdtype, use_edns=True, want_dnssec=True)
            res = self.sendUDPQuery(query)

            # Expect NXDOMAIN for signaling records of zones we don't serve
            self.assertRcodeEqual(res, dns.rcode.NXDOMAIN)
