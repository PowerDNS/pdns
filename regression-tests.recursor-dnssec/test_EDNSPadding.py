import dns
import os
import socket
import unittest

import paddingoption

from recursortests import RecursorTest


class RecursorEDNSPaddingTest(RecursorTest):
    _confdir = "RecursorEDNSPadding"
    _auth_zones = {
        "8": {"threads": 1, "zones": ["ROOT"]},
        "9": {"threads": 1, "zones": ["secure.example", "islandofsecurity.example"]},
        "10": {"threads": 1, "zones": ["example"]},
    }

    def checkPadding(self, message, numberOfBytes=None):
        self.assertEqual(message.edns, 0)
        self.assertEqual(len(message.options), 1)
        for option in message.options:
            self.assertEqual(option.otype, 12)
            if numberOfBytes:
                self.assertEqual(option.olen, numberOfBytes)

    def checkNoPadding(self, message):
        self.assertEqual(message.edns, 0)
        self.assertEqual(len(message.options), 0)

    def checkNoEDNS(self, message):
        self.assertEqual(message.edns, -1)

    def sendUDPQueryTo(self, query, toAddr, v6=True, timeout=2.0):
        if v6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.settimeout(2.0)
        sock.connect((toAddr, self._recursorPort))

        if timeout:
            sock.settimeout(timeout)

        try:
            sock.send(query.to_wire())
            data = sock.recv(4096)
        except socket.timeout:
            data = None

        sock.close()
        message = None
        if data:
            message = dns.message.from_wire(data)
        return message

    def testQueryWithoutEDNS(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=False)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoEDNS(res)
        self.assertRRsetInAnswer(res, expected)


class PaddingDefaultTest(RecursorEDNSPaddingTest):
    _confdir = "PaddingDefault"

    def testQueryWithPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)


class PaddingDefaultNotAllowedTest(RecursorEDNSPaddingTest):
    _confdir = "PaddingDefaultNotAllowed"
    _config_template = """edns-padding-from=127.0.0.2
packetcache-ttl=60
    """

    def testQueryWithPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)


class PaddingAlwaysTest(RecursorEDNSPaddingTest):
    _confdir = "PaddingAlways"
    _config_template = """edns-padding-from=127.0.0.1
edns-padding-mode=always
edns-padding-tag=7830
packetcache-ttl=60
    """
    _lua_dns_script_file = """
    function preresolve(dq)
      if dq.qname == newDN("host1.secure.example.") then
        -- check that EDNS Padding was enabled (default)
        if dq.addPaddingToResponse ~= true then
          -- and stop the process otherwise
          return true
        end
        -- disable EDNS Padding
        dq.addPaddingToResponse = false
      end
      return false
    end

    local ffi = require("ffi")

    ffi.cdef[[
      typedef struct pdns_ffi_param pdns_ffi_param_t;

      const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref);
      void pdns_ffi_param_set_padding_disabled(pdns_ffi_param_t* ref, bool disabled);
    ]]

    function gettag_ffi(ref)
      local qname = ffi.string(ffi.C.pdns_ffi_param_get_qname(ref))
      if qname == 'host1.sub.secure.example' then
        ffi.C.pdns_ffi_param_set_padding_disabled(ref, true)
      end
    end
    """

    def testQueryWithPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithPaddingButDisabledViaLua(self):
        name = "host1.secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.2")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithPaddingButDisabledViaGettagFFI(self):
        name = "host1.sub.secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.11")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        query.flags |= dns.flags.RD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)


class PaddingNotAllowedAlwaysTest(RecursorEDNSPaddingTest):
    _confdir = "PaddingNotAllowedAlways"
    _config_template = """edns-padding-from=127.0.0.2
edns-padding-mode=always
edns-padding-tag=7830
packetcache-ttl=60
    """

    def testQueryWithPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)


class PaddingWhenPaddedTest(RecursorEDNSPaddingTest):
    _confdir = "PaddingWhenPadded"
    _config_template = """edns-padding-from=127.0.0.1
edns-padding-mode=padded-queries-only
edns-padding-tag=7830
local-address=127.0.0.1
packetcache-ttl=60
    """

    def testQueryWithPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)


class PaddingWhenPaddedNotAllowedTest(RecursorEDNSPaddingTest):
    _confdir = "PaddingWhenPaddedNotAllowed"
    _config_template = """edns-padding-from=127.0.0.2
edns-padding-mode=padded-queries-only
edns-padding-tag=7830
local-address=127.0.0.1
packetcache-ttl=60
    """

    def testQueryWithPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkNoPadding(res)
        self.assertRRsetInAnswer(res, expected)


@unittest.skipIf("SKIP_IPV6_TESTS" in os.environ, "IPv6 tests are disabled")
class PaddingAllowedAlwaysSameTagTest(RecursorEDNSPaddingTest):
    # we use the default tag (0) for padded responses, which will cause
    # the same packet cache entry (with padding ) to be returned to a client
    # not allowed by the edns-padding-from list
    _confdir = "PaddingAllowedAlwaysSameTag"
    _config_template = """edns-padding-from=127.0.0.1
edns-padding-mode=always
edns-padding-tag=0
local-address=127.0.0.1, ::1
packetcache-ttl=60
    """

    @classmethod
    def setUpClass(cls):
        if "SKIP_IPV6_TESTS" in os.environ:
            raise unittest.SkipTest("IPv6 tests are disabled")

        super(PaddingAllowedAlwaysSameTagTest, cls).setUpClass()

    def testQueryWithPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        po = paddingoption.PaddingOption(64)
        query = dns.message.make_query(name, "A", want_dnssec=True, options=[po])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

        res = self.sendUDPQueryTo(query, "::1")
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

    def testQueryWithoutPadding(self):
        name = "secure.example."
        expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, "A", "192.0.2.17")
        query = dns.message.make_query(name, "A", want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)

        res = self.sendUDPQueryTo(query, "::1")
        self.checkPadding(res)
        self.assertRRsetInAnswer(res, expected)
