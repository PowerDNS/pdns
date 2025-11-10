#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestSVCB(DNSDistTest):

    _config_template = """
    local basicSVC = { newSVCRecordParameters(1, "dot.powerdns.com.", { mandatory={"port"}, alpn={"dot"}, noDefaultAlpn=true, port=853, ipv4hint={ "192.0.2.1" }, ipv6hint={ "2001:db8::1" } }),
                       newSVCRecordParameters(2, "doh.powerdns.com.", { mandatory={"port"}, alpn={"h2"}, port=443, ipv4hint={ "192.0.2.2" }, ipv6hint={ "2001:db8::2" }, key7="/dns-query{?dns}" })
                     }
    addAction(AndRule{QTypeRule(64), SuffixMatchNodeRule("basic.svcb.tests.powerdns.com.")}, SpoofSVCAction(basicSVC, {aa=true}))

    local noHintsSVC = { newSVCRecordParameters(1, "dot.powerdns.com.", { mandatory={"port"}, alpn={"dot"}, noDefaultAlpn=true, port=853}),
                         newSVCRecordParameters(2, "doh.powerdns.com.", { mandatory={"port"}, alpn={"h2"}, port=443, key7="/dns-query{?dns}" })
                     }
    addAction(AndRule{QTypeRule(64), SuffixMatchNodeRule("no-hints.svcb.tests.powerdns.com.")}, SpoofSVCAction(noHintsSVC, {aa=true}))

    local effectiveTargetSVC = { newSVCRecordParameters(1, ".", { mandatory={"port"}, alpn={ "dot" }, noDefaultAlpn=true, port=853, ipv4hint={ "192.0.2.1" }, ipv6hint={ "2001:db8::1" }}),
                                 newSVCRecordParameters(2, ".", { mandatory={"port"}, alpn={ "h2" }, port=443, ipv4hint={ "192.0.2.1" }, ipv6hint={ "2001:db8::1" }, key7="/dns-query{?dns}"})
                     }
    addAction(AndRule{QTypeRule(64), SuffixMatchNodeRule("effective-target.svcb.tests.powerdns.com.")}, SpoofSVCAction(effectiveTargetSVC, {aa=true}))

    local httpsSVC = { newSVCRecordParameters(1, ".", { mandatory={"port"}, alpn={ "h2" }, noDefaultAlpn=true, port=8002, ipv4hint={ "192.0.2.2" }, ipv6hint={ "2001:db8::2" }}) }
    addAction(AndRule{QTypeRule(65), SuffixMatchNodeRule("https.svcb.tests.powerdns.com.")}, SpoofSVCAction(httpsSVC))

    newServer{address="127.0.0.1:%d"}
    """

    def testBasic(self):
        """
        SVCB: Basic service binding
        """
        name = 'basic.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 4)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text("doh.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.2'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text("dot.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))
            self.assertEqual(receivedResponse.additional[2], dns.rrset.from_text("doh.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::2'))
            self.assertEqual(receivedResponse.additional[3], dns.rrset.from_text("dot.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::1'))

    def testNoHints(self):
        """
        SVCB: No hints
        """
        name = 'no-hints.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 0)

    def testEffectiveTarget(self):
        """
        SVCB: Effective target
        """
        name = 'effective-target.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 2)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::1'))

    def testHTTPS(self):
        """
        SVCB: HTTPS
        """
        name = 'https.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 65, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 65)
            self.assertEqual(len(receivedResponse.additional), 2)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.2'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::2'))

class TestSVCBViaFFI(DNSDistTest):

    _config_template = """
    local ffi = require("ffi")

    function setSVC(record, port, mandatoryParam, alpn, v4Hint, v6Hint)
      ffi.C.dnsdist_ffi_svc_record_parameters_set_port(record, port)
      ffi.C.dnsdist_ffi_svc_record_parameters_add_mandatory_param(record, mandatoryParam)
      ffi.C.dnsdist_ffi_svc_record_parameters_add_alpn(record, alpn, #alpn)
      if v4Hint then
        ffi.C.dnsdist_ffi_svc_record_parameters_add_ipv4_hint(record, v4Hint, #v4Hint)
      end
      if v6Hint then
        ffi.C.dnsdist_ffi_svc_record_parameters_add_ipv6_hint(record, v6Hint, #v6Hint)
      end
    end

    function generateSVC(target, priority, port, alpn, noDefaultALPN, v4Hint, v6Hint)
      local recordPtr = ffi.new("dnsdist_ffi_svc_record_parameters* [1]")
      local recordPtrOut = ffi.cast("dnsdist_ffi_svc_record_parameters**", recordPtr)
      ffi.C.dnsdist_ffi_svc_record_parameters_new(target, priority, noDefaultALPN, recordPtrOut)
      ffi.gc(recordPtrOut[0], ffi.C.dnsdist_ffi_svc_record_parameters_free)
      -- 3 is the port parameter
      setSVC(recordPtrOut[0], port, 3, alpn, v4Hint, v6Hint)
      return recordPtrOut[0]
    end

    function basicSVC(dq)
      local SVCrecords = ffi.new("dnsdist_ffi_svc_record_parameters* [2]")
      SVCrecords[0] = generateSVC("dot.powerdns.com.", 1, 853, "dot", true, "192.0.2.1", "2001:db8::1")
      SVCrecords[1] = generateSVC("doh.powerdns.com.", 2, 443, "h2", false, "192.0.2.2", "2001:db8::2")
      local path = "/dns-query{?dns}"
      ffi.C.dnsdist_ffi_svc_record_parameters_set_additional_param(SVCrecords[1], 7, path, #path)
      local SVCrecordsPtr = ffi.cast("const dnsdist_ffi_svc_record_parameters**", SVCrecords)
      if not ffi.C.dnsdist_ffi_dnsquestion_generate_svc_response(dq, SVCrecordsPtr, 2, 60) then
        return DNSAction.ServFail
      end
      return DNSAction.HeaderModify
    end

    addAction(AndRule{QTypeRule(64), SuffixMatchNodeRule("basic.svcb.tests.powerdns.com.")}, LuaFFIAction(basicSVC))

    function noHintsSVC(dq)
      local SVCrecords = ffi.new("dnsdist_ffi_svc_record_parameters* [2]")
      SVCrecords[0] = generateSVC("dot.powerdns.com.", 1, 853, "dot", true, nil, nil)
      SVCrecords[1] = generateSVC("doh.powerdns.com.", 2, 443, "h2", false, nil, nil)
      local path = "/dns-query{?dns}"
      ffi.C.dnsdist_ffi_svc_record_parameters_set_additional_param(SVCrecords[1], 7, path, #path)
      local SVCrecordsPtr = ffi.cast("const dnsdist_ffi_svc_record_parameters**", SVCrecords)
      if not ffi.C.dnsdist_ffi_dnsquestion_generate_svc_response(dq, SVCrecordsPtr, 2, 60) then
        return DNSAction.ServFail
      end
      return DNSAction.HeaderModify
    end

    addAction(AndRule{QTypeRule(64), SuffixMatchNodeRule("no-hints.svcb.tests.powerdns.com.")}, LuaFFIAction(noHintsSVC))

    function effectiveTargetSVC(dq)
      local SVCrecords = ffi.new("dnsdist_ffi_svc_record_parameters* [2]")
      SVCrecords[0] = generateSVC(".", 1, 853, "dot", true, "192.0.2.1", "2001:db8::1")
      SVCrecords[1] = generateSVC(".", 2, 443, "h2", false, "192.0.2.1", "2001:db8::1")
      local path = "/dns-query{?dns}"
      ffi.C.dnsdist_ffi_svc_record_parameters_set_additional_param(SVCrecords[1], 7, path, #path)
      local SVCrecordsPtr = ffi.cast("const dnsdist_ffi_svc_record_parameters**", SVCrecords)
      if not ffi.C.dnsdist_ffi_dnsquestion_generate_svc_response(dq, SVCrecordsPtr, 2, 60) then
        return DNSAction.ServFail
      end
      return DNSAction.HeaderModify
    end

    addAction(AndRule{QTypeRule(64), SuffixMatchNodeRule("effective-target.svcb.tests.powerdns.com.")}, LuaFFIAction(effectiveTargetSVC))

    function httpsSVC(dq)
      local SVCrecords = ffi.new("dnsdist_ffi_svc_record_parameters* [1]")
      SVCrecords[0] = generateSVC(".", 1, 8002, "h2", false, "192.0.2.2", "2001:db8::2")
      local SVCrecordsPtr = ffi.cast("const dnsdist_ffi_svc_record_parameters**", SVCrecords)
      if not ffi.C.dnsdist_ffi_dnsquestion_generate_svc_response(dq, SVCrecordsPtr, 1, 60) then
        return DNSAction.ServFail
      end
      return DNSAction.HeaderModify
    end

    addAction(AndRule{QTypeRule(65), SuffixMatchNodeRule("https.svcb.tests.powerdns.com.")}, LuaFFIAction(httpsSVC))

    newServer{address="127.0.0.1:%d"}
    """

    def testBasic(self):
        """
        SVCB: Basic service binding
        """
        name = 'basic.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 4)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text("doh.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.2'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text("dot.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))
            self.assertEqual(receivedResponse.additional[2], dns.rrset.from_text("doh.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::2'))
            self.assertEqual(receivedResponse.additional[3], dns.rrset.from_text("dot.powerdns.com.", 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::1'))

    def testNoHints(self):
        """
        SVCB: No hints
        """
        name = 'no-hints.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 0)

    def testEffectiveTarget(self):
        """
        SVCB: Effective target
        """
        name = 'effective-target.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 64, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 64)
            self.assertEqual(len(receivedResponse.additional), 2)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::1'))

    def testHTTPS(self):
        """
        SVCB: HTTPS
        """
        name = 'https.svcb.tests.powerdns.com.'
        query = dns.message.make_query(name, 65, 'IN')
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (_, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertTrue(receivedResponse)
            self.assertEqual(len(receivedResponse.answer), 1)
            self.assertEqual(receivedResponse.answer[0].rdtype, 65)
            self.assertEqual(len(receivedResponse.additional), 2)
            self.assertEqual(receivedResponse.additional[0], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.2'))
            self.assertEqual(receivedResponse.additional[1], dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.AAAA, '2001:db8::2'))
