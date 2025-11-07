#!/usr/bin/env python
import unittest
import dns
from dnsdisttests import DNSDistTest

class TestDNSParser(DNSDistTest):

    _verboseMode = True
    _config_template = """
  function checkQueryPacket(dq)
    local packet = dq:getContent()
    if #packet ~= 41 then
      return DNSAction.Spoof, #packet..".invalid.query.size."
    end

    local overlay = newDNSPacketOverlay(packet)
    if overlay.qname:toString() ~= "powerdns.com." then
      return DNSAction.Spoof, overlay.qname:toString().."invalid.query.qname."
    end
    if overlay.qtype ~= DNSQType.A then
      return DNSAction.Spoof, overlay.qtype..".invalid.query.qtype."
    end
    if overlay.qclass ~= DNSClass.IN then
      return DNSAction.Spoof, overlay.qclass..".invalid.query.qclass."
    end
    local count = overlay:getRecordsCountInSection(0)
    if count ~= 0 then
      return DNSAction.Spoof, count..".invalid.query.count.in.q."
    end
    count = overlay:getRecordsCountInSection(1)
    if count ~= 0 then
      return DNSAction.Spoof, count..".invalid.query.count.in.a."
    end
    count = overlay:getRecordsCountInSection(2)
    if count ~= 0 then
      return DNSAction.Spoof, count..".invalid.query.count.in.auth."
    end
    count = overlay:getRecordsCountInSection(3)
    -- for OPT
    if count ~= 1 then
      return DNSAction.Spoof, count..".invalid.query.count.in.add."
    end
    return DNSAction.None
  end

  function checkResponsePacket(dq)
    local packet = dq:getContent()
    if #packet ~= 57 then
      print(#packet..".invalid.size.")
      return DNSResponseAction.ServFail
    end

    local overlay = newDNSPacketOverlay(packet)
    if overlay.qname:toString() ~= "powerdns.com." then
      print(overlay.qname:toString().."invalid.qname.")
      return DNSResponseAction.ServFail
    end
    if overlay.qtype ~= DNSQType.A then
      print(overlay.qtype..".invalid.qtype.")
      return DNSResponseAction.ServFail
    end
    if overlay.qclass ~= DNSClass.IN then
      print(overlay.qclass..".invalid.qclass.")
      return DNSResponseAction.ServFail
    end
    local count = overlay:getRecordsCountInSection(0)
    if count ~= 0 then
      print(count..".invalid.count.in.q.")
      return DNSResponseAction.ServFail
    end
    count = overlay:getRecordsCountInSection(1)
    if count ~= 1 then
      print(count..".invalid.count.in.a.")
      return DNSResponseAction.ServFail
    end
    count = overlay:getRecordsCountInSection(2)
    if count ~= 0 then
      print(count..".invalid.count.in.auth.")
      return DNSResponseAction.ServFail
    end
    count = overlay:getRecordsCountInSection(3)
    -- for OPT
    if count ~= 1 then
      print(count..".invalid.count.in.add.")
      return DNSResponseAction.ServFail
    end
    local record = overlay:getRecord(0)
    if record.name:toString() ~= "powerdns.com." then
      print(record.name:toString()..".invalid.name.")
      return DNSResponseAction.ServFail
    end
    if record.type ~= DNSQType.A then
      print(record.type..".invalid.type.")
      return DNSResponseAction.ServFail
    end
    if record.class ~= DNSClass.IN then
      print(record.class..".invalid.class.")
      return DNSResponseAction.ServFail
    end
    if record.ttl ~= 3600 then
      print(record.ttl..".invalid.ttl.")
      return DNSResponseAction.ServFail
    end
    if record.place ~= 1 then
      print(record.place..".invalid.place.")
      return DNSResponseAction.ServFail
    end
    if record.contentLength ~= 4 then
      print(record.contentLength..".invalid.contentLength.")
      return DNSResponseAction.ServFail
    end
    if record.contentOffset ~= 42 then
      print(record.contentOffset..".invalid.contentOffset.")
      return DNSResponseAction.ServFail
    end
    return DNSAction.None
  end

  addAction(AllRule(), LuaAction(checkQueryPacket))
  addResponseAction(AllRule(), LuaResponseAction(checkResponsePacket))
  newServer{address="127.0.0.1:%d"}
    """

    def testQuestionAndResponse(self):
        """
        DNS Parser: basic checks
        """
        name = 'powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            print(receivedResponse)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)


class TestDNSRecordParser(DNSDistTest):

    _verboseMode = True
    _config_template = """
  function checkResponsePacket(dq)
    local packet = dq:getContent()
    local overlay = newDNSPacketOverlay(packet)
    local count = overlay:getRecordsCountInSection(DNSSection.Answer)
    for i = 0, count - 1 do
      local record = overlay:getRecord(i)
      local parsedAsA = parseARecord(packet, record)
      local parsedAsAAAA = parseAAAARecord(packet, record)
      local parsedAsAddress = parseAddressRecord(packet, record)
      local parsedAsCNAME = parseCNAMERecord(packet, record)
      if record.type == DNSQType.A then
        if parsedAsA:toString() ~= "192.0.2.1" then
          print(parsedAsA:toString()..".invalid.parsed.a.record.")
          return DNSResponseAction.ServFail
        end
        if parsedAsAddress:toString() ~= "192.0.2.1" then
          print(parsedAsAddress:toString()..".invalid.parsed.a.record. as address")
          return DNSResponseAction.ServFail
        end
      else
        if parsedAsA then
          print("Unexpected A parse success")
          return DNSResponseAction.ServFail
        end
      end

      if record.type == DNSQType.AAAA then
        if parsedAsAAAA:toString() ~= "ff:db8::ffff" then
          print(parsedAsAAAA:toString()..".invalid.parsed.aaaa.record.")
          return DNSResponseAction.ServFail
        end
        if parsedAsAddress:toString() ~= "ff:db8::ffff" then
          print(parsedAsAddress:toString()..".invalid.parsed.aaaa.record. as address")
          return DNSResponseAction.ServFail
        end
      else
        if parsedAsAAAA then
          print("Unexpected AAAA parse success")
          return DNSResponseAction.ServFail
        end
      end

      if record.type == DNSQType.CNAME then
        if parsedAsCNAME:toString() ~= "not-powerdns.com." then
          print(parsedAsCNAME:toString()..".invalid.parsed.cname.record.")
          return DNSResponseAction.ServFail
        end
        if parsedAsAddress then
          print("Unexpected address parse success")
          return DNSResponseAction.ServFail
        end
      else
        if parsedAsCNAME then
          print("Unexpected CNAME parse success")
          return DNSResponseAction.ServFail
        end
      end
    end
    return DNSAction.None
  end

  addResponseAction(AllRule(), LuaResponseAction(checkResponsePacket))
  newServer{address="127.0.0.1:%d"}
    """

    def testQuestionAndResponseWithParsers(self):
        """
        DNS Parser: parsers checks
        """
        name = 'powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=True)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '192.0.2.1')
        response.answer.append(rrset)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.AAAA,
                                    'ff:db8::ffff')
        response.answer.append(rrset)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.CNAME,
                                    'not-powerdns.com.')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            print(receivedResponse)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(receivedResponse, response)
