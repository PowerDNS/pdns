#!/usr/bin/env python
import socket
import unittest
import dns
from dnsdisttests import DNSDistTest


def get_loopback_itf():
    interfaces = socket.if_nameindex()
    for itf in interfaces:
        if itf[1] == "lo":
            return "lo"
    return None


class TestIncomingInterface(DNSDistTest):
    _lo_itf = get_loopback_itf()
    _config_template = """
    local itfName = '%s'
    addLocal('127.0.0.1:%d', {interface=itfName})

    function checkItf(dq)
      if dq:getIncomingInterface() ~= itfName then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    function checkItfResponse(dr)
      if dr:getIncomingInterface() ~= itfName then
        return DNSResponseAction.ServFail
      end
      return DNSResponseAction.None
    end

    addAction(AllRule(), LuaAction(checkItf))
    addResponseAction(AllRule(), LuaResponseAction(checkItfResponse))
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ["_lo_itf", "_dnsDistPort", "_testServerPort"]
    _skipListeningOnCL = True

    def testItfName(self):
        """
        Advanced: Check incoming interface name
        """
        if get_loopback_itf() is None:
            raise unittest.SkipTest("No lo interface")

        name = "incoming-interface.advanced.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")

        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "4.3.2.1")
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            receivedQuery.id = query.id
            self.assertEqual(receivedQuery, query)
            self.assertEqual(receivedResponse, response)


class TestIncomingInterfaceNotSet(DNSDistTest):
    _lo_itf = get_loopback_itf()
    _config_template = """
    local itfName = '%s'
    addLocal('127.0.0.1:%d')

    function checkItf(dq)
      if dq:getIncomingInterface() ~= itfName then
        return DNSAction.Spoof, '1.2.3.4'
      end
      return DNSAction.None
    end

    function checkItfResponse(dr)
      if dr:getIncomingInterface() ~= itfName then
        return DNSResponseAction.ServFail
      end
      return DNSResponseAction.None
    end

    addAction(AllRule(), LuaAction(checkItf))
    addResponseAction(AllRule(), LuaResponseAction(checkItfResponse))
    newServer{address="127.0.0.1:%d"}
    """
    _config_params = ["_lo_itf", "_dnsDistPort", "_testServerPort"]
    _skipListeningOnCL = True

    def testItfName(self):
        """
        Advanced: Check incoming interface name (not set)
        """
        if get_loopback_itf() is None:
            raise unittest.SkipTest("No lo interface")

        name = "incoming-interface-not-set.advanced.tests.powerdns.com."
        query = dns.message.make_query(name, "A", "IN")
        # dnsdist set RA = RD for spoofed responses
        query.flags &= ~dns.flags.RD

        expectedResponse = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name, 60, dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        expectedResponse.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response=None, useQueue=False)
            self.assertEqual(receivedQuery, None)
            self.assertEqual(receivedResponse, expectedResponse)
