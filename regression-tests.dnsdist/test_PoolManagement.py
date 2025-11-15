#!/usr/bin/env python
import dns
from dnsdisttests import DNSDistTest

class TestPoolManagement(DNSDistTest):
    _config_template = """
    local backendPort = %d
    server1 = newServer{address="127.0.0.1:"..backendPort, tcpOnly=true}
    server2 = newServer{address="127.0.0.1:"..backendPort, tcpOnly=true}
    server3 = newServer{address="127.0.0.1:"..backendPort, tcpOnly=true}
    server1:addPool("new-pool")
    server2:addPool("new-pool")
    server3:addPool("new-pool")
    server1:rmPool("new-pool")
    server1:addPool("new-pool")
    rmServer(server1)
    rmServer(server2)
    server3:rmPool("new-pool")
    """

    def testSimpleA(self):
        """
        Pool management: A query without EDNS
        """
        name = 'pool-mngmt.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN', use_edns=False)
        response = dns.message.make_response(query)
        rrset = dns.rrset.from_text(name,
                                    3600,
                                    dns.rdataclass.IN,
                                    dns.rdatatype.A,
                                    '127.0.0.1')
        response.answer.append(rrset)

        for method in ("sendUDPQuery", "sendTCPQuery"):
            sender = getattr(self, method)
            (receivedQuery, receivedResponse) = sender(query, response)
            self.assertTrue(receivedQuery)
            self.assertTrue(receivedResponse)
            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)
