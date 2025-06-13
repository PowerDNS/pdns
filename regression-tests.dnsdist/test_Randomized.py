#!/usr/bin/env python
import dns
import socket
from dnsdisttests import DNSDistTest

class RandomizedIDs:
    def testRandomizedIDOverUDPFromLuaConfig(self):
        """
        Randomized IDs over UDP: Lua config
        """
        name = 'lua-config.randomizedids.tests.powerdns.com.'
        query = dns.message.make_query(name, 'A', 'IN')
        response = dns.message.make_response(query)

        randomized = False
        for idx in range(10):
            (receivedQuery, receivedResponse) = self.sendUDPQuery(query, response)
            if socket.ntohs(receivedQuery.id) != idx:
                randomized = True

            receivedQuery.id = query.id
            self.assertEqual(query, receivedQuery)
            self.assertEqual(response, receivedResponse)

        self.assertTrue(randomized)

class RandomizedIDsLuaConfig(DNSDistTest, RandomizedIDs):
    _config_template = """
    setRandomizedIdsOverUDP(true)
    newServer{address="127.0.0.1:%d"}
    """

class RandomizedIDsYAMLConfig(DNSDistTest, RandomizedIDs):
    _yaml_config_template = """
backends:
  - address: "127.0.0.1:%d"
    protocol: Do53
tuning:
  udp:
    randomize_ids_to_backend: true
    """
    _yaml_config_params = ['_testServerPort']
    _config_params = []
