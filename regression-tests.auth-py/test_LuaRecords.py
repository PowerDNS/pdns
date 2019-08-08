#!/usr/bin/env python
import unittest
import requests
import threading
import dns
import time
import clientsubnetoption

from authtests import AuthTest

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

class FakeHTTPServer(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        if (self.path == '/ping.json'):
            self.wfile.write('{"ping":"pong"}')
        else:
            self.wfile.write("<html><body><h1>hi!</h1><h2>Programming in Lua !</h2></body></html>")

    def log_message(self, format, *args):
        return

    def do_HEAD(self):
        self._set_headers()

class TestLuaRecords(AuthTest):
    _config_template = """
geoip-database-files=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb
edns-subnet-processing=yes
launch=bind geoip
any-to-tcp=no
"""

    _zones = {
        'example.org': """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    {prefix}.10
ns2.example.org.             3600 IN A    {prefix}.11

web1.example.org.            3600 IN A    {prefix}.101
web2.example.org.            3600 IN A    {prefix}.102
web3.example.org.            3600 IN A    {prefix}.103

all.ifportup                 3600 IN LUA  A     "ifportup(8080, {{'{prefix}.101', '{prefix}.102'}})"
some.ifportup                3600 IN LUA  A     "ifportup(8080, {{'192.168.42.21', '{prefix}.102'}})"
none.ifportup                3600 IN LUA  A     "ifportup(8080, {{'192.168.42.21', '192.168.21.42'}})"
all.noneup.ifportup          3600 IN LUA  A     "ifportup(8080, {{'192.168.42.21', '192.168.21.42'}}, {{ backupSelector='all' }})"

whashed.example.org.         3600 IN LUA  A     "pickwhashed({{ {{15, '1.2.3.4'}}, {{42, '4.3.2.1'}} }})"
rand.example.org.            3600 IN LUA  A     "pickrandom({{'{prefix}.101', '{prefix}.102'}})"
v6-bogus.rand.example.org.   3600 IN LUA  AAAA  "pickrandom({{'{prefix}.101', '{prefix}.102'}})"
v6.rand.example.org.         3600 IN LUA  AAAA  "pickrandom({{'2001:db8:a0b:12f0::1', 'fe80::2a1:9bff:fe9b:f268'}})"
closest.geo                  3600 IN LUA  A     "pickclosest({{'1.1.1.2','1.2.3.4'}})"
empty.rand.example.org.      3600 IN LUA  A     "pickrandom()"
timeout.example.org.         3600 IN LUA  A     "; local i = 0 ;  while i < 1000 do pickrandom() ; i = i + 1 end return '1.2.3.4'"
wrand.example.org.           3600 IN LUA  A     "pickwrandom({{ {{30, '{prefix}.102'}}, {{15, '{prefix}.103'}} }})"

config    IN    LUA    LUA ("settings={{stringmatch='Programming in Lua'}} "
                            "EUWips={{'{prefix}.101','{prefix}.102'}}      "
                            "EUEips={{'192.168.42.101','192.168.42.102'}}  "
                            "NLips={{'{prefix}.111', '{prefix}.112'}}  "
                            "USAips={{'{prefix}.103'}}                     ")

usa          IN    LUA    A   ( ";include('config')                         "
                                "return ifurlup('http://www.lua.org:8080/', "
                                "{{USAips, EUEips}}, settings)              ")

mix.ifurlup  IN    LUA    A   ("ifurlup('http://www.other.org:8080/ping.json', "
                               "{{ '192.168.42.101', '{prefix}.101' }},        "
                               "{{ stringmatch='pong' }})                      ")

eu-west      IN    LUA    A   ( ";include('config')                         "
                                "return ifurlup('http://www.lua.org:8080/', "
                                "{{EUWips, EUEips, USAips}}, settings)      ")

nl           IN    LUA    A   ( ";include('config')                                "
                                "return ifportup(8081, NLips) ")
latlon.geo      IN LUA    TXT "latlon()"
continent.geo   IN LUA    TXT ";if(continent('NA')) then return 'true' else return 'false' end"
asnum.geo       IN LUA    TXT ";if(asnum('4242')) then return 'true' else return 'false' end"
country.geo     IN LUA    TXT ";if(country('US')) then return 'true' else return 'false' end"
latlonloc.geo   IN LUA    TXT "latlonloc()"

true.netmask     IN LUA   TXT   ( ";if(netmask({{ '{prefix}.0/24' }})) "
                                  "then return 'true'                  "
                                  "else return 'false'             end " )
false.netmask    IN LUA   TXT   ( ";if(netmask({{ '1.2.3.4/8' }}))     "
                                  "then return 'true'                  "
                                  "else return 'false'             end " )

view             IN    LUA    A          ("view({{                                       "
                                          "{{ {{'192.168.0.0/16'}}, {{'192.168.1.54'}}}},"
                                          "{{ {{'{prefix}.0/16'}}, {{'{prefix}.54'}}}},  "
                                          "{{ {{'0.0.0.0/0'}}, {{'192.0.2.1'}}}}         "
                                          " }})                                          " )
txt.view         IN    LUA    TXT        ("view({{                                       "
                                          "{{ {{'192.168.0.0/16'}}, {{'txt'}}}},         "
                                          "{{ {{'0.0.0.0/0'}}, {{'else'}}}}              "
                                          " }})                                          " )
none.view        IN    LUA    A          ("view({{                                     "
                                          "{{ {{'192.168.0.0/16'}}, {{'192.168.1.54'}}}},"
                                          "{{ {{'1.2.0.0/16'}}, {{'1.2.3.4'}}}},         "
                                          " }})                                          " )
*.magic          IN    LUA    A     "closestMagic()"
www-balanced     IN           CNAME 1-1-1-3.17-1-2-4.1-2-3-5.magic.example.org.

any              IN    LUA    A   "'192.0.2.1'"
any              IN           TXT "hello there"

        """,
    }
    _web_rrsets = []

    @classmethod
    def startResponders(cls):
        webserver = threading.Thread(name='HTTP Listener',
                                     target=cls.HTTPResponder,
                                     args=[8080]
        )
        webserver.setDaemon(True)
        webserver.start()

    @classmethod
    def HTTPResponder(cls, port):
        server_address = ('', port)
        httpd = HTTPServer(server_address, FakeHTTPServer)
        httpd.serve_forever()

    @classmethod
    def setUpClass(cls):

        super(TestLuaRecords, cls).setUpClass()

        cls._web_rrsets = [dns.rrset.from_text('web1.example.org.', 0, dns.rdataclass.IN, 'A',
                                               '{prefix}.101'.format(prefix=cls._PREFIX)),
                           dns.rrset.from_text('web2.example.org.', 0, dns.rdataclass.IN, 'A',
                                               '{prefix}.102'.format(prefix=cls._PREFIX)),
                           dns.rrset.from_text('web3.example.org.', 0, dns.rdataclass.IN, 'A',
                                               '{prefix}.103'.format(prefix=cls._PREFIX))
        ]

    def testPickRandom(self):
        """
        Basic pickrandom() test with a set of A records
        """
        expected = [dns.rrset.from_text('rand.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.101'.format(prefix=self._PREFIX)),
                    dns.rrset.from_text('rand.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.102'.format(prefix=self._PREFIX))]
        query = dns.message.make_query('rand.example.org', 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testBogusV6PickRandom(self):
        """
        Test a bogus AAAA pickrandom() record  with a set of v4 addr
        """
        query = dns.message.make_query('v6-bogus.rand.example.org', 'AAAA')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testV6PickRandom(self):
        """
        Test pickrandom() AAAA record
        """
        expected = [dns.rrset.from_text('v6.rand.example.org.', 0, dns.rdataclass.IN, 'AAAA',
                                        '2001:db8:a0b:12f0::1'),
                    dns.rrset.from_text('v6.rand.example.org.', 0, dns.rdataclass.IN, 'AAAA',
                                        'fe80::2a1:9bff:fe9b:f268')]
        query = dns.message.make_query('v6.rand.example.org', 'AAAA')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testEmptyRandom(self):
        """
        Basic pickrandom() test with an empty set
        """
        query = dns.message.make_query('empty.rand.example.org', 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

    def testWRandom(self):
        """
        Basic pickwrandom() test with a set of A records
        """
        expected = [dns.rrset.from_text('wrand.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.103'.format(prefix=self._PREFIX)),
                    dns.rrset.from_text('wrand.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.102'.format(prefix=self._PREFIX))]
        query = dns.message.make_query('wrand.example.org', 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testIfportup(self):
        """
        Basic ifportup() test
        """
        query = dns.message.make_query('all.ifportup.example.org', 'A')
        expected = [
            dns.rrset.from_text('all.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '{prefix}.101'.format(prefix=self._PREFIX)),
            dns.rrset.from_text('all.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '{prefix}.102'.format(prefix=self._PREFIX))]

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testIfportupWithSomeDown(self):
        """
        Basic ifportup() test with some ports DOWN
        """
        query = dns.message.make_query('some.ifportup.example.org', 'A')
        expected = [
            dns.rrset.from_text('some.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '192.168.42.21'),
            dns.rrset.from_text('some.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '{prefix}.102'.format(prefix=self._PREFIX))]

        # we first expect any of the IPs as no check has been performed yet
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

        # the first IP should not be up so only second shoud be returned
        expected = [expected[1]]
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testIfportupWithAllDown(self):
        """
        Basic ifportup() test with all ports DOWN
        """
        query = dns.message.make_query('none.ifportup.example.org', 'A')
        expected = [
            dns.rrset.from_text('none.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '192.168.42.21'),
            dns.rrset.from_text('none.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '192.168.21.42'.format(prefix=self._PREFIX))]

        # we first expect any of the IPs as no check has been performed yet
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

        # no port should be up so we expect any
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testIfportupWithAllDownAndAllBackupSelector(self):
        """
        Basic ifportup() test with all ports DOWN, fallback to 'all' backup selector
        """
        name = 'all.noneup.ifportup.example.org.'
        query = dns.message.make_query(name, dns.rdatatype.A)
        expected = [dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.A, '192.168.42.21', '192.168.21.42')]

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

        time.sleep(1)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, expected)

    def testIfurlup(self):
        """
        Basic ifurlup() test
        """
        reachable = [
            '{prefix}.103'.format(prefix=self._PREFIX)
        ]
        unreachable = ['192.168.42.101', '192.168.42.102']
        ips = reachable + unreachable
        all_rrs = []
        reachable_rrs = []
        for ip in ips:
            rr = dns.rrset.from_text('usa.example.org.', 0, dns.rdataclass.IN, 'A', ip)
            all_rrs.append(rr)
            if ip in reachable:
                reachable_rrs.append(rr)

        query = dns.message.make_query('usa.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

        time.sleep(1)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, reachable_rrs)

    def testIfurlupSimplified(self):
        """
        Basic ifurlup() test with the simplified list of ips
        Also ensures the correct path is queried
        """
        reachable = [
            '{prefix}.101'.format(prefix=self._PREFIX)
        ]
        unreachable = ['192.168.42.101']
        ips = reachable + unreachable
        all_rrs = []
        reachable_rrs = []
        for ip in ips:
            rr = dns.rrset.from_text('mix.ifurlup.example.org.', 0, dns.rdataclass.IN, 'A', ip)
            all_rrs.append(rr)
            if ip in reachable:
                reachable_rrs.append(rr)

        query = dns.message.make_query('mix.ifurlup.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

        time.sleep(1)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, reachable_rrs)

    def testLatlon(self):
        """
        Basic latlon() test
        """
        name = 'latlon.geo.example.org.'
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.0', 24)
        query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096, options=[ecso])
        expected = dns.rrset.from_text(name, 0,
                                       dns.rdataclass.IN, 'TXT',
                                       '"47.913000 -122.304200"')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)

    def testLatlonloc(self):
        """
        Basic latlonloc() test
        """
        name = 'latlonloc.geo.example.org.'
        expected = dns.rrset.from_text(name, 0,dns.rdataclass.IN, 'TXT',
                                       '"47 54 46.8 N 122 18 15.12 W 0.00m 1.00m 10000.00m 10.00m"')
        ecso = clientsubnetoption.ClientSubnetOption('1.2.3.0', 24)
        query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096, options=[ecso])

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertRRsetInAnswer(res, expected)

    def testWildcardError(self):
        """
        Ensure errors coming from LUA wildcards are reported
        """
        query = dns.message.make_query('failure.magic.example.org', 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    def testClosestMagic(self):
        """
        Basic closestMagic() test
        """
        name = 'www-balanced.example.org.'
        cname = '1-1-1-3.17-1-2-4.1-2-3-5.magic.example.org.'
        queries = [
            ('1.1.1.0', 24,  '1.1.1.3'),
            ('1.2.3.0', 24,  '1.2.3.5'),
            ('17.1.0.0', 16, '17.1.2.4')
        ]

        for (subnet, mask, ip) in queries:
            ecso = clientsubnetoption.ClientSubnetOption(subnet, mask)
            query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])

            response = dns.message.make_response(query)

            response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.CNAME, cname))
            response.answer.append(dns.rrset.from_text(cname, 0, dns.rdataclass.IN, 'A', ip))

            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertEqual(res.answer, response.answer)

    def testAsnum(self):
        """
        Basic asnum() test
        """
        queries = [
            ('1.1.1.0', 24,  '"true"'),
            ('1.2.3.0', 24,  '"false"'),
            ('17.1.0.0', 16, '"false"')
        ]
        name = 'asnum.geo.example.org.'
        for (subnet, mask, txt) in queries:
            ecso = clientsubnetoption.ClientSubnetOption(subnet, mask)
            query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096, options=[ecso])
            expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', txt)

            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testCountry(self):
        """
        Basic country() test
        """
        queries = [
            ('1.1.1.0', 24,  '"false"'),
            ('1.2.3.0', 24,  '"true"'),
            ('17.1.0.0', 16, '"false"')
        ]
        name = 'country.geo.example.org.'
        for (subnet, mask, txt) in queries:
            ecso = clientsubnetoption.ClientSubnetOption(subnet, mask)
            query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096, options=[ecso])
            expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', txt)

            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testContinent(self):
        """
        Basic continent() test
        """
        queries = [
            ('1.1.1.0', 24,  '"false"'),
            ('1.2.3.0', 24,  '"true"'),
            ('17.1.0.0', 16, '"false"')
        ]
        name = 'continent.geo.example.org.'
        for (subnet, mask, txt) in queries:
            ecso = clientsubnetoption.ClientSubnetOption(subnet, mask)
            query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096, options=[ecso])
            expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', txt)

            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testClosest(self):
        """
        Basic pickclosest() test
        """
        queries = [
            ('1.1.1.0', 24,  '1.1.1.2'),
            ('1.2.3.0', 24,  '1.2.3.4'),
            ('17.1.0.0', 16, '1.1.1.2')
        ]
        name = 'closest.geo.example.org.'
        for (subnet, mask, ip) in queries:
            ecso = clientsubnetoption.ClientSubnetOption(subnet, mask)
            query = dns.message.make_query(name, 'A', 'IN', use_edns=True, payload=4096, options=[ecso])
            expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', ip)

            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testNetmask(self):
        """
        Basic netmask() test
        """
        queries = [
            {
                'expected': dns.rrset.from_text('true.netmask.example.org.', 0,
                                       dns.rdataclass.IN, 'TXT',
                                       '"true"'),
                'query': dns.message.make_query('true.netmask.example.org', 'TXT')
            },
            {
                'expected': dns.rrset.from_text('false.netmask.example.org.', 0,
                                       dns.rdataclass.IN, 'TXT',
                                       '"false"'),
                'query': dns.message.make_query('false.netmask.example.org', 'TXT')
            }
        ]
        for query in queries :
            res = self.sendUDPQuery(query['query'])
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, query['expected'])

    def testView(self):
        """
        Basic view() test
        """
        queries = [
            {
                'expected': dns.rrset.from_text('view.example.org.', 0,
                                       dns.rdataclass.IN, 'A',
                                       '{prefix}.54'.format(prefix=self._PREFIX)),
                'query': dns.message.make_query('view.example.org', 'A')
            },
            {
                'expected': dns.rrset.from_text('txt.view.example.org.', 0,
                                       dns.rdataclass.IN, 'TXT',
                                       '"else"'),
                'query': dns.message.make_query('txt.view.example.org', 'TXT')
            }
        ]
        for query in queries :
            res = self.sendUDPQuery(query['query'])
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, query['expected'])

    def testViewNoMatch(self):
        """
        view() test where no netmask match
        """
        query = dns.message.make_query('none.view.example.org', 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)
        self.assertAnswerEmpty(res)

    def testWHashed(self):
        """
        Basic pickwhashed() test with a set of A records
        As the `bestwho` is hashed, we should always get the same answer
        """
        expected = [dns.rrset.from_text('whashed.example.org.', 0, dns.rdataclass.IN, 'A', '1.2.3.4'),
                    dns.rrset.from_text('whashed.example.org.', 0, dns.rdataclass.IN, 'A', '4.3.2.1')]
        query = dns.message.make_query('whashed.example.org', 'A')

        first = self.sendUDPQuery(query)
        self.assertRcodeEqual(first, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(first, expected)
        for _ in range(5):
            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, first.answer[0])

    def testTimeout(self):
        """
        Test if LUA scripts are aborted if script execution takes too long
        """
        query = dns.message.make_query('timeout.example.org', 'A')

        first = self.sendUDPQuery(query)
        self.assertRcodeEqual(first, dns.rcode.SERVFAIL)


    def testA(self):
        """
        Test A query against `any`
        """
        name = 'any.example.org.'

        query = dns.message.make_query(name, 'A')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, response.answer)

    def testANY(self):
        """
        Test ANY query against `any`
        """

        name = 'any.example.org.'

        query = dns.message.make_query(name, 'ANY')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.A, '192.0.2.1'))
        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', '"hello there"'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(self.sortRRsets(res.answer), self.sortRRsets(response.answer))

if __name__ == '__main__':
    unittest.main()
    exit(0)
