#!/usr/bin/env python
import unittest
import threading
import dns
import time
import clientsubnetoption

from authtests import AuthTest

from http.server import BaseHTTPRequestHandler, HTTPServer

webserver = None

class FakeHTTPServer(BaseHTTPRequestHandler):
    def _set_headers(self, response_code=200):
        self.send_response(response_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if self.path == '/404':
            self._set_headers(404)
            self.wfile.write(bytes('this page does not exist', 'utf-8'))
            return

        self._set_headers()
        if self.path == '/ping.json':
            self.wfile.write(bytes('{"ping":"pong"}', 'utf-8'))
        if self.path == '/weight.txt':
            self.wfile.write(bytes('12', 'utf-8'))
        else:
            self.wfile.write(bytes("<html><body><h1>hi!</h1><h2>Programming in Lua !</h2></body></html>", "utf-8"))

    def log_message(self, format, *args):
        return

    def do_HEAD(self):
        self._set_headers()

class BaseLuaTest(AuthTest):
    _config_template = """
geoip-database-files=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb
edns-subnet-processing=yes
launch={backend} geoip
any-to-tcp=no
enable-lua-records
lua-records-insert-whitespace=yes
lua-health-checks-interval=1
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
multi.ifportup               3600 IN LUA  A     "ifportup(8080, {{ {{'192.168.42.23'}}, {{'192.168.42.21', '{prefix}.102'}}, {{'{prefix}.101'}} }})"
none.ifportup                3600 IN LUA  A     "ifportup(8080, {{'192.168.42.21', '192.168.21.42'}})"
all.noneup.ifportup          3600 IN LUA  A     "ifportup(8080, {{'192.168.42.21', '192.168.21.42'}}, {{ backupSelector='all' }})"

hashed.example.org.          3600 IN LUA  A     "pickhashed({{ '1.2.3.4', '4.3.2.1' }})"
hashed-v6.example.org.       3600 IN LUA  AAAA  "pickhashed({{ '2001:db8:a0b:12f0::1', 'fe80::2a1:9bff:fe9b:f268' }})"
hashed-txt.example.org.      3600 IN LUA  TXT   "pickhashed({{ 'bob', 'alice' }})"
whashed.example.org.         3600 IN LUA  A     "pickwhashed({{ {{15, '1.2.3.4'}}, {{42, '4.3.2.1'}} }})"
*.namehashed.example.org.    3600 IN LUA  A     "picknamehashed({{ {{15, '1.2.3.4'}}, {{42, '4.3.2.1'}} }})"
whashed-txt.example.org.     3600 IN LUA  TXT   "pickwhashed({{ {{15, 'bob'}}, {{42, 'alice'}} }})"
chashed.example.org.         3600 IN LUA  A     "pickchashed({{ {{15, '1.2.3.4'}}, {{42, '4.3.2.1'}} }})"
chashed-txt.example.org.     3600 IN LUA  TXT   "pickchashed({{ {{15, 'bob'}}, {{42, 'alice'}} }})"
rand.example.org.            3600 IN LUA  A     "pickrandom({{'{prefix}.101', '{prefix}.102'}})"
rand-txt.example.org.        3600 IN LUA  TXT   "pickrandom({{ 'bob', 'alice' }})"
randn-txt.example.org.       3600 IN LUA  TXT   "pickrandomsample( 2, {{ 'bob', 'alice', 'john' }} )"
v6-bogus.rand.example.org.   3600 IN LUA  AAAA  "pickrandom({{'{prefix}.101', '{prefix}.102'}})"
v6.rand.example.org.         3600 IN LUA  AAAA  "pickrandom({{ '2001:db8:a0b:12f0::1', 'fe80::2a1:9bff:fe9b:f268' }})"
selfweighted.example.org.    3600 IN LUA  A     "pickselfweighted('http://selfweighted.example.org:8080/weight.txt',{{'{prefix}.101', '{prefix}.102'}})"
closest.geo                  3600 IN LUA  A     "pickclosest({{ '1.1.1.2', '1.2.3.4' }})"
empty.rand.example.org.      3600 IN LUA  A     "pickrandom()"
timeout.example.org.         3600 IN LUA  A     "; local i = 0 ;  while i < 1000 do pickrandom() ; i = i + 1 end return '1.2.3.4'"
wrand.example.org.           3600 IN LUA  A     "pickwrandom({{ {{30, '{prefix}.102'}}, {{15, '{prefix}.103'}} }})"
wrand-txt.example.org.       3600 IN LUA  TXT   "pickwrandom({{ {{30, 'bob'}}, {{15, 'alice'}} }})"
all.example.org.             3600 IN LUA  A     "all({{'1.2.3.4','4.3.2.1'}})"

config    IN    LUA    LUA ("settings={{stringmatch='Programming in Lua'}} "
                            "EUWips={{'{prefix}.101','{prefix}.102'}}      "
                            "EUEips={{'192.168.42.101','192.168.42.102'}}  "
                            "NLips={{'{prefix}.111', '{prefix}.112'}}      "
                            "USAips={{'{prefix}.103', '192.168.42.105'}}   ")

usa          IN    LUA    A   ( ";include('config')                         "
                                "return ifurlup('http://www.lua.org:8080/', "
                                "USAips, settings)                          ")

usa-ext      IN    LUA    A   ( ";include('config')                         "
                                "return ifurlup('http://www.lua.org:8080/', "
                                "{{EUEips, USAips}}, settings)              ")

usa-unreachable IN LUA    A   ( ";settings={{stringmatch='Programming in Lua', minimumFailures=2}} "
                                "USAips={{'{prefix}.103', '192.168.42.105'}}"
                                "return ifurlup('http://www.lua.org:8080/', "
                                "USAips, settings)                          ")

usa-slowcheck IN   LUA    A   ( ";settings={{stringmatch='Programming in Lua', interval=8}} "
                                "USAips={{'{prefix}.103', '192.168.42.105'}}"
                                "return ifurlup('http://www.lua.org:8080/', "
                                "USAips, settings)                          ")

usa-failincomplete IN LUA A   ( ";settings={{stringmatch='Programming in Lua', failOnIncompleteCheck='true'}} "
                                "USAips={{'192.168.42.105'}}"
                                "return ifurlup('http://www.lua.org:8080/', "
                                "USAips, settings)                          ")

mix.ifurlup  IN    LUA    A   ("ifurlup('http://www.other.org:8080/ping.json', "
                               "{{ '192.168.42.101', '{prefix}.101' }},        "
                               "{{ stringmatch='pong' }})                      ")

usa-404      IN    LUA    A   ( ";include('config')                         "
                                "return ifurlup('http://www.lua.org:8080/404', "
                                "USAips, {{ httpcode='404' }})              ")

ifurlextup   IN    LUA    A   "ifurlextup({{{{['192.168.0.1']='http://{prefix}.101:8080/404',['192.168.0.2']='http://{prefix}.102:8080/404'}}, {{['192.168.0.3']='http://{prefix}.101:8080/'}}}})"

nl           IN    LUA    A   ( ";include('config')                                "
                                "return ifportup(8081, NLips) ")
latlon.geo      IN LUA    TXT "latlon()"
continent.geo   IN LUA    TXT ";if(continent('NA')) then return 'true' else return 'false' end"
continent-code.geo   IN LUA    TXT ";return continentCode()"
asnum.geo       IN LUA    TXT ";if(asnum('4242')) then return 'true' else return 'false' end"
country.geo     IN LUA    TXT ";if(country('US')) then return 'true' else return 'false' end"
country-code.geo     IN LUA    TXT ";return countryCode()"
region.geo      IN LUA    TXT ";if(region('CA')) then return 'true' else return 'false' end"
region-code.geo      IN LUA    TXT ";return regionCode()"
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

resolve          IN    LUA    A   ";local r=resolve('localhost', 1) local t={{}} for _,v in ipairs(r) do table.insert(t, v:toString()) end return t"

filterforwardempty IN LUA A "filterForward('192.0.2.1', newNMG{{'192.1.2.0/24'}}, '')"

*.createforward  IN    LUA    A     "filterForward(createForward(), newNMG{{'1.0.0.0/8', '64.0.0.0/8'}})"
*.createforward6 IN    LUA    AAAA  "filterForward(createForward6(), newNMG{{'2000::/3'}}, 'fe80::1')"
*.no-filter.createforward6    IN    LUA    AAAA  "createForward6()"
*.createreverse  IN    LUA    PTR   "createReverse('%5%.example.com', {{['10.10.10.10'] = 'quad10.example.com.'}})"
*.createreverse6 IN    LUA    PTR   "createReverse6('%33%.example.com', {{['2001:db8::1'] = 'example.example.com.'}})"

newcafromraw     IN    LUA    A    "newCAFromRaw('ABCD'):toString()"
newcafromraw     IN    LUA    AAAA "newCAFromRaw('ABCD020340506070'):toString()"

counter          IN    LUA    TXT  ";counter = counter or 0 counter=counter+1 return tostring(counter)"

lookmeup         IN           A  192.0.2.5
dblookup         IN    LUA    A  "dblookup('lookmeup.example.org', pdns.A)[1]"

whitespace       IN    LUA    TXT "'foo" "bar'"
geoipqueryattribute IN LUA    TXT ("string.format('%d %d %d %d %d %d %d',"
                                   "GeoIPQueryAttribute.ASn, GeoIPQueryAttribute.City, GeoIPQueryAttribute.Continent,"
                                   "GeoIPQueryAttribute.Country, GeoIPQueryAttribute.Country2, GeoIPQueryAttribute.Name,"
                                   "GeoIPQueryAttribute.Region, GeoIPQueryAttribute.Location)")
        """
    }
    _web_rrsets = []

    @classmethod
    def startResponders(cls):
        global webserver
        if webserver: return  # it is already running

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

        super(BaseLuaTest, cls).setUpClass()

        cls._web_rrsets = [dns.rrset.from_text('web1.example.org.', 0, dns.rdataclass.IN, 'A',
                                               '{prefix}.101'.format(prefix=cls._PREFIX)),
                           dns.rrset.from_text('web2.example.org.', 0, dns.rdataclass.IN, 'A',
                                               '{prefix}.102'.format(prefix=cls._PREFIX)),
                           dns.rrset.from_text('web3.example.org.', 0, dns.rdataclass.IN, 'A',
                                               '{prefix}.103'.format(prefix=cls._PREFIX))
        ]

class TestLuaRecords(BaseLuaTest):

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

    def testPickRandomTxt(self):
        """
        Basic pickrandom() test with a set of TXT records
        """
        expected = [dns.rrset.from_text('rand-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'bob'),
                    dns.rrset.from_text('rand-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'alice')]
        query = dns.message.make_query('rand-txt.example.org', 'TXT')

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

    def testSelfWeighted(self):
        """
        Test the selfweighted() function with a set of A records
        """
        expected = [dns.rrset.from_text('selfweighted.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.101'.format(prefix=self._PREFIX)),
                    dns.rrset.from_text('selfweighted.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.102'.format(prefix=self._PREFIX))]
        query = dns.message.make_query('selfweighted.example.org', 'A')
        self.sendUDPQuery(query)

        # wait for health checks to happen
        time.sleep(3)

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testPickRandomSampleTxt(self):
        """
        Basic pickrandomsample() test with a set of TXT records
        """
        expected = [dns.rrset.from_text('randn-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'bob', 'alice'),
                    dns.rrset.from_text('randn-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'bob', 'john'),
                    dns.rrset.from_text('randn-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'alice', 'bob'),
                    dns.rrset.from_text('randn-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'alice', 'john'),
                    dns.rrset.from_text('randn-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'john', 'bob'),
                    dns.rrset.from_text('randn-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'john', 'alice')]
        query = dns.message.make_query('randn-txt.example.org', 'TXT')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertIn(res.answer[0], expected)

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

    def testWRandomTxt(self):
        """
        Basic pickwrandom() test with a set of TXT records
        """
        expected = [dns.rrset.from_text('wrand-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'bob'),
                    dns.rrset.from_text('wrand-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'alice')]
        query = dns.message.make_query('wrand-txt.example.org', 'TXT')

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

        # the first IP should not be up so only second should be returned
        expected = [expected[1]]
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

    def testIfportupWithSomeDownMultiset(self):
        """
        Basic ifportup() test with some ports DOWN from multiple sets
        """
        query = dns.message.make_query('multi.ifportup.example.org', 'A')
        expected = [
            dns.rrset.from_text('multi.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '192.168.42.21'),
            dns.rrset.from_text('multi.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '192.168.42.23'),
            dns.rrset.from_text('multi.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '{prefix}.102'.format(prefix=self._PREFIX)),
            dns.rrset.from_text('multi.ifportup.example.org.', 0, dns.rdataclass.IN, 'A',
                                '{prefix}.101'.format(prefix=self._PREFIX))
        ]

        # we first expect any of the IPs as no check has been performed yet
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

        # An ip is up in 2 sets, but we expect only the one from the middle set
        expected = [expected[2]]
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

        time.sleep(3)
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
        unreachable = ['192.168.42.105']
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

        # the timeout in the LUA health checker is 1 second, so we make sure to wait slightly longer here
        time.sleep(3)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, reachable_rrs)

    def testIfurlupHTTPCode(self):
        """
        Basic ifurlup() test, with non-default HTTP code
        """
        reachable = [
            '{prefix}.103'.format(prefix=self._PREFIX)
        ]
        unreachable = ['192.168.42.105']
        ips = reachable + unreachable
        all_rrs = []
        reachable_rrs = []
        for ip in ips:
            rr = dns.rrset.from_text('usa-404.example.org.', 0, dns.rdataclass.IN, 'A', ip)
            all_rrs.append(rr)
            if ip in reachable:
                reachable_rrs.append(rr)

        query = dns.message.make_query('usa-404.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

        # the timeout in the LUA health checker is 2 second, so we make sure to wait slightly longer here
        time.sleep(3)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, reachable_rrs)

    def testIfurlupMultiSet(self):
        """
        Basic ifurlup() test with mutiple sets
        """
        reachable = [
            '{prefix}.103'.format(prefix=self._PREFIX)
        ]
        unreachable = ['192.168.42.101', '192.168.42.102', '192.168.42.105']
        ips = reachable + unreachable
        all_rrs = []
        reachable_rrs = []
        for ip in ips:
            rr = dns.rrset.from_text('usa-ext.example.org.', 0, dns.rdataclass.IN, 'A', ip)
            all_rrs.append(rr)
            if ip in reachable:
                reachable_rrs.append(rr)

        query = dns.message.make_query('usa-ext.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

        # the timeout in the LUA health checker is 1 second, so we make sure to wait slightly longer here
        time.sleep(3)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, reachable_rrs)

    def testIfurlextup(self):
        expected = [dns.rrset.from_text('ifurlextup.example.org.', 0, dns.rdataclass.IN, dns.rdatatype.A, '192.168.0.3')]

        query = dns.message.make_query('ifurlextup.example.org', 'A')
        self.sendUDPQuery(query)

        # wait for health checks to happen
        time.sleep(5)

        res = self.sendUDPQuery(query)

        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, expected)

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

        time.sleep(3)
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

    def testCountryCode(self):
        """
        Basic countryCode() test
        """
        queries = [
            ('1.1.1.0', 24,  '"au"'),
            ('1.2.3.0', 24,  '"us"'),
            ('17.1.0.0', 16, '"--"')
        ]
        name = 'country-code.geo.example.org.'
        for (subnet, mask, txt) in queries:
            ecso = clientsubnetoption.ClientSubnetOption(subnet, mask)
            query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096, options=[ecso])
            expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', txt)

            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testRegion(self):
        """
        Basic region() test
        """
        queries = [
            ('1.1.1.0', 24,  '"false"'),
            ('1.2.3.0', 24,  '"true"'),
            ('17.1.0.0', 16, '"false"')
        ]
        name = 'region.geo.example.org.'
        for (subnet, mask, txt) in queries:
            ecso = clientsubnetoption.ClientSubnetOption(subnet, mask)
            query = dns.message.make_query(name, 'TXT', 'IN', use_edns=True, payload=4096, options=[ecso])
            expected = dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'TXT', txt)

            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, expected)

    def testRegionCode(self):
        """
        Basic regionCode() test
        """
        queries = [
            ('1.1.1.0', 24,  '"--"'),
            ('1.2.3.0', 24,  '"ca"'),
            ('17.1.0.0', 16, '"--"')
        ]
        name = 'region-code.geo.example.org.'
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

    def testContinentCode(self):
        """
        Basic continentCode() test
        """
        queries = [
            ('1.1.1.0', 24,  '"oc"'),
            ('1.2.3.0', 24,  '"na"'),
            ('17.1.0.0', 16, '"--"')
        ]
        name = 'continent-code.geo.example.org.'
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

    def testAll(self):
        """
        Basic all() test
        """
        expected = [dns.rrset.from_text('all.example.org.', 0, dns.rdataclass.IN, dns.rdatatype.A, '1.2.3.4', '4.3.2.1')]
        query = dns.message.make_query('all.example.org.', 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, expected)

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

    def testCWHashed(self):
        """
        Basic pickwhashed() and pickchashed() test with a set of A records
        As the `bestwho` is hashed, we should always get the same answer
        """
        for qname in ['whashed.example.org.', 'chashed.example.org.']:
            expected = [dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '1.2.3.4'),
                        dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'A', '4.3.2.1')]
            query = dns.message.make_query(qname, 'A')

            first = self.sendUDPQuery(query)
            self.assertRcodeEqual(first, dns.rcode.NOERROR)
            self.assertAnyRRsetInAnswer(first, expected)
            for _ in range(5):
                res = self.sendUDPQuery(query)
                self.assertRcodeEqual(res, dns.rcode.NOERROR)
                self.assertRRsetInAnswer(res, first.answer[0])

    def testNamehashed(self):
        """
        Basic picknamehashed() test with a set of A records
        As the name is hashed, we should always get the same IP back for the same record name.
        """

        queries = [
            {
                'query': dns.message.make_query('test.namehashed.example.org', 'A'),
                'expected': dns.rrset.from_text('test.namehashed.example.org.', 0,
                                       dns.rdataclass.IN, 'A',
                                       '1.2.3.4'),
            },
            {
                'query': dns.message.make_query('test2.namehashed.example.org', 'A'),
                'expected': dns.rrset.from_text('test2.namehashed.example.org.', 0,
                                       dns.rdataclass.IN, 'A',
                                       '4.3.2.1'),
            }
        ]
        for query in queries :
            res = self.sendUDPQuery(query['query'])
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, query['expected'])

    def testCWHashedTxt(self):
        """
        Basic pickwhashed() test with a set of TXT records
        As the `bestwho` is hashed, we should always get the same answer
        """
        for qname in ['whashed-txt.example.org.', 'chashed-txt.example.org.']:
            expected = [dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'TXT', 'bob'),
                        dns.rrset.from_text(qname, 0, dns.rdataclass.IN, 'TXT', 'alice')]
            query = dns.message.make_query(qname,'TXT')

            first = self.sendUDPQuery(query)
            self.assertRcodeEqual(first, dns.rcode.NOERROR)
            self.assertAnyRRsetInAnswer(first, expected)
            for _ in range(5):
                res = self.sendUDPQuery(query)
                self.assertRcodeEqual(res, dns.rcode.NOERROR)
                self.assertRRsetInAnswer(res, first.answer[0])

    def testHashed(self):
        """
        Basic pickhashed() test with a set of A records
        As the `bestwho` is hashed, we should always get the same answer
        """
        expected = [dns.rrset.from_text('hashed.example.org.', 0, dns.rdataclass.IN, 'A', '1.2.3.4'),
                    dns.rrset.from_text('hashed.example.org.', 0, dns.rdataclass.IN, 'A', '4.3.2.1')]
        query = dns.message.make_query('hashed.example.org', 'A')

        first = self.sendUDPQuery(query)
        self.assertRcodeEqual(first, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(first, expected)
        for _ in range(5):
            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, first.answer[0])

    def testHashedV6(self):
        """
        Basic pickhashed() test with a set of AAAA records
        As the `bestwho` is hashed, we should always get the same answer
        """
        expected = [dns.rrset.from_text('hashed-v6.example.org.', 0, dns.rdataclass.IN, 'AAAA', '2001:db8:a0b:12f0::1'),
                    dns.rrset.from_text('hashed-v6.example.org.', 0, dns.rdataclass.IN, 'AAAA', 'fe80::2a1:9bff:fe9b:f268')]
        query = dns.message.make_query('hashed-v6.example.org', 'AAAA')

        first = self.sendUDPQuery(query)
        self.assertRcodeEqual(first, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(first, expected)
        for _ in range(5):
            res = self.sendUDPQuery(query)
            self.assertRcodeEqual(res, dns.rcode.NOERROR)
            self.assertRRsetInAnswer(res, first.answer[0])

    def testHashedTXT(self):
        """
        Basic pickhashed() test with a set of TXT records
        As the `bestwho` is hashed, we should always get the same answer
        """
        expected = [dns.rrset.from_text('hashed-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'bob'),
                    dns.rrset.from_text('hashed-txt.example.org.', 0, dns.rdataclass.IN, 'TXT', 'alice')]
        query = dns.message.make_query('hashed-txt.example.org', 'TXT')

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

    def testCAFromRaw(self):
        """
        Test newCAFromRaw() function
        """
        name = 'newcafromraw.example.org.'

        query = dns.message.make_query(name, 'A')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.A, '65.66.67.68'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, response.answer)

        query = dns.message.make_query(name, 'AAAA')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.AAAA, '4142:4344:3032:3033:3430:3530:3630:3730'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, response.answer)

    def testResolve(self):
        """
        Test resolve() function
        """
        name = 'resolve.example.org.'

        query = dns.message.make_query(name, 'A')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.A, '127.0.0.1'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, response.answer)

    def testFilterForwardEmpty(self):
        """
        Test filterForward() function with empty fallback
        """
        name = 'filterforwardempty.example.org.'

        query = dns.message.make_query(name, 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, [])

    def testCreateForwardAndReverse(self):
        expected = {
            ".createforward.example.org." : (dns.rdatatype.A, {
                "1.2.3.4": "1.2.3.4",
                "1.2.3.4.static": "1.2.3.4",
                "1.2.3.4.5.6": "1.2.3.4",
                "invalid.1.2.3.4": "0.0.0.0",
                "invalid": "0.0.0.0",
                "1-2-3-4": "1.2.3.4",
                "1-2-3-4.foo": "1.2.3.4",
                "1-2-3-4.foo.bar": "1.2.3.4",
                "1-2-3-4.foo.bar.baz": "0.0.0.0",
                "1-2-3-4.foo.bar.baz.quux": "0.0.0.0",
                "ip-1-2-3-4": "1.2.3.4",
                "ip-is-here-for-you-1-2-3-4": "1.2.3.4",
                "40414243": "64.65.66.67",
                "p40414243": "64.65.66.67",
                "ip40414243": "64.65.66.67",
                "ipp40414243": "64.65.66.67",
                "ip4041424": "0.0.0.0",
                "ip-441424": "0.0.0.0",
                "ip-5abcdef": "0.0.0.0",
                "host64-22-33-44": "64.22.33.44",
                "2.2.2.2": "0.0.0.0"   # filtered
            }),
            ".createreverse.example.org." : (dns.rdatatype.PTR, {
                "4.3.2.1": "1-2-3-4.example.com.",
                "10.10.10.10": "quad10.example.com."   # exception
            }),
            ".createforward6.example.org." : (dns.rdatatype.AAAA, {
                "2001--db8" : "2001::db8",
                "20010002000300040005000600070db8" : "2001:2:3:4:5:6:7:db8",
                "blabla20010002000300040005000600070db8" : "2001:2:3:4:5:6:7:db8",
                "4000-db8--1" : "fe80::1",   # filtered, with fallback address override
                "l1.l2.l3.l4.l5.l6.l7.l8" : "fe80::1"
            }),
            ".createreverse6.example.org." : (dns.rdatatype.PTR, {
                "8.b.d.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2" : "2001--db8.example.com.",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2" : "example.example.com."   # exception
            })
        }

        for suffix, v in expected.items():
            qtype, pairs = v
            for prefix, target in pairs.items():
                name = prefix + suffix

                query = dns.message.make_query(name, qtype)
                response = dns.message.make_response(query)
                response.answer.append(dns.rrset.from_text(
                    name, 0, dns.rdataclass.IN, qtype, target))

                res = self.sendUDPQuery(query)
                print(res)
                self.assertRcodeEqual(res, dns.rcode.NOERROR)
                self.assertEqual(res.answer, response.answer)

    def testCreateForwardAndReverseWithZero(self):
        """
        Fix #7524
        """
        expected = {
            ".no-filter.createforward6.example.org." : (dns.rdatatype.AAAA, {
                "0--0" : "::",
                "0--1" : "::1",
                "0aa--0" : "aa::",
                "0aa--1" : "aa::1",
                "2001--0" : "2001::",
                "a-b--c" : "a:b::c",
                "a--b-c" : "a::b:c"
            }),
            ".createreverse6.example.org." : (dns.rdatatype.PTR, {
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0" : "0--0.example.com.",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0" : "0--1.example.com.",
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.a.0.0" : "0aa--0.example.com.",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.a.0.0" : "0aa--1.example.com.",
                "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2" : "2001--0.example.com.",
                "c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.0.0.0.a.0.0.0" : "a-b--c.example.com.",
                "c.0.0.0.b.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0" : "a--b-c.example.com."
            })
        }

        for suffix, v in expected.items():
            qtype, pairs = v
            for prefix, target in pairs.items():
                name = prefix + suffix

                query = dns.message.make_query(name, qtype)
                response = dns.message.make_response(query)
                response.answer.append(dns.rrset.from_text(
                    name, 0, dns.rdataclass.IN, qtype, target))

                res = self.sendUDPQuery(query)
                print(res)
                self.assertRcodeEqual(res, dns.rcode.NOERROR)
                self.assertEqual(res.answer, response.answer)

    def _getCounter(self, tcp=False):
        """
        Helper function for shared/non-shared testing
        """
        name = 'counter.example.org.'

        query = dns.message.make_query(name, 'TXT')
        responses = []

        sender = self.sendTCPQuery if tcp else self.sendUDPQuery

        for i in range(50):
            res = sender(query)
            responses.append(res.answer[0][0])

        return(responses)

    def testCounter(self):
        """
        Test non-shared behaviour
        """

        resUDP = set(self._getCounter(tcp=False))
        resTCP = set(self._getCounter(tcp=True))

        self.assertEqual(len(resUDP), 1)
        self.assertEqual(len(resTCP), 1)

    def testDblookup(self):
        """
        Test dblookup() function
        """

        name = 'dblookup.example.org.'

        query = dns.message.make_query(name, 'A')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.5'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(self.sortRRsets(res.answer), self.sortRRsets(response.answer))

    def testWhitespace(self, expectws=True):
        """
        Test TXT query for whitespace
        """
        name = 'whitespace.example.org.'

        query = dns.message.make_query(name, 'TXT')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.TXT, '"foo   bar"' if expectws else '"foobar"'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, response.answer)

    def testGeoIPQueryAttribute(self):
        """
        Test GeoIPQueryAttribute enum
        """
        name = 'geoipqueryattribute.example.org.'

        query = dns.message.make_query(name, 'TXT')

        response = dns.message.make_response(query)

        response.answer.append(dns.rrset.from_text(name, 0, dns.rdataclass.IN, dns.rdatatype.TXT, '"0 1 2 3 4 5 6"'))

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertEqual(res.answer, response.answer)


class TestLuaRecordsShared(TestLuaRecords):
    # The lua-records-exec-limit parameter needs to be increased from the
    # default value of 1000, for the testGeoIPQueryAttribute test would hit
    # the limit.
    _config_template = """
geoip-database-files=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb
edns-subnet-processing=yes
launch={backend} geoip
any-to-tcp=no
enable-lua-records=shared
lua-records-insert-whitespace=yes
lua-health-checks-interval=1
"""

    def testCounter(self):
        """
        Test shared behaviour
        """

        resUDP = set(self._getCounter(tcp=False))
        resTCP = set(self._getCounter(tcp=True))

        self.assertEqual(len(resUDP), 50)
        self.assertEqual(len(resTCP), 50)

class TestLuaRecordsNoWhiteSpace(TestLuaRecords):
    _config_template = """
geoip-database-files=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb
edns-subnet-processing=yes
launch={backend} geoip
any-to-tcp=no
enable-lua-records
lua-records-insert-whitespace=no
lua-health-checks-interval=1
"""

    def testWhitespace(self):
        return TestLuaRecords.testWhitespace(self, False)

class TestLuaRecordsSlowTimeouts(BaseLuaTest):
     # This configuration is similar to BaseLuaTest, but the health check
     # interval is increased to 5 seconds.
    _config_template = """
geoip-database-files=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb
edns-subnet-processing=yes
launch={backend} geoip
any-to-tcp=no
enable-lua-records
lua-records-insert-whitespace=yes
lua-health-checks-interval=5
"""

    def testIfurlupMinimumFailures(self):
        """
        Simple ifurlup() test with minimumFailures option set.
        """
        reachable = [
            '{prefix}.103'.format(prefix=self._PREFIX)
        ]
        unreachable = ['192.168.42.105']
        ips = reachable + unreachable
        all_rrs = []
        reachable_rrs = []
        unreachable_rrs = []
        for ip in ips:
            rr = dns.rrset.from_text('usa-unreachable.example.org.', 0, dns.rdataclass.IN, 'A', ip)
            all_rrs.append(rr)
            if ip in reachable:
                reachable_rrs.append(rr)
            else:
                unreachable_rrs.append(rr)

        query = dns.message.make_query('usa-unreachable.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

        # The above request being sent at time T, the following events occur:
        # T+00: results computed using backupSelector as no data available yet
        # T+00: checker thread starts
        # T+02: 192.168.42.105 found down, first time, still kept up
        # T+05: checker thread wakes up, decides to skip 192.168.42.105 check,
        #       as its last update time was T+02, hence no check until T+07
        # T+10: checker thread wakes up
        # T+12: 192.168.42.105 found down, second time, finally marked down

        # Due to minimumFailures set, there should be no error yet.
        time.sleep(5)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

        # Wait for another check. At this point the checker thread should have
        # reached the minimumFailures threshold and mark the unreachable IP
        # as such.
        time.sleep(8)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, reachable_rrs)
        self.assertNoneRRsetInAnswer(res, unreachable_rrs)

    def testIfurlupInterval(self):
        """
        Simple ifurlup() test with interval option set.
        """
        reachable = [
            '{prefix}.103'.format(prefix=self._PREFIX)
        ]
        unreachable = ['192.168.42.105']
        ips = reachable + unreachable
        all_rrs = []
        reachable_rrs = []
        unreachable_rrs = []
        for ip in ips:
            rr = dns.rrset.from_text('usa-slowcheck.example.org.', 0, dns.rdataclass.IN, 'A', ip)
            all_rrs.append(rr)
            if ip in reachable:
                reachable_rrs.append(rr)
            else:
                unreachable_rrs.append(rr)

        query = dns.message.make_query('usa-slowcheck.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

        # the timeout in the LUA health checker is 5 second, but usa-slowcheck
        # uses 8 seconds, which forces the thread to run every second (gcd
        # of 5 and 8).
        time.sleep(6)

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        # due to minimumFailures set, there should be no error yet
        self.assertAnyRRsetInAnswer(res, all_rrs)

        # At this point the check should have fired.
        time.sleep(3)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, reachable_rrs)
        self.assertNoneRRsetInAnswer(res, unreachable_rrs)

    def testIfurlupFailOnIncompleteCheck(self):
        """
        Simple ifurlup() test with failOnIncompleteCheck option set.
        """
        ips = ['192.168.42.105']
        all_rrs = []
        for ip in ips:
            rr = dns.rrset.from_text('usa-failincomplete.example.org.', 0, dns.rdataclass.IN, 'A', ip)
            all_rrs.append(rr)

        query = dns.message.make_query('usa-failincomplete.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

        # The above request being sent at time T, the following events occur:
        # T+00: SERVFAIL returned as no data available yet
        # T+00: checker thread starts
        # T+02: 192.168.42.105 found down and marked as such

        time.sleep(3)
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, all_rrs)

class TestLuaRecordsExecLimit(BaseLuaTest):
     # This configuration is similar to BaseLuaTest, but the exec limit is
     # set to a very low value.
    _config_template = """
geoip-database-files=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb
edns-subnet-processing=yes
launch={backend} geoip
any-to-tcp=no
enable-lua-records
lua-records-insert-whitespace=yes
lua-records-exec-limit=1
"""

    def testA(self):
        """
        Test A query against `any`, failing due to exec-limit
        """
        name = 'any.example.org.'

        query = dns.message.make_query(name, 'A')

        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.SERVFAIL)

if __name__ == '__main__':
    unittest.main()
    exit(0)
