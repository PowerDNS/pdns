import clientsubnetoption
import cookiesoption
import dns
import os

from recursortests import RecursorTest

class GettagRecursorTest(RecursorTest):
    _confdir = 'LuaGettag'
    _config_template = """
    log-common-errors=yes
    gettag-needs-edns-options=yes
    """
    _lua_dns_script_file = """
    function gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp)

      local tags = {}
      local data = {}

      -- make sure we can pass data around to the other hooks
      data['canary'] = 'from-gettag'

      -- test that the remote addr is valid
      if remote:toString() ~= '127.0.0.1' then
        pdnslog("invalid remote")
        table.insert(tags, 'invalid remote '..remote:toString())
        return 1, tags, data
      end

      -- test that the local addr is valid
      if localip:toString() ~= '127.0.0.1' then
        pdnslog("invalid local")
        table.insert(tags, 'invalid local '..localip:toString())
        return 1, tags, data
      end

      if not ednssubnet:empty() then
         table.insert(tags, 'edns-subnet-'..ednssubnet:toString())
      end

      for k,v in pairs(ednsoptions) do
        table.insert(tags, 'ednsoption-'..k..'-count-'..v:count())
        local len = 0
        local values = v:getValues()
        for j,l in pairs(values) do
          len = len + l:len()

          -- check that the old interface (before 4.2.0) still works
          if j == 0 then
            if l:len() ~= v.size then
              table.insert(tags, 'size obtained via the old edns option interface does not match')
            end
            value = v:getContent()
            if value ~= l then
              table.insert(tags, 'content obtained via the old edns option interface does not match')
            end
          end
        end
        table.insert(tags, 'ednsoption-'..k..'-total-len-'..len)
      end

      if tcp then
        table.insert(tags, 'gettag-tcp')
      end

      -- test that tags are passed to other hooks
      table.insert(tags, qname:toString())
      table.insert(tags, 'gettag-qtype-'..qtype)

      return 0, tags, data
    end

    function preresolve(dq)

      -- test that we are getting the tags set by gettag()
      -- and also getting the correct qname
      local found = false
      for _, tag in pairs(dq:getPolicyTags()) do
        if dq.qname:equal(tag) then
          found = true
        end
        dq:addAnswer(pdns.TXT, '"'..tag..'"')
      end

      if not found then
        pdnslog("not valid tag found")
        dq.rcode = pdns.REFUSED
        return true
      end

      if dq.data['canary'] ~= 'from-gettag' then
        pdnslog("did not get any data from gettag")
        dq.rcode = pdns.REFUSED
        return true
      end

      if dq.qtype == pdns.A then
        dq:addAnswer(pdns.A, '192.0.2.1')
      elseif dq.qtype == pdns.AAAA then
        dq:addAnswer(pdns.AAAA, '2001:db8::1')
      end

      return true
    end
    """

    @classmethod
    def setUpClass(cls):

        cls.setUpSockets()
        confdir = os.path.join('configs', cls._confdir)
        cls.createConfigDir(confdir)
        cls.generateRecursorConfig(confdir)
        cls.startRecursor(confdir, cls._recursorPort)

    @classmethod
    def tearDownClass(cls):
        cls.tearDownRecursor()

    def assertResponseMatches(self, query, expectedRRs, response):
        expectedResponse = dns.message.make_response(query)

        if query.flags & dns.flags.RD:
            expectedResponse.flags |= dns.flags.RA
        if query.flags & dns.flags.CD:
            expectedResponse.flags |= dns.flags.CD

        expectedResponse.answer = expectedRRs
        print(expectedResponse)
        print(response)
        self.assertEquals(response, expectedResponse)

    def testA(self):
        name = 'gettag.lua.'
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [ name, 'gettag-qtype-1'])
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testTCPA(self):
        name = 'gettag-tcpa.lua.'
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [ name, 'gettag-qtype-1', 'gettag-tcp'])
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendTCPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testAAAA(self):
        name = 'gettag-aaaa.lua.'
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'AAAA', '2001:db8::1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [ name, 'gettag-qtype-28'])
            ]
        query = dns.message.make_query(name, 'AAAA', want_dnssec=True)
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testSubnet(self):
        name = 'gettag-subnet.lua.'
        subnet = '192.0.2.255'
        subnetMask = 32
        ecso = clientsubnetoption.ClientSubnetOption(subnet, subnetMask)
        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [name, 'gettag-qtype-1', 'edns-subnet-' + subnet + '/' + str(subnetMask),
                                                                         'ednsoption-8-count-1', 'ednsoption-8-total-len-8']),
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[ecso])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

    def testEDNSOptions(self):
        name = 'gettag-ednsoptions.lua.'
        subnet = '192.0.2.255'
        subnetMask = 32
        ecso = clientsubnetoption.ClientSubnetOption(subnet, subnetMask)
        eco1 = cookiesoption.CookiesOption(b'deadbeef', b'deadbeef')
        eco2 = cookiesoption.CookiesOption(b'deadc0de', b'deadc0de')

        expected = [
            dns.rrset.from_text(name, 0, dns.rdataclass.IN, 'A', '192.0.2.1'),
            dns.rrset.from_text_list(name, 0, dns.rdataclass.IN, 'TXT', [name, 'gettag-qtype-1', 'edns-subnet-' + subnet + '/' + str(subnetMask),
                                                                         'ednsoption-10-count-2', 'ednsoption-10-total-len-32',
                                                                         'ednsoption-8-count-1', 'ednsoption-8-total-len-8'
                                                                        ]),
            ]
        query = dns.message.make_query(name, 'A', want_dnssec=True, options=[eco1,ecso,eco2])
        query.flags |= dns.flags.CD
        res = self.sendUDPQuery(query)
        self.assertResponseMatches(query, expected, res)

# TODO:
# - postresolve
# - preoutquery
# - ipfilter
# - prerpz
# - nxdomain
# - nodata
