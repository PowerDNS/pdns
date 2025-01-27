#!/usr/bin/env python
import unittest
import dns
import os
import subprocess

from authtests import AuthTest

class TestLuaRecordsLMDB(AuthTest):
    # Copied from AuthTest, without the bind-config and bind-dnssec fields,
    # since these tests target LMDB an a backend.
    _config_template_default = """
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
launch=lmdb
enable-lua-records
"""

    _zones = {
        'example.org': """
example.org.                 3600 IN SOA  {soa}
example.org.                 3600 IN NS   ns1.example.org.
example.org.                 3600 IN NS   ns2.example.org.
ns1.example.org.             3600 IN A    {prefix}.10
ns2.example.org.             3600 IN A    {prefix}.11

config    IN    LUA    LUA ("settings={{stringmatch='Programming in Lua'}} "
                            "EUWips={{'{prefix}.101','{prefix}.102'}}      "
                            "EUEips={{'192.168.42.101','192.168.42.102'}}  "
                            "NLips={{'{prefix}.111', '{prefix}.112'}}      "
                            "USAips={{'{prefix}.103', '192.168.42.105'}}   ")

nested-lua.example.org.      3600 IN LUA  A   ( ";include('config') "
                                                "return pickrandom(EUWips)" )

        """
    }

    @classmethod
    def generateAllAuthConfig(cls, confdir):
        # This is very similar to AuthTest.generateAllAuthConfig,
        # but for lmdb backend, we ignore auth keys but need to load-zone
        # into lmdb storage.
        cls.generateAuthConfig(confdir)

        for zonename, zonecontent in cls._zones.items():
            cls.generateAuthZone(confdir,
                                 zonename,
                                 zonecontent)
            pdnsutilCmd = [os.environ['PDNSUTIL'],
                           '--config-dir=%s' % confdir,
                           'load-zone',
                           zonename,
                           os.path.join(confdir, '%s.zone' % zonename)]

            print(' '.join(pdnsutilCmd))
            try:
                subprocess.check_output(pdnsutilCmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                raise AssertionError('%s failed (%d): %s' % (pdnsutilCmd, e.returncode, e.output))

    def testPickRandomWithNestedLua(self):
        """
        Basic pickrandom() test with a set of A records, with a bit of lua inclusion
        """

        expected = [dns.rrset.from_text('nested-lua.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.101'.format(prefix=self._PREFIX)),
                    dns.rrset.from_text('nested-lua.example.org.', 0, dns.rdataclass.IN, 'A',
                                        '{prefix}.102'.format(prefix=self._PREFIX))]

        query = dns.message.make_query('nested-lua.example.org', 'A')
        res = self.sendUDPQuery(query)
        self.assertRcodeEqual(res, dns.rcode.NOERROR)
        self.assertAnyRRsetInAnswer(res, expected)

if __name__ == '__main__':
    unittest.main()
    exit(0)
