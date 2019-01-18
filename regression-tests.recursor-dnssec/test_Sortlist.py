import dns
from recursortests import RecursorTest


class testSortlist(RecursorTest):
    _confdir = 'Sortlist'

    _config_template = """dnssec=off"""
    _lua_config_file = """addSortList("0.0.0.0/0", 
                {"17.238.240.0/24", "17.138.149.200",
                    {"17.218.242.254", "17.218.252.254"}, 
                    "17.38.42.80",
                    "17.208.240.100" })"""

    def testSortlist(self):
        msg = dns.message.make_query("sortcname.example.", dns.rdatatype.ANY)
        msg.flags = dns.flags.from_text('RD')

        res = self.sendUDPQuery(msg, fwparams=dict(one_rr_per_rrset=True))

        self.assertMessageHasFlags(res, ['QR', 'RA', 'RD'], [])
        self.assertRcodeEqual(res, dns.rcode.NOERROR)

        indexCNAME = -1
        indexMX = -1
        recordsA = []

        for i, ans in enumerate(res.answer):
            if ans.rdtype == dns.rdatatype.CNAME:
                self.assertEqual(indexCNAME, -1)
                indexCNAME = i
            elif ans.rdtype == dns.rdatatype.MX:
                self.assertEqual(indexMX, -1)
                indexMX = i
            elif ans.rdtype == dns.rdatatype.A:
                recordsA.append(str(ans).split()[-1])

        self.assertEqual(indexCNAME, 0)
        self.assertGreater(indexMX, 0)

        self.assertEqual(recordsA, ['17.238.240.5', '17.38.42.80', '192.168.0.1'])