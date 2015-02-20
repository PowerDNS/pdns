#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/std/map.hpp>
#include "dnsname.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
using namespace boost;
using std::string;

BOOST_AUTO_TEST_SUITE(dnsname_cc)

BOOST_AUTO_TEST_CASE(test_basic) {
  string before("www.ds9a.nl.");
  DNSName b(before);

  BOOST_CHECK_EQUAL(b.getRawLabels().size(), 3);
  string after(b.toString());
  BOOST_CHECK_EQUAL(before, after);

  DNSName wwwds9anl("www.ds9a.nl.");
  DNSName nl("nl.");
  BOOST_CHECK(wwwds9anl.isPartOf(nl));
  BOOST_CHECK(wwwds9anl.isPartOf(wwwds9anl));

  BOOST_CHECK(!nl.isPartOf(wwwds9anl));

  BOOST_CHECK(wwwds9anl == wwwds9anl);

  BOOST_CHECK(DNSName("wWw.ds9A.Nl.") == DNSName("www.ds9a.nl."));
  BOOST_CHECK(DNSName("www.ds9a.nl.") == DNSName("www.ds9a.nl."));

  BOOST_CHECK(DNSName("www.ds9a.nl.").toString() == "www.ds9a.nl.");

  DNSName left("ds9a.nl.");
  left.prependRawLabel("www");
  BOOST_CHECK( left == DNSName("WwW.Ds9A.Nl."));

  left.appendRawLabel("com");

  BOOST_CHECK( left == DNSName("WwW.Ds9A.Nl.com."));
  
  DNSName root;
  BOOST_CHECK(root.toString() == ".");

  root.appendRawLabel("www");
  root.appendRawLabel("powerdns.com");
  root.appendRawLabel("com");

  BOOST_CHECK_EQUAL(root.toString(), "www.powerdns\\.com.com.");

  DNSName rfc4343_2_2(R"(Donald\032E\.\032Eastlake\0323rd.example.)");
  DNSName example("example.");
  BOOST_CHECK(rfc4343_2_2.isPartOf(example));

  auto labels=rfc4343_2_2.getRawLabels();
  BOOST_CHECK_EQUAL(*labels.begin(), "Donald E. Eastlake 3rd");
  BOOST_CHECK_EQUAL(*labels.rbegin(), "example");
  BOOST_CHECK_EQUAL(labels.size(), 2);

  try {
    DNSName broken("bert..hubert.");
    BOOST_CHECK(0);
  }catch(...){}

  DNSName n;
  n.appendRawLabel("powerdns.dnsmaster");
  n.appendRawLabel("powerdns");
  n.appendRawLabel("com");

  BOOST_CHECK_EQUAL(n.toString(), "powerdns\\.dnsmaster.powerdns.com.");

  BOOST_CHECK_EQUAL(DNSName().toString(), ".");

  DNSName p;
  string label("power");
  label.append(1, (char)0);
  label.append("dns");
  p.appendRawLabel(label);
  p.appendRawLabel("com");

  BOOST_CHECK_EQUAL(p.toString(), "power\\000dns.com.");
}

BOOST_AUTO_TEST_CASE(test_toolong) {
  try {
    DNSName w("1234567890123456789012345678901234567890123456789012345678901234567890.com.");
    BOOST_CHECK(0);
  }
  catch(...){}


  try {
    DNSName w("com.");
    w.prependRawLabel("1234567890123456789012345678901234567890123456789012345678901234567890");
    BOOST_CHECK(0);
  }
  catch(...){}

}

BOOST_AUTO_TEST_CASE(test_dnsstrings) {
  DNSName w("www.powerdns.com.");
  BOOST_CHECK_EQUAL(w.toDNSString(), string("\003www\010powerdns\003com\000", 18));
}

BOOST_AUTO_TEST_CASE(test_chopping) {
  DNSName w("www.powerdns.com.");
  BOOST_CHECK_EQUAL(w.toString(), "www.powerdns.com.");
  BOOST_CHECK(w.chopOff());
  BOOST_CHECK_EQUAL(w.toString(), "powerdns.com.");
  BOOST_CHECK(w.chopOff());
  BOOST_CHECK_EQUAL(w.toString(), "com.");
  BOOST_CHECK(w.chopOff());
  BOOST_CHECK_EQUAL(w.toString(), ".");
  BOOST_CHECK(!w.chopOff());
  BOOST_CHECK(!w.chopOff());

  w.prependRawLabel("net");
  w.prependRawLabel("root-servers");
  w.prependRawLabel("a");
  BOOST_CHECK_EQUAL(w.toString(), "a.root-servers.net.");
}

BOOST_AUTO_TEST_CASE(test_Append) {
  DNSName dn("www."), powerdns("powerdns.com.");
  DNSName tot=dn+powerdns;
  
  BOOST_CHECK_EQUAL(tot.toString(), "www.powerdns.com.");
  BOOST_CHECK(tot == DNSName("www.powerdns.com."));

  dn+=powerdns;

  BOOST_CHECK(dn == DNSName("www.powerdns.com."));
}

BOOST_AUTO_TEST_CASE(test_packetParse) {
  vector<unsigned char> packet;
  reportBasicTypes();
  DNSPacketWriter dpw(packet, "www.ds9a.nl.", QType::AAAA);
  
  uint16_t qtype, qclass;
  DNSName dn((char*)&packet[0], packet.size(), 12, false, &qtype, &qclass);
  BOOST_CHECK_EQUAL(dn.toString(), "www.ds9a.nl.");
  BOOST_CHECK_EQUAL(qtype, QType::AAAA);
  BOOST_CHECK_EQUAL(qclass, 1);

  dpw.startRecord("ds9a.nl.", DNSRecordContent::TypeToNumber("NS"));
  NSRecordContent nrc("ns1.powerdns.com");
  nrc.toPacket(dpw);

  dpw.commit();

  /* packet now looks like this:
     012345678901 12 bytes of header
     3www4ds9a2nl0 13 bytes of name
     0001 0001      4 bytes of qtype and qclass
     answername     2 bytes
     0001 0001      4 bytes of qtype and class
     0000 0000      4 bytes of TTL
     0000           2 bytes of content length
     content name */

  DNSName dn2((char*)&packet[0], packet.size(), 12+13+4, true, &qtype, &qclass);
  BOOST_CHECK_EQUAL(dn2.toString(), "ds9a.nl."); 
  BOOST_CHECK_EQUAL(qtype, QType::NS);
  BOOST_CHECK_EQUAL(qclass, 1);

  DNSName dn3((char*)&packet[0], packet.size(), 12+13+4+2 + 4 + 4 + 2, true);
  BOOST_CHECK_EQUAL(dn3.toString(), "ns1.powerdns.com."); 

  try {
    DNSName dn4((char*)&packet[0], packet.size(), 12+13+4, false); // compressed, should fail
    BOOST_CHECK(0); 
  }
  catch(...){}
}

BOOST_AUTO_TEST_CASE(test_suffixmatch) {
  SuffixMatchNode smn;
  DNSName ezdns("ezdns.it.");
  smn.add(ezdns.getRawLabels());

  smn.add(DNSName("org.").getRawLabels());

  DNSName wwwpowerdnscom("www.powerdns.com.");
  DNSName wwwezdnsit("www.ezdns.it.");
  BOOST_CHECK(smn.check(wwwezdnsit));
  BOOST_CHECK(!smn.check(wwwpowerdnscom));

  BOOST_CHECK(smn.check(DNSName("www.powerdns.org.")));
  BOOST_CHECK(smn.check(DNSName("www.powerdns.oRG.")));

  smn.add(DNSName("news.bbc.co.uk."));
  BOOST_CHECK(smn.check(DNSName("news.bbc.co.uk.")));
  BOOST_CHECK(smn.check(DNSName("www.news.bbc.co.uk.")));
  BOOST_CHECK(smn.check(DNSName("www.www.www.www.www.news.bbc.co.uk.")));
  BOOST_CHECK(!smn.check(DNSName("images.bbc.co.uk.")));

  BOOST_CHECK(!smn.check(DNSName("www.news.gov.uk.")));

  smn.add(DNSName()); // block the root
  BOOST_CHECK(smn.check(DNSName("a.root-servers.net.")));


}
BOOST_AUTO_TEST_SUITE_END()
