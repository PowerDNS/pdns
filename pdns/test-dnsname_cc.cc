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

BOOST_AUTO_TEST_CASE(test_packetParse) {
  vector<unsigned char> packet;
  DNSPacketWriter dpw(packet, "www.ds9a.nl.", QType::AAAA);

  uint16_t qtype;
  DNSName dn((char*)&packet[12], packet.size() - 12, &qtype);
  BOOST_CHECK_EQUAL(dn.toString(), "www.ds9a.nl.");
  BOOST_CHECK_EQUAL(qtype, QType::AAAA);
}

BOOST_AUTO_TEST_SUITE_END()
