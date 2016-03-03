#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/std/map.hpp>
#include <numeric>
#include <math.h>
#include "dnsname.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include <unordered_set>
using namespace boost;
using std::string;

BOOST_AUTO_TEST_SUITE(dnsname_cc)

BOOST_AUTO_TEST_CASE(test_basic) {
  string before("www.ds9a.nl.");
  DNSName b(before);
  BOOST_CHECK_EQUAL(b.getRawLabels().size(), 3);
  string after(b.toString());
  BOOST_CHECK_EQUAL(before, after);

  DNSName jpmens("ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test.xxx.yyy-yyyy.zzzzzzzzz-test.");

  BOOST_CHECK_EQUAL(jpmens.toString(), "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.test.xxx.yyy-yyyy.zzzzzzzzz-test.");

  DNSName wwwds9anl("www.ds9a.nl.");
  DNSName wwwds9anl1("www.ds9a\002nl.");
  DNSName nl("nl.");
  BOOST_CHECK(wwwds9anl.isPartOf(nl));
  BOOST_CHECK(!wwwds9anl1.isPartOf(nl));
  BOOST_CHECK(wwwds9anl.isPartOf(wwwds9anl));

  BOOST_CHECK(!nl.isPartOf(wwwds9anl));

  BOOST_CHECK(wwwds9anl == wwwds9anl);

  BOOST_CHECK(DNSName("wWw.ds9A.Nl.") == DNSName("www.ds9a.nl."));
  BOOST_CHECK(DNSName("www.ds9a.nl.") == DNSName("www.ds9a.nl."));

  BOOST_CHECK(DNSName("www.ds9a.nl.").toString() == "www.ds9a.nl.");


  { // Check root vs empty
    DNSName name("."); // root
    DNSName parent; // empty
    BOOST_CHECK(name != parent);
  }

  { // Check name part of root
    DNSName name("a.");
    DNSName parent(".");
    BOOST_CHECK(name.isPartOf(parent));
  }

  { // Label boundary
    DNSName name("a\002bb.");
    DNSName parent("bb.");
    BOOST_CHECK(!name.isPartOf(parent));
  }

  { // Multi label parent
    DNSName name("a.bb.ccc.dddd.");
    DNSName parent("ccc.dddd.");
    BOOST_CHECK(name.isPartOf(parent));
  }

  { // Last char diff
    DNSName name("a.bb.ccc.dddd.");
    DNSName parent("ccc.dddx.");
    BOOST_CHECK(!name.isPartOf(parent));
  }

  { // Equal length identical
    DNSName name("aaaa.bbb.cc.d.");
    DNSName parent("aaaa.bbb.cc.d.");
    BOOST_CHECK(name.isPartOf(parent));
  }

  { // Equal length first char diff
    DNSName name("xaaa.bbb.cc.d.");
    DNSName parent("aaaa.bbb.cc.d.");
    BOOST_CHECK(!name.isPartOf(parent));
  }

  { // Make relative
    DNSName name("aaaa.bbb.cc.d.");
    DNSName parent("cc.d.");
    BOOST_CHECK_EQUAL( name.makeRelative(parent), DNSName("aaaa.bbb."));
  }

  { // Labelreverse
    DNSName name("aaaa.bbb.cc.d.");
    BOOST_CHECK( name.labelReverse() == DNSName("d.cc.bbb.aaaa."));
  }

  { // empty() empty
    DNSName name;
    BOOST_CHECK(name.empty());
  }
  
  { // empty() root
    DNSName name(".");
    BOOST_CHECK(!name.empty());
    
    DNSName rootnodot("");
    BOOST_CHECK_EQUAL(name, rootnodot);
    
    string empty;
    DNSName rootnodot2(empty);
    BOOST_CHECK_EQUAL(rootnodot2, name);
  }

  DNSName left("ds9a.nl.");
  left.prependRawLabel("www");
  BOOST_CHECK( left == DNSName("WwW.Ds9A.Nl."));

  left.appendRawLabel("com");

  BOOST_CHECK( left == DNSName("WwW.Ds9A.Nl.com."));
  
  DNSName unset;

  unset.appendRawLabel("www");
  unset.appendRawLabel("powerdns.com");
  unset.appendRawLabel("com");

  BOOST_CHECK_EQUAL(unset.toString(), "www.powerdns\\.com.com.");

  DNSName rfc4343_2_2(R"(Donald\032E\.\032Eastlake\0323rd.example.)");
  DNSName example("example.");
  BOOST_CHECK(rfc4343_2_2.isPartOf(example));

  auto labels=rfc4343_2_2.getRawLabels();
  BOOST_CHECK_EQUAL(*labels.begin(), "Donald E. Eastlake 3rd");
  BOOST_CHECK_EQUAL(*labels.rbegin(), "example");
  BOOST_CHECK_EQUAL(labels.size(), 2);


  DNSName build;
  build.appendRawLabel("Donald E. Eastlake 3rd");
  build.appendRawLabel("example");
  BOOST_CHECK_EQUAL(build.toString(), R"(Donald\032E\.\032Eastlake\0323rd.example.)");
  BOOST_CHECK_THROW(DNSName broken("bert..hubert."), std::runtime_error);

  DNSName n;
  n.appendRawLabel("powerdns.dnsmaster");
  n.appendRawLabel("powerdns");
  n.appendRawLabel("com");

  BOOST_CHECK_EQUAL(n.toString(), "powerdns\\.dnsmaster.powerdns.com.");

  //  BOOST_CHECK(DNSName().toString() != ".");

  DNSName p;
  string label("power");
  label.append(1, (char)0);
  label.append("dns");
  p.appendRawLabel(label);
  p.appendRawLabel("com");

  BOOST_CHECK_EQUAL(p.toString(), "power\\000dns.com.");
}

BOOST_AUTO_TEST_CASE(test_trim) {
  DNSName w("www.powerdns.com.");
  BOOST_CHECK_EQUAL(w.countLabels(), 3);
  w.trimToLabels(2);
  BOOST_CHECK_EQUAL(w.toString(), "powerdns.com.");
  DNSName w2("powerdns.com.");
  BOOST_CHECK(w==w2);

  DNSName root(".");
  BOOST_CHECK_EQUAL(root.countLabels(), 0);
}

BOOST_AUTO_TEST_CASE(test_toolong) {

  BOOST_CHECK_THROW(DNSName w("1234567890123456789012345678901234567890123456789012345678901234567890.com."), std::range_error);

  BOOST_CHECK_THROW(DNSName w("12345678901234567890.12345678901234567890123456.789012345678901.234567890.12345678901234567890.12345678901234567890123456.789012345678901.234567890.12345678901234567890.12345678901234567890123456.789012345678901.234567890.234567890.789012345678901.234567890.234567890.789012345678901.234567890.234567890.com."), std::range_error);
}

BOOST_AUTO_TEST_CASE(test_dnsstrings) {
  DNSName w("www.powerdns.com.");
  BOOST_CHECK_EQUAL(w.toDNSString(), string("\003www\010powerdns\003com\000", 18));
}

BOOST_AUTO_TEST_CASE(test_empty) {
  DNSName empty;
  BOOST_CHECK_THROW(empty.toString(), std::out_of_range);
  BOOST_CHECK_THROW(empty.toStringNoDot(), std::out_of_range);
  BOOST_CHECK_THROW(empty.toDNSString(), std::out_of_range);
  BOOST_CHECK(empty.empty());
  BOOST_CHECK(!empty.isRoot());
  BOOST_CHECK(!empty.isWildcard());
  BOOST_CHECK_EQUAL(empty, empty);
  BOOST_CHECK(!(empty < empty));
  
  DNSName root(".");
  BOOST_CHECK(empty < root);

  BOOST_CHECK_THROW(empty.isPartOf(root), std::out_of_range);
  BOOST_CHECK_THROW(root.isPartOf(empty), std::out_of_range);
}

BOOST_AUTO_TEST_CASE(test_specials) {
  DNSName root(".");
  
  BOOST_CHECK(root.isRoot());
  BOOST_CHECK(root != DNSName());

  DNSName wcard("*.powerdns.com");
  BOOST_CHECK(wcard.isWildcard());

  DNSName notwcard("www.powerdns.com");
  BOOST_CHECK(!notwcard.isWildcard());
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

BOOST_AUTO_TEST_CASE(test_PacketParse) {
  vector<unsigned char> packet;
  reportBasicTypes();
  DNSName root(".");
  DNSPacketWriter dpw1(packet, DNSName("."), QType::AAAA);
  DNSName p((char*)&packet[0], packet.size(), 12, false);
  BOOST_CHECK_EQUAL(p, root);
  unsigned char* buffer=&packet[0];
  /* set invalid label len:
     - packet.size() == 17 (sizeof(dnsheader) + 1 + 2 + 2)
     - label len < packet.size() but
     - offset is 12, label len of 15 should be rejected
     because offset + 15 >= packet.size()
  */
  buffer[sizeof(dnsheader)] = 15;
  BOOST_CHECK_THROW(DNSName((char*)&packet[0], packet.size(), 12, false), std::range_error);
}


BOOST_AUTO_TEST_CASE(test_hash) {
  DNSName a("wwW.Ds9A.Nl"), b("www.ds9a.nl");
  BOOST_CHECK_EQUAL(a.hash(), b.hash());
  
  vector<uint32_t> counts(1500);
 
  for(unsigned int n=0; n < 100000; ++n) {
    DNSName dn(std::to_string(n)+"."+std::to_string(n*2)+"ds9a.nl");
    DNSName dn2(std::to_string(n)+"."+std::to_string(n*2)+"Ds9a.nL");
    BOOST_CHECK_EQUAL(dn.hash(), dn2.hash());
    counts[dn.hash() % counts.size()]++;
  }
  
  double sum = std::accumulate(std::begin(counts), std::end(counts), 0.0);
  double m =  sum / counts.size();
  
  double accum = 0.0;
  std::for_each (std::begin(counts), std::end(counts), [&](const double d) {
      accum += (d - m) * (d - m);
  });
      
  double stdev = sqrt(accum / (counts.size()-1));
  BOOST_CHECK(stdev < 10);      
}

BOOST_AUTO_TEST_CASE(test_hashContainer) {
  std::unordered_set<DNSName> s;
  s.insert(DNSName("www.powerdns.com"));
  BOOST_CHECK(s.count(DNSName("WwW.PoWerDNS.CoM")));
  BOOST_CHECK_EQUAL(s.size(), 1);
  s.insert(DNSName("www.POWERDNS.com"));
  BOOST_CHECK_EQUAL(s.size(), 1);
  s.insert(DNSName("www2.POWERDNS.com"));
  BOOST_CHECK_EQUAL(s.size(), 2);

  s.clear();
  unsigned int n=0;
  for(; n < 100000; ++n)
    s.insert(DNSName(std::to_string(n)+".test.nl"));
  BOOST_CHECK_EQUAL(s.size(), n);

}


BOOST_AUTO_TEST_CASE(test_QuestionHash) {
  vector<unsigned char> packet;
  reportBasicTypes();
  DNSPacketWriter dpw1(packet, DNSName("www.ds9a.nl."), QType::AAAA);
  
  auto hash1=hashQuestion((char*)&packet[0], packet.size(), 0);
  DNSPacketWriter dpw2(packet, DNSName("wWw.Ds9A.nL."), QType::AAAA);
  auto hash2=hashQuestion((char*)&packet[0], packet.size(), 0);
  BOOST_CHECK_EQUAL(hash1, hash2);
 
  vector<uint32_t> counts(1500);
 
  for(unsigned int n=0; n < 100000; ++n) {
    packet.clear();
    DNSPacketWriter dpw1(packet, DNSName(std::to_string(n)+"."+std::to_string(n*2)+"."), QType::AAAA);
    counts[hashQuestion((char*)&packet[0], packet.size(), 0) % counts.size()]++;
  }
  
  double sum = std::accumulate(std::begin(counts), std::end(counts), 0.0);
  double m =  sum / counts.size();
  
  double accum = 0.0;
  std::for_each (std::begin(counts), std::end(counts), [&](const double d) {
      accum += (d - m) * (d - m);
  });
      
  double stdev = sqrt(accum / (counts.size()-1));
  BOOST_CHECK(stdev < 10);      
}
  

BOOST_AUTO_TEST_CASE(test_packetParse) {
  vector<unsigned char> packet;
  reportBasicTypes();
  DNSPacketWriter dpw(packet, DNSName("www.ds9a.nl."), QType::AAAA);
  
  uint16_t qtype, qclass;
  DNSName dn((char*)&packet[0], packet.size(), 12, false, &qtype, &qclass);
  BOOST_CHECK_EQUAL(dn.toString(), "www.ds9a.nl.");
  BOOST_CHECK(qtype == QType::AAAA);
  BOOST_CHECK_EQUAL(qclass, 1);

  dpw.startRecord(DNSName("ds9a.nl."), DNSRecordContent::TypeToNumber("NS"));
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
  BOOST_CHECK(qtype == QType::NS);
  BOOST_CHECK_EQUAL(qclass, 1);

  DNSName dn3((char*)&packet[0], packet.size(), 12+13+4+2 + 4 + 4 + 2, true);
  BOOST_CHECK_EQUAL(dn3.toString(), "ns1.powerdns.com."); 
  try {
    DNSName dn4((char*)&packet[0], packet.size(), 12+13+4, false); // compressed, should fail
    BOOST_CHECK(0); 
  }
  catch(...){}
}

BOOST_AUTO_TEST_CASE(test_escaping) {
  DNSName n;
  string label;

  for(int i = 0; i < 250; ++i) {
    if(!((i+1)%63)) {
      n.appendRawLabel(label);
      label.clear();
    }
    label.append(1,(char)i);
  }
  if(!label.empty())
    n.appendRawLabel(label);

  DNSName n2(n.toString());
  BOOST_CHECK(n==n2);
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

  smn.add(DNSName(".")); // block the root
  BOOST_CHECK(smn.check(DNSName("a.root-servers.net.")));
}


BOOST_AUTO_TEST_CASE(test_concat) {
  DNSName first("www."), second("powerdns.com.");
  BOOST_CHECK_EQUAL((first+second).toString(), "www.powerdns.com.");
}

BOOST_AUTO_TEST_CASE(test_compare_naive) {
  BOOST_CHECK(DNSName("abc.com.") < DNSName("zdf.com."));
  BOOST_CHECK(DNSName("Abc.com.") < DNSName("zdf.com."));
  BOOST_CHECK(DNSName("Abc.com.") < DNSName("Zdf.com."));
  BOOST_CHECK(DNSName("abc.com.") < DNSName("Zdf.com."));
}

BOOST_AUTO_TEST_CASE(test_compare_empty) {
  DNSName a, b;
  BOOST_CHECK(!(a<b));
  BOOST_CHECK(!a.canonCompare(b));
}


BOOST_AUTO_TEST_CASE(test_compare_canonical) {
  DNSName lower("bert.com."), higher("alpha.nl.");
  BOOST_CHECK(lower.canonCompare(higher));

  BOOST_CHECK(DNSName("bert.com").canonCompare(DNSName("www.bert.com")));
  BOOST_CHECK(DNSName("BeRt.com").canonCompare(DNSName("WWW.berT.com")));
  BOOST_CHECK(!DNSName("www.BeRt.com").canonCompare(DNSName("WWW.berT.com")));

  CanonDNSNameCompare a;
  BOOST_CHECK(a(DNSName("."), DNSName("www.powerdns.com")));
  BOOST_CHECK(a(DNSName("."), DNSName("www.powerdns.net")));
  BOOST_CHECK(!a(DNSName("www.powerdns.net"), DNSName(".")));

  vector<DNSName> vec;
  for(const std::string& a : {"bert.com.", "alpha.nl.", "articles.xxx.",
	"Aleph1.powerdns.com.", "ZOMG.powerdns.com.", "aaa.XXX.", "yyy.XXX.", 
	"test.powerdns.com."}) {
    vec.push_back(DNSName(a));
  }
  sort(vec.begin(), vec.end(), CanonDNSNameCompare());
  //  for(const auto& v : vec)
  //    cerr<<'"'<<v.toString()<<'"'<<endl;

  vector<DNSName> right;
  for(const auto& a: {"bert.com.",  "Aleph1.powerdns.com.",
	"test.powerdns.com.",
	"ZOMG.powerdns.com.",
	"alpha.nl.",
	"aaa.XXX.",
	"articles.xxx.",
	"yyy.XXX."})
    right.push_back(DNSName(a));

  
  BOOST_CHECK(vec==right);
}


BOOST_AUTO_TEST_CASE(test_empty_label) { // empty label

  { // append
    DNSName dn("www.");
    BOOST_CHECK_THROW(dn.appendRawLabel(""), std::range_error);
  }

  { // prepend
    DNSName dn("www.");
    BOOST_CHECK_THROW(dn.prependRawLabel(""), std::range_error);
  }
}

BOOST_AUTO_TEST_CASE(test_label_length_max) { // 63 char label

  string label("123456789012345678901234567890123456789012345678901234567890123");

  { // append
    DNSName dn("www.");
    dn.appendRawLabel(label);
    BOOST_CHECK_EQUAL(dn.toString(), "www." + label + ".");
  }

  { // prepend
    DNSName dn("www.");
    dn.prependRawLabel(label);
    BOOST_CHECK_EQUAL(dn.toString(), label + ".www.");
  }
}

BOOST_AUTO_TEST_CASE(test_label_length_too_long) { // 64 char label

  string label("1234567890123456789012345678901234567890123456789012345678901234");

  { // append
    DNSName dn("www.");
    BOOST_CHECK_THROW(dn.appendRawLabel(label), std::range_error);
  }

  { // prepend
    DNSName dn("www.");
    BOOST_CHECK_THROW(dn.prependRawLabel(label), std::range_error);
  }
}

BOOST_AUTO_TEST_CASE(test_name_length_max) { // 255 char name

  string name("123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789."
              "123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789."
              "123456789.123456789.123456789.123456789.123456789.");
  string label("123");

  { // append
    DNSName dn(name);
    dn.appendRawLabel(label);
    BOOST_CHECK_EQUAL(dn.toString().size(), 254);
  }

  { // prepend
    DNSName dn(name);
    dn.prependRawLabel(label);
    BOOST_CHECK_EQUAL(dn.toString().size(), 254);
  }

  { // concat
    DNSName dn(name);

    dn += DNSName(label + ".");
    BOOST_CHECK_EQUAL(dn.toString().size(), 254);
  }
}

BOOST_AUTO_TEST_CASE(test_name_length_too_long) { // 256 char name

  string name("123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789."
              "123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789.123456789."
              "123456789.123456789.123456789.123456789.123456789.");
  string label("1234");

  { // append
    DNSName dn(name);
    BOOST_CHECK_THROW(dn.appendRawLabel(label), std::range_error);
  }

  { // prepend
    DNSName dn(name);
    BOOST_CHECK_THROW(dn.prependRawLabel(label), std::range_error);
  }

  { // concat
    DNSName dn(name);
    BOOST_CHECK_THROW(dn += DNSName(label + "."), std::range_error);
  }
}


BOOST_AUTO_TEST_CASE(test_invalid_label_length) { // Invalid label length in qname

  string name("\x02""ns\x07""example\x04""com\x00", 16);

  BOOST_CHECK_THROW(DNSName dn(name.c_str(), name.size(), 0, true), std::range_error);
}

BOOST_AUTO_TEST_CASE(test_compression) { // Compression test

  string name("\x03""com\x00""\x07""example\xc0""\x00""\x03""www\xc0""\x05", 21);

  DNSName dn(name.c_str(), name.size(), 15, true);
  BOOST_CHECK_EQUAL(dn.toString(), "www.example.com.");
}

BOOST_AUTO_TEST_CASE(test_pointer_pointer_root) { // Pointer to pointer to root

  string name("\x00""\xc0""\x00""\x03""com\xc0""\x01",9);

  DNSName dn(name.c_str(), name.size(), 3, true);
  BOOST_CHECK_EQUAL(dn.toString(), "com.");
}

BOOST_AUTO_TEST_CASE(test_bad_compression_pointer) { // Pointing beyond packet boundary

  std::string name("\x03""com\x00""\x07""example\xc0""\x11""xc0""\x00", 17);

  BOOST_CHECK_THROW(DNSName dn(name.c_str(), name.length(), 5, true), std::range_error);
}

BOOST_AUTO_TEST_CASE(test_compression_loop) { // Compression loop (add one label)

  std::string name("\x03""www\xc0""\x00", 6);

  BOOST_CHECK_THROW(DNSName dn(name.c_str(), name.length(), 0, true), std::range_error);
}

BOOST_AUTO_TEST_CASE(test_compression_loop1) { // Compression loop (pointer loop)

  string name("\xc0""\x00", 2);

  BOOST_CHECK_THROW(DNSName dn(name.c_str(), name.size(), 0, true), std::range_error);
}

BOOST_AUTO_TEST_CASE(test_compression_loop2) { // Compression loop (deep recursion)

  int i;
  string name("\x00\xc0\x00", 3);
  for (i=0; i<98; ++i) {
    name.append( 1, ((i >> 7) & 0xff) | 0xc0);
    name.append( 1, ((i << 1) & 0xff) | 0x01);
  }
  BOOST_CHECK_NO_THROW(DNSName dn(name.c_str(), name.size(), name.size()-2, true));

  ++i;
  name.append( 1, ((i >> 7) & 0xff) | 0xc0);
  name.append( 1, ((i << 1) & 0xff) | 0x01);

  BOOST_CHECK_THROW(DNSName dn(name.c_str(), name.size(), name.size()-2, true), std::range_error);
}

BOOST_AUTO_TEST_CASE(test_wirelength) { // Testing if we get the correct value from the wirelength function
  DNSName name("www.powerdns.com");
  BOOST_CHECK_EQUAL(name.wirelength(), 18);

  DNSName sname("powerdns.com");
  sname.prependRawLabel(string("ww\x00""w", 4));
  BOOST_CHECK_EQUAL(sname.wirelength(), 19);

  sname = DNSName("powerdns.com");
  sname.prependRawLabel(string("www\x00", 4));
  BOOST_CHECK_EQUAL(sname.wirelength(), 19);
}


BOOST_AUTO_TEST_SUITE_END()
