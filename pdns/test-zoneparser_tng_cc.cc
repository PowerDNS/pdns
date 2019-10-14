#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>
#include <boost/iostreams/device/file.hpp>
#include "dns.hh"
#include "zoneparser-tng.hh"
#include "dnsrecords.hh"
#include "dnsname.hh"
#include <fstream>
#include <cstdlib>

BOOST_AUTO_TEST_SUITE(test_zoneparser_tng_cc)

BOOST_AUTO_TEST_CASE(test_tng_record_types) {
  reportAllTypes();

  std::ostringstream pathbuf;
  const char* p = std::getenv("SRCDIR");
  if(!p)
    p = ".";
  pathbuf << p << "/../regression-tests/zones/unit.test";
  ZoneParserTNG zp(pathbuf.str(), DNSName("unit.test"));
  DNSResourceRecord rr;

  ifstream ifs(pathbuf.str());

  while(zp.get(rr)) {
    // make sure these concur.
    std::string host, type, data;
    unsigned int ttl;
    std::getline(ifs, host, ' ');
    std::getline(ifs, type, ' ');
    ttl = pdns_stou(type);
    std::getline(ifs, type, ' ');
    std::getline(ifs, type, ' ');
    std::getline(ifs, data, '\n');
    // see if these agree
    BOOST_CHECK_EQUAL(rr.qname.toString(), host);
    BOOST_CHECK_EQUAL(rr.ttl, ttl);
    BOOST_CHECK_EQUAL(rr.qtype.getName(), type);
    if (rr.qtype == QType::SOA)
      continue; // FIXME400 remove trailing dots from data
    if (*(rr.content.rbegin()) != '.' && *(data.rbegin()) == '.') 
      BOOST_CHECK_EQUAL(rr.content, std::string(data.begin(),data.end()-1));
    else
      BOOST_CHECK_EQUAL(rr.content, data);
  }
}

BOOST_AUTO_TEST_CASE(test_tng_record_generate) {
  reportAllTypes();

  std::ostringstream pathbuf;
  const char* p = std::getenv("SRCDIR");
  if(!p)
    p = ".";
  pathbuf << p << "/../regression-tests/zones/unit2.test";
  ZoneParserTNG zp(pathbuf.str(), DNSName("unit2.test"));

  vector<string> expected = {
    "0.01.0003.000005.00000007.unit2.test.",
    "1.02.0004.000006.00000008.unit2.test.",
    "2.03.0005.000007.00000009.unit2.test.",
    "3.04.0006.000008.0000000a.unit2.test.",
    "4.05.0007.000009.0000000b.unit2.test.",
    "5.06.0008.00000A.0000000c.unit2.test.",
    "6.07.0009.00000B.0000000d.unit2.test.",
    "7.10.0010.00000C.0000000e.unit2.test.",
    "8.11.0011.00000D.0000000f.unit2.test.",
    "9.12.0012.00000E.00000010.unit2.test.",
    "10.13.0013.00000F.00000011.unit2.test.",
    "11.14.0014.000010.00000012.unit2.test.",
    "12.15.0015.000011.00000013.unit2.test.",
    "13.16.0016.000012.00000014.unit2.test.",
    "14.17.0017.000013.00000015.unit2.test.",
    "15.20.0018.000014.00000016.unit2.test.",
    "16.21.0019.000015.00000017.unit2.test."
  };

  for (auto const & exp : expected) {
    DNSResourceRecord rr;
    zp.get(rr);
    BOOST_CHECK_EQUAL(rr.qname.toString(), exp);
    BOOST_CHECK_EQUAL(rr.ttl, 86400U);
    BOOST_CHECK_EQUAL(rr.qclass, 1U);
    BOOST_CHECK_EQUAL(rr.qtype.getName(), "A");
    BOOST_CHECK_EQUAL(rr.content, "1.2.3.4");
  }

}

BOOST_AUTO_TEST_SUITE_END();
