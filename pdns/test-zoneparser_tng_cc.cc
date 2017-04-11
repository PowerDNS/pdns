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

BOOST_AUTO_TEST_SUITE_END();
