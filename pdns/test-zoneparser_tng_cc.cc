#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/file.hpp>
#include <boost/lexical_cast.hpp>
#include "dns.hh"
#include "zoneparser-tng.hh"
#include "dnsrecords.hh"
#include <fstream>

BOOST_AUTO_TEST_SUITE(test_zoneparser_tng_cc)

BOOST_AUTO_TEST_CASE(test_tng_record_types) {
  reportAllTypes();
  reportFancyTypes();

  ZoneParserTNG zp("../regression-tests/zones/unit.test", "unit.test");
  DNSResourceRecord rr;

  boost::iostreams::stream<boost::iostreams::file_source> ifs("../regression-tests/zones/unit.test");

  while(zp.get(rr)) {
    // make sure these concur.
    std::string host, type, data;
    int ttl;
    std::getline(ifs, host, ' ');
    std::getline(ifs, type, ' ');
    ttl = boost::lexical_cast<int>(type);
    std::getline(ifs, type, ' ');
    std::getline(ifs, type, ' ');
    std::getline(ifs, data, '\n');
    // see if these agree
    BOOST_CHECK_EQUAL(rr.qname, host);
    BOOST_CHECK_EQUAL(rr.ttl, ttl);
    BOOST_CHECK_EQUAL(rr.qtype.getName(), type);
    if (*(rr.content.rbegin()) != '.' && *(data.rbegin()) == '.') 
      BOOST_CHECK_EQUAL(rr.content, std::string(data.begin(),data.end()-1));
    else
      BOOST_CHECK_EQUAL(rr.content, data);
  } 

}

BOOST_AUTO_TEST_SUITE_END();
