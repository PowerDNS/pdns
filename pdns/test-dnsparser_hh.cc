#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "dnsparser.hh"

BOOST_AUTO_TEST_SUITE(test_dnsparser_hh)

BOOST_AUTO_TEST_CASE(test_type_lowercase)
{
  std::string lc("type12345");
  std::string uc("TYPE12345");

  uint16_t lc_result = DNSRecordContent::TypeToNumber(lc);
  uint16_t uc_result = DNSRecordContent::TypeToNumber(uc);
  BOOST_CHECK_EQUAL(lc_result, 12345);
  BOOST_CHECK_EQUAL(lc_result, uc_result);
}

BOOST_AUTO_TEST_SUITE_END()
