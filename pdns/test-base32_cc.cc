#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>
#include "base32.hh"

BOOST_AUTO_TEST_SUITE(test_base32_cc)

BOOST_AUTO_TEST_CASE(test_base32_basic)
{
  typedef boost::tuple<const std::string, const std::string> case_t;
  typedef std::list<case_t> cases_t;

  // RFC test vectors
  cases_t cases = boost::assign::list_of(case_t(std::string(""), std::string("")))(case_t(std::string("f"), std::string("co======")))(case_t(std::string("fo"), std::string("cpng====")))(case_t(std::string("foo"), std::string("cpnmu===")))(case_t(std::string("foob"), std::string("cpnmuog=")))(case_t(std::string("fooba"), std::string("cpnmuoj1")))(case_t(std::string("foobar"), std::string("cpnmuoj1e8======")));

  for (const case_t& val : cases) {
    std::string res;
    res = toBase32Hex(val.get<0>());
    BOOST_CHECK_EQUAL(res, val.get<1>());
    res = fromBase32Hex(val.get<1>());
    BOOST_CHECK_EQUAL(res, val.get<0>());
  }
};

BOOST_AUTO_TEST_SUITE_END();
