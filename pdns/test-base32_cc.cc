#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include "base32.hh"

BOOST_AUTO_TEST_SUITE(test_base32_cc)

BOOST_AUTO_TEST_CASE(test_record_types) {
  typedef boost::tuple<const std::string, const std::string> case_t;
  typedef std::list<case_t> cases_t;

  // RFC test vectors
  cases_t cases = boost::assign::list_of
    (case_t(std::string(""), std::string("")))
    (case_t(std::string("f"), std::string("CO======")))
    (case_t(std::string("fo"), std::string("CPNG====")))
    (case_t(std::string("foo"), std::string("CPNMU===")))
    (case_t(std::string("foob"), std::string("CPNMUOG=")))
    (case_t(std::string("fooba"), std::string("CPNMUOJ1")))
    (case_t(std::string("foobar"), std::string("CPNMUOJ1E8======")))
  ;

  BOOST_FOREACH(const case_t& val, cases) {
     std::string res;
     res = toBase32Hex(val.get<0>());
     BOOST_CHECK_EQUAL(res, val.get<1>());
     res = fromBase32Hex(val.get<1>());
     BOOST_CHECK_EQUAL(res, val.get<0>());
  }
};

BOOST_AUTO_TEST_SUITE_END();
