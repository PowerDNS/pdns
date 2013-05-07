#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include "base64.hh"
BOOST_AUTO_TEST_SUITE(base64_cc)

BOOST_AUTO_TEST_CASE(test_Base64_Roundtrip) {
  std::string before("Some Random String"), after;
  std::string encoded = Base64Encode(before);
  B64Decode(encoded, after);
  BOOST_CHECK_EQUAL(before, after);
}

BOOST_AUTO_TEST_SUITE_END()
