#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>

#include "sha.hh"
#include "misc.hh"

using namespace boost;
using namespace boost::assign;

BOOST_AUTO_TEST_SUITE(test_sha_hh)

// input, output
typedef boost::tuple<const std::string, const std::string> case_t;
typedef std::vector<case_t> cases_t;

BOOST_AUTO_TEST_CASE(test_sha1)
{
  cases_t cases = list_of(case_t("abc", "a9 99 3e 36 47 06 81 6a ba 3e 25 71 78 50 c2 6c 9c d0 d8 9d "))(case_t("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84 98 3e 44 1c 3b d2 6e ba ae 4a a1 f9 51 29 e5 e5 46 70 f1 "));

  for (case_t& val : cases) {
    BOOST_CHECK_EQUAL(makeHexDump(pdns_sha1sum(val.get<0>())), val.get<1>());
  }
}

BOOST_AUTO_TEST_CASE(test_sha256)
{
  cases_t cases = list_of(case_t("abc", "ba 78 16 bf 8f 01 cf ea 41 41 40 de 5d ae 22 23 b0 03 61 a3 96 17 7a 9c b4 10 ff 61 f2 00 15 ad "))(case_t("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "24 8d 6a 61 d2 06 38 b8 e5 c0 26 93 0c 3e 60 39 a3 3c e4 59 64 ff 21 67 f6 ec ed d4 19 db 06 c1 "));

  for (case_t& val : cases) {
    BOOST_CHECK_EQUAL(makeHexDump(pdns_sha256sum(val.get<0>())), val.get<1>());
  }
}

BOOST_AUTO_TEST_CASE(test_sha384)
{
  cases_t cases = list_of(case_t("abc", "cb 00 75 3f 45 a3 5e 8b b5 a0 3d 69 9a c6 50 07 27 2c 32 ab 0e de d1 63 1a 8b 60 5a 43 ff 5b ed 80 86 07 2b a1 e7 cc 23 58 ba ec a1 34 c8 25 a7 "))(case_t("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "33 91 fd dd fc 8d c7 39 37 07 a6 5b 1b 47 09 39 7c f8 b1 d1 62 af 05 ab fe 8f 45 0d e5 f3 6b c6 b0 45 5a 85 20 bc 4e 6f 5f e9 5b 1f e3 c8 45 2b "));

  for (case_t& val : cases) {
    BOOST_CHECK_EQUAL(makeHexDump(pdns_sha384sum(val.get<0>())), val.get<1>());
  }
}

BOOST_AUTO_TEST_CASE(test_sha512)
{
  cases_t cases = list_of(case_t("abc", "dd af 35 a1 93 61 7a ba cc 41 73 49 ae 20 41 31 12 e6 fa 4e 89 a9 7e a2 0a 9e ee e6 4b 55 d3 9a 21 92 99 2a 27 4f c1 a8 36 ba 3c 23 a3 fe eb bd 45 4d 44 23 64 3c e8 0e 2a 9a c9 4f a5 4c a4 9f "))(case_t("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "20 4a 8f c6 dd a8 2f 0a 0c ed 7b eb 8e 08 a4 16 57 c1 6e f4 68 b2 28 a8 27 9b e3 31 a7 03 c3 35 96 fd 15 c1 3b 1b 07 f9 aa 1d 3b ea 57 78 9c a0 31 ad 85 c7 a7 1d d7 03 54 ec 63 12 38 ca 34 45 "));

  for (case_t& val : cases) {
    BOOST_CHECK_EQUAL(makeHexDump(pdns_sha512sum(val.get<0>())), val.get<1>());
  }
}

BOOST_AUTO_TEST_SUITE_END()
