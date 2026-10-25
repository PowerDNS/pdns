#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <openssl/err.h>

#include "digests.hh"
#include "misc.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_digests_hh)

BOOST_AUTO_TEST_CASE(test_pdns_md5sum)
{
  std::string result = "a3 24 8c e3 1a 88 a6 40 e6 30 73 98 57 6d 06 9e ";
  std::string sum = pdns::md5("a quick brown fox jumped over the lazy dog");

  BOOST_CHECK_EQUAL(makeHexDump(sum), result);
}

BOOST_AUTO_TEST_CASE(test_pdns_sha1sum)
{
  std::string result = "b9 37 10 0d c9 57 b3 86 d9 cb 77 fc 90 c0 18 22 fd eb 6e 7f ";
  std::string sum = pdns::sha1("a quick brown fox jumped over the lazy dog");

  BOOST_CHECK_EQUAL(makeHexDump(sum), result);
}

#if OPENSSL_VERSION_MAJOR >= 3
BOOST_AUTO_TEST_CASE(test_pdns_hash_failure_clears_error_queue)
{
  /* make the digest fetch fail, as MD5 does when only the FIPS provider is available */
  BOOST_REQUIRE_EQUAL(EVP_set_default_properties(nullptr, "provider=pdns-test-none"), 1);
  ERR_clear_error();
  BOOST_CHECK_THROW(pdns::md5("a quick brown fox jumped over the lazy dog"), std::runtime_error);
  const auto pending = ERR_peek_error();
  BOOST_REQUIRE_EQUAL(EVP_set_default_properties(nullptr, ""), 1);

  /* an error left on the queue breaks the next OpenSSL user on this thread, e.g. libmysqlclient */
  BOOST_CHECK_EQUAL(pending, 0UL);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
