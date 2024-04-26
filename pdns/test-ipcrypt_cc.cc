#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_IPCIPHER

#include <boost/test/unit_test.hpp>
#include "ipcipher.hh"
#include "misc.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_ipcrypt_hh)

BOOST_AUTO_TEST_CASE(test_ipcrypt4)
{
  ComboAddress address("127.0.0.1");
  std::string key = "0123456789ABCDEF";
  auto encrypted = encryptCA(address, key);

  auto decrypted = decryptCA(encrypted, key);
  BOOST_CHECK_EQUAL(address.toString(), decrypted.toString());
}

BOOST_AUTO_TEST_CASE(test_ipcrypt4_vector)
{
  // test vector from https://github.com/veorq/ipcrypt
  vector<pair<string, string>> tests{{{"127.0.0.1"}, {"114.62.227.59"}},
                                     {{"8.8.8.8"}, {"46.48.51.50"}},
                                     {{"1.2.3.4"}, {"171.238.15.199"}}};

  std::string key = "some 16-byte key";

  for (const auto& p : tests) {
    auto encrypted = encryptCA(ComboAddress(p.first), key);
    BOOST_CHECK_EQUAL(encrypted.toString(), p.second);
    auto decrypted = decryptCA(encrypted, key);
    BOOST_CHECK_EQUAL(decrypted.toString(), p.first);
  }

  // test from Frank Denis' test.cc
  ComboAddress address("192.168.69.42");
  ComboAddress out;
  ComboAddress dec;
  string key2;
  for (int n = 0; n < 16; ++n) {
    key2.append(1, (char)n + 1);
  }

  for (unsigned int i = 0; i < 100000000UL; i++) {
    out = encryptCA(address, key2);
    //    dec=decryptCA(out, key2);
    // BOOST_CHECK(ip==dec);
    address = out;
  }

  ComboAddress expected("93.155.197.186");

  BOOST_CHECK_EQUAL(address.toString(), expected.toString());
}

BOOST_AUTO_TEST_CASE(test_ipcrypt6)
{
  ComboAddress address("::1");
  std::string key = "0123456789ABCDEF";
  auto encrypted = encryptCA(address, key);

  auto decrypted = decryptCA(encrypted, key);
  BOOST_CHECK_EQUAL(address.toString(), decrypted.toString());
}

BOOST_AUTO_TEST_SUITE_END()

#endif /* HAVE_IPCIPHER */
