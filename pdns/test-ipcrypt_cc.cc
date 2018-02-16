#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "ipcipher.hh"
#include "misc.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_ipcrypt_hh)

BOOST_AUTO_TEST_CASE(test_ipcrypt4)
{
  ComboAddress ca("127.0.0.1");
  std::string key="0123456789ABCDEF";
  auto encrypted = encryptCA(ca, key);

  auto decrypted = decryptCA(encrypted, key);
  BOOST_CHECK_EQUAL(ca.toString(), decrypted.toString());
}

BOOST_AUTO_TEST_CASE(test_ipcrypt4_vector)
{
  vector<pair<string,string>>  tests{   // test vector from https://github.com/veorq/ipcrypt
    {{"127.0.0.1"},{"114.62.227.59"}},
    {{"8.8.8.8"},  {"46.48.51.50"}},
    {{"1.2.3.4"},  {"171.238.15.199"}}};

  std::string key="some 16-byte key";

  for(const auto& p : tests) {
    auto encrypted = encryptCA(ComboAddress(p.first), key);
    BOOST_CHECK_EQUAL(encrypted.toString(), p.second);
    auto decrypted = decryptCA(encrypted, key);
    BOOST_CHECK_EQUAL(decrypted.toString(), p.first);
  }

  // test from Frank Denis' test.cc
  ComboAddress ip("192.168.69.42"), out, dec;
  string key2;
  for(int n=0; n<16; ++n)
    key2.append(1, (char)n+1);

  for (unsigned int i = 0; i < 100000000UL; i++) {
    out=encryptCA(ip, key2);
    //    dec=decryptCA(out, key2);
    // BOOST_CHECK(ip==dec);
    ip=out;
  }

  ComboAddress expected("93.155.197.186");

  BOOST_CHECK_EQUAL(ip.toString(), expected.toString());
}


BOOST_AUTO_TEST_CASE(test_ipcrypt6)
{
  ComboAddress ca("::1");
  std::string key="0123456789ABCDEF";
  auto encrypted = encryptCA(ca, key);

  auto decrypted = decryptCA(encrypted, key);
  BOOST_CHECK_EQUAL(ca.toString(), decrypted.toString());
}


BOOST_AUTO_TEST_SUITE_END()
