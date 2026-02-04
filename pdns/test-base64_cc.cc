#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include <boost/assign/std/map.hpp>

#include "base64.hh"
#include "openssl/conf.h"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_base64_cc)

BOOST_AUTO_TEST_CASE(test_Base64_Roundtrip) {
  const std::string before("Some Random String");
  const auto encoded = Base64Encode(before);

  std::string after;
  B64Decode(encoded, after);
  BOOST_CHECK_EQUAL(before, after);
}

/* for a in $(seq 1 32);
   do
    plain=$(pwgen -1  -s $a)
    echo  \(\"$plain\",\"$(echo -n $plain | openssl enc -base64)\"\) ;
   done
*/

BOOST_AUTO_TEST_CASE(test_Base64_Encode) {
  using cases_t = std::map<std::string, std::string>;
  cases_t cases;
  assign::insert(cases)
    ("", "")
    ("z","eg==")
    ("x4","eDQ=")
    ("J07","SjA3")
    ("kl8F","a2w4Rg==")
    ("2NUx9","Mk5VeDk=")
    ("hwXQ8C","aHdYUThD")
    ("V7ZHmlG","VjdaSG1sRw==")
    ("FuNFLSd5","RnVORkxTZDU=")
    ("YVGwy3Vbi","WVZHd3kzVmJp")
    ("6ueW4V3oLG","NnVlVzRWM29MRw==")
    ("d5zR7AWIBIQ","ZDV6UjdBV0lCSVE=")
    ("WJjZ6xgpRMCD","V0pqWjZ4Z3BSTUNE")
    ("e8I52L0vC9Kfq","ZThJNTJMMHZDOUtmcQ==")
    ("ufxMi8EZgTDja8","dWZ4TWk4RVpnVERqYTg=")
    ("MiNPxzxUkNXCFg1","TWlOUHh6eFVrTlhDRmcx")
    ("abqIPosEky85gFVM","YWJxSVBvc0VreTg1Z0ZWTQ==")
    ("Qccuox8igoyRKEeTo","UWNjdW94OGlnb3lSS0VlVG8=")
    ("wbaw6g6WWo4iiYXosV","d2JhdzZnNldXbzRpaVlYb3NW")
    ("ZIfJZIA3Kd0a6iIr0vc","WklmSlpJQTNLZDBhNmlJcjB2Yw==")
    ("SUhE1RK7xrRfvYOiaPMQ","U1VoRTFSSzd4clJmdllPaWFQTVE=")
    ("ZAWsEeB4bcTUzTr828VTd","WkFXc0VlQjRiY1RVelRyODI4VlRk")
    ("xc9rpu0F5ztR7r3jElr2BS","eGM5cnB1MEY1enRSN3IzakVscjJCUw==")
    ("xvEWPkZjqVjIZwsL5WhijES","eHZFV1BrWmpxVmpJWndzTDVXaGlqRVM=")
    ("yy4yAmcBKCNF3hWriWbDnKmF","eXk0eUFtY0JLQ05GM2hXcmlXYkRuS21G")
    ("9wKEMpl8OlFvnD10wwhoK7BjY","OXdLRU1wbDhPbEZ2bkQxMHd3aG9LN0JqWQ==")
    ("SB6yLm39pDVIUiQ5g73BvyRzBs","U0I2eUxtMzlwRFZJVWlRNWc3M0J2eVJ6QnM=")
    ("Acu4kk1puF98lIzd1b9bt8ha7Er","QWN1NGtrMXB1Rjk4bEl6ZDFiOWJ0OGhhN0Vy")
    ("P4X6efItE6cn03ksLTvniqMQlel3","UDRYNmVmSXRFNmNuMDNrc0xUdm5pcU1RbGVsMw==")
    ("RnQSvhIOz3ywuHCoSotJGKjBdCVbx","Um5RU3ZoSU96M3l3dUhDb1NvdEpHS2pCZENWYng=")
    ("ykybXtN0lelsLSzyzd4DTP3sYp8YGu","eWt5Ylh0TjBsZWxzTFN6eXpkNERUUDNzWXA4WUd1")
    ("eSHBt7Xx5F7A4HFtabXEzDLD01bnSiG","ZVNIQnQ3WHg1RjdBNEhGdGFiWEV6RExEMDFiblNpRw==")
    ("dq4KydZjmcoQQ45VYBP2EDR8FqKaMul0","ZHE0S3lkWmptY29RUTQ1VllCUDJFRFI4RnFLYU11bDA=");

  for (const auto& val : cases) {
    const auto encoded = Base64Encode(val.first);
    BOOST_CHECK_EQUAL(encoded, val.second);
    std::string decoded;
    B64Decode(val.second, decoded);
    BOOST_CHECK_EQUAL(decoded, val.first);
  }
}

BOOST_AUTO_TEST_CASE(test_Base64_Decode_Garbage)
{
  const std::string paddingOnly("====");
  std::string decoded;
  auto ret = B64Decode(paddingOnly, decoded);
#if OPENSSL_VERSION_NUMBER >= 0x30500000
  BOOST_CHECK_EQUAL(ret, -1);
#else
  // does not test anything meaningful, but avoids a "ret unused" warning
  BOOST_CHECK(ret == 0 || ret == -1);
#endif
}

BOOST_AUTO_TEST_SUITE_END()
