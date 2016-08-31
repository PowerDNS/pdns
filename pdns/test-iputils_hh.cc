#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <bitset>
#include "iputils.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(iputils_hh)

BOOST_AUTO_TEST_CASE(test_ComboAddress) {
  ComboAddress local("127.0.0.1", 53);
  BOOST_CHECK(local==local);
  BOOST_CHECK_EQUAL(local.sin4.sin_family, AF_INET);
  BOOST_CHECK_EQUAL(local.sin4.sin_port, htons(53));
  BOOST_CHECK_EQUAL(local.sin4.sin_addr.s_addr, htonl(0x7f000001UL));

  ComboAddress remote("130.161.33.15", 53);
  BOOST_CHECK(!(local == remote));
  BOOST_CHECK_EQUAL(remote.sin4.sin_port, htons(53));
  
  ComboAddress withport("213.244.168.210:53");
  BOOST_CHECK_EQUAL(withport.sin4.sin_port, htons(53));
  
  ComboAddress withportO("213.244.168.210:53", 5300);
  BOOST_CHECK_EQUAL(withportO.sin4.sin_port, htons(53));
 
  withport = ComboAddress("[::]:53");
  BOOST_CHECK_EQUAL(withport.sin4.sin_port, htons(53));
  
  withport = ComboAddress("[::]:5300", 53);
  BOOST_CHECK_EQUAL(withport.sin4.sin_port, htons(5300));

  // Verify that 2 'empty' ComboAddresses are equal, used in syncres.hh to
  // signal auth-zones
  ComboAddress a = ComboAddress();
  ComboAddress b = ComboAddress();
  BOOST_CHECK(a == b);

  // Verify that 2 ComboAddresses are not the same
  ComboAddress c = ComboAddress("127.0.0.1:53");
  ComboAddress d = ComboAddress("127.0.0.1:52");
  ComboAddress e = ComboAddress("127.0.0.2:53");

  BOOST_CHECK(a != c);
  BOOST_CHECK(c != d);
  BOOST_CHECK(c != e);
  BOOST_CHECK(d != e);
  BOOST_CHECK(!(a != b));

  // Verify that we don't allow invalid port numbers
  BOOST_CHECK_THROW(ComboAddress("127.0.0.1:70000"), PDNSException); // Port no. too high
  BOOST_CHECK_THROW(ComboAddress("127.0.0.1:-6"), PDNSException); // Port no. too low
  BOOST_CHECK_THROW(ComboAddress("[::1]:70000"), PDNSException); // Port no. too high
  BOOST_CHECK_THROW(ComboAddress("[::1]:-6"), PDNSException); // Port no. too low
}

BOOST_AUTO_TEST_CASE(test_ComboAddressCompare) {
  ComboAddress a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  BOOST_CHECK(!(a<b));
  BOOST_CHECK(!(a>b));
}

BOOST_AUTO_TEST_CASE(test_ComboAddressTruncate) {
  ComboAddress ca4("130.161.252.29");
  ca4.truncate(24);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.252.0");
  ca4.truncate(16);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.0.0");



  ca4 = ComboAddress("130.161.252.29");
  ComboAddress orig(ca4);
  for(int n=32; n; --n) {
    ca4.truncate(n);

    uint32_t p;
    memcpy(&p, (char*)&ca4.sin4.sin_addr.s_addr, 4);
    std::bitset<32> result(htonl(p));

    memcpy(&p, (char*)&orig.sin4.sin_addr.s_addr, 4);
    std::bitset<32> manual(htonl(p));

    auto tokill=32-n;
    for(int i =0; i< tokill; ++i)
      manual.set(i, 0);

    BOOST_CHECK_EQUAL(result, manual);
  }

  ca4 = ComboAddress("130.161.252.29");
  ca4.truncate(31);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.252.28");

  ca4.truncate(30);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.252.28");

  ca4.truncate(29);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.252.24");
  
  ca4.truncate(23);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.252.0");

  ca4.truncate(22);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.252.0");

  ca4.truncate(21);
  BOOST_CHECK_EQUAL(ca4.toString(), "130.161.248.0");

  ComboAddress ca6("2001:888:2000:1d::2");
  ca6.truncate(120);
  BOOST_CHECK_EQUAL(ca6.toString(), "2001:888:2000:1d::");
  ca6.truncate(64);
  BOOST_CHECK_EQUAL(ca6.toString(), "2001:888:2000:1d::");
  ca6.truncate(72);                  // 0102 304 0506 78
  BOOST_CHECK_EQUAL(ca6.toString(), "2001:888:2000:1d::");
  ca6.truncate(56);
  BOOST_CHECK_EQUAL(ca6.toString(), "2001:888:2000::");
  ca6.truncate(48);
  BOOST_CHECK_EQUAL(ca6.toString(), "2001:888:2000::");
  ca6.truncate(32);
  BOOST_CHECK_EQUAL(ca6.toString(), "2001:888::");
  ca6.truncate(16);
  BOOST_CHECK_EQUAL(ca6.toString(), "2001::");
  ca6.truncate(8);
  BOOST_CHECK_EQUAL(ca6.toString(), "2000::");
  

  orig=ca6=ComboAddress("2001:888:2000:1d::2");
  for(int n=128; n; --n) {
    ca6.truncate(n);

    std::bitset<128> result, manual;
    for(int i=0; i < 16; ++i) {
      result<<=8;
      result|= std::bitset<128>(*((unsigned char*)&ca6.sin6.sin6_addr.s6_addr + i));

      manual<<=8;
      manual|= std::bitset<128>(*((unsigned char*)&orig.sin6.sin6_addr.s6_addr + i));
    }

    auto tokill=128-n;
    for(int i =0; i< tokill; ++i)
      manual.set(i, 0);

    BOOST_CHECK_EQUAL(result, manual);
  }
}


BOOST_AUTO_TEST_CASE(test_Mapping)
{
  ComboAddress lh("::1");
  BOOST_CHECK_EQUAL(lh.toString(), "::1");

  ComboAddress lh2("::2");
  BOOST_CHECK_EQUAL(lh2.toString(), "::2");  
  
}

BOOST_AUTO_TEST_CASE(test_Netmask) {
  ComboAddress local("127.0.0.1", 53);
  ComboAddress remote("130.161.252.29", 53);
  
  Netmask nm("127.0.0.1/24");
  BOOST_CHECK(nm.match(local));
  BOOST_CHECK(!nm.match(remote));

  Netmask nm6("fe80::92fb:a6ff:fe4a:51da/64");
  BOOST_CHECK(nm6.match("fe80::92fb:a6ff:fe4a:51db"));
  BOOST_CHECK(!nm6.match("fe81::92fb:a6ff:fe4a:51db"));

  Netmask nmp("130.161.252.29/32");
  BOOST_CHECK(nmp.match(remote));

  Netmask nmp6("fe80::92fb:a6ff:fe4a:51da/128");
  BOOST_CHECK(nmp6.match("fe80::92fb:a6ff:fe4a:51da"));
  BOOST_CHECK(!nmp6.match("fe81::92fb:a6ff:fe4a:51db"));

  Netmask all("0.0.0.0/0");
  BOOST_CHECK(all.match(local) && all.match(remote));

  Netmask all6("::/0");
  BOOST_CHECK(all6.match("::1") && all6.match("fe80::92fb:a6ff:fe4a:51da"));
}

BOOST_AUTO_TEST_CASE(test_NetmaskGroup) {
  NetmaskGroup ng;
  ng.addMask("10.0.1.0");
  BOOST_CHECK(ng.match(ComboAddress("10.0.1.0")));
  ng.toMasks("127.0.0.0/8, 10.0.0.0/24");
  BOOST_CHECK(ng.match(ComboAddress("127.0.0.1")));
  BOOST_CHECK(ng.match(ComboAddress("10.0.0.3")));
  BOOST_CHECK(ng.match(ComboAddress("10.0.1.0")));
  BOOST_CHECK(!ng.match(ComboAddress("128.1.2.3")));
  BOOST_CHECK(!ng.match(ComboAddress("10.0.1.1")));
  BOOST_CHECK(!ng.match(ComboAddress("::1")));
  ng.addMask("::1");
  BOOST_CHECK(ng.match(ComboAddress("::1")));
  BOOST_CHECK(!ng.match(ComboAddress("::2")));
  ng.addMask("fe80::/16");
  BOOST_CHECK(ng.match(ComboAddress("fe80::1")));
  BOOST_CHECK(!ng.match(ComboAddress("fe81::1")));
}


BOOST_AUTO_TEST_SUITE_END()
