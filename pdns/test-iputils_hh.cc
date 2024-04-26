#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <bitset>
#include "iputils.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_iputils_hh)

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

  ComboAddress defaultport("213.244.168.210");
  BOOST_CHECK_EQUAL(defaultport.sin4.sin_port, htons(0));

  defaultport = ComboAddress("[::1]");
  BOOST_CHECK_EQUAL(defaultport.sin4.sin_port, htons(0));

  defaultport = ComboAddress("::1");
  BOOST_CHECK_EQUAL(defaultport.sin4.sin_port, htons(0));

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
  a.reset();
  b.reset();
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

BOOST_AUTO_TEST_CASE(test_ComboAddressReverse)
{
  ComboAddress a{"1.2.3.4"};
  BOOST_CHECK_EQUAL(a.toStringReversed(), "4.3.2.1");

  ComboAddress b{"192.168.0.1"};
  BOOST_CHECK_EQUAL(b.toStringReversed(), "1.0.168.192");

  ComboAddress c{"2001:db8::567:89ab"};
  BOOST_CHECK_EQUAL(c.toStringReversed(), "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2");

  ComboAddress d{"::1"};
  BOOST_CHECK_EQUAL(d.toStringReversed(), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0");

  ComboAddress e{"ab:cd::10"};
  BOOST_CHECK_EQUAL(e.toStringReversed(), "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.c.0.0.b.a.0.0");

  ComboAddress f{"4321:0:1:2:3:4:567:89ab"};
  BOOST_CHECK_EQUAL(f.toStringReversed(), "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4");
}

BOOST_AUTO_TEST_CASE(test_Mapping)
{
  ComboAddress lh("::1");
  BOOST_CHECK_EQUAL(lh.toString(), "::1");
}

BOOST_AUTO_TEST_CASE(test_Netmask) {
  ComboAddress local("127.0.0.1", 53);
  ComboAddress remote("130.161.252.29", 53);

  Netmask nm("127.0.0.1/24");
  BOOST_CHECK(nm.getBits() == 24);
  BOOST_CHECK(nm.match(local));
  BOOST_CHECK(!nm.match(remote));
  BOOST_CHECK(nm.isIPv4());
  BOOST_CHECK(!nm.isIPv6());

  Netmask nm6("fe80::92fb:a6ff:fe4a:51da/64");
  BOOST_CHECK(nm6.getBits() == 64);
  BOOST_CHECK(nm6.match("fe80::92fb:a6ff:fe4a:51db"));
  BOOST_CHECK(!nm6.match("fe81::92fb:a6ff:fe4a:51db"));
  BOOST_CHECK(!nm6.isIPv4());
  BOOST_CHECK(nm6.isIPv6());

  Netmask nmp("130.161.252.29/32");
  BOOST_CHECK(nmp.match(remote));

  Netmask nmp6("fe80::92fb:a6ff:fe4a:51da/128");
  BOOST_CHECK(nmp6.match("fe80::92fb:a6ff:fe4a:51da"));
  BOOST_CHECK(!nmp6.match("fe81::92fb:a6ff:fe4a:51db"));

  Netmask all("0.0.0.0/0");
  BOOST_CHECK(all.match(local) && all.match(remote));

  Netmask all6("::/0");
  BOOST_CHECK(all6.match("::1") && all6.match("fe80::92fb:a6ff:fe4a:51da"));


  Netmask fromCombo1(ComboAddress("192.0.2.1:53"), 32);
  Netmask fromCombo2(ComboAddress("192.0.2.1:54"), 32);
  BOOST_CHECK(fromCombo1 == fromCombo2);
  BOOST_CHECK(fromCombo1.match("192.0.2.1"));
  BOOST_CHECK(fromCombo1.match(ComboAddress("192.0.2.1:80")));
  BOOST_CHECK(fromCombo1.getNetwork() == ComboAddress("192.0.2.1"));
  BOOST_CHECK(fromCombo1.getMaskedNetwork() == ComboAddress("192.0.2.1"));

  Netmask nm25("192.0.2.255/25");
  BOOST_CHECK(nm25.getBits() == 25);
  BOOST_CHECK(nm25.getNetwork() == ComboAddress("192.0.2.128"));
  BOOST_CHECK(nm25.getMaskedNetwork() == ComboAddress("192.0.2.128"));

  /* Make sure that more specific Netmasks are lesser than less specific ones,
     as this is very useful when matching. */
  Netmask specific32("192.0.0.0/32");
  Netmask specific24("192.0.0.0/24");
  Netmask specific16("192.0.0.0/16");
  BOOST_CHECK(specific32 < specific24);
  BOOST_CHECK(specific24 > specific32);
  BOOST_CHECK(specific24 < specific16);
  BOOST_CHECK(specific16 > specific24);

  Netmask sameMask1("192.0.0.0/16");
  Netmask sameMask2("192.0.0.1/16");
  BOOST_CHECK(!(sameMask1 < sameMask2));
  BOOST_CHECK(!(sameMask2 > sameMask1));
  BOOST_CHECK(sameMask1 == sameMask2);

  Netmask nm1921("192.1.255.255/16");
  Netmask nm1922("192.2.255.255/16");
  BOOST_CHECK(!(nm1921 == nm1922));
  BOOST_CHECK(nm1921 < nm1922);
  BOOST_CHECK(nm1922 > nm1921);

  /* An empty Netmask should be larger than
     every others. */
  Netmask empty = Netmask();
  Netmask full("255.255.255.255/32");
  BOOST_CHECK(empty > all);
  BOOST_CHECK(all < empty);
  BOOST_CHECK(empty > full);
  BOOST_CHECK(full < empty);

  /* invalid (too large) mask */
  {
    Netmask invalidMaskV4("192.0.2.1/33");
    BOOST_CHECK_EQUAL(invalidMaskV4.getBits(), 32U);
    BOOST_CHECK(invalidMaskV4.getNetwork() == ComboAddress("192.0.2.1"));
    Netmask invalidMaskV6("fe80::92fb:a6ff:fe4a:51da/129");
    BOOST_CHECK_EQUAL(invalidMaskV6.getBits(), 128U);
    BOOST_CHECK(invalidMaskV6.getNetwork() == ComboAddress("fe80::92fb:a6ff:fe4a:51da"));
  }
  {
    Netmask invalidMaskV4(ComboAddress("192.0.2.1"), 33);
    BOOST_CHECK_EQUAL(invalidMaskV4.getBits(), 32U);
    BOOST_CHECK(invalidMaskV4.getNetwork() == ComboAddress("192.0.2.1"));
    Netmask invalidMaskV6(ComboAddress("fe80::92fb:a6ff:fe4a:51da"), 129);
    BOOST_CHECK_EQUAL(invalidMaskV6.getBits(), 128U);
    BOOST_CHECK(invalidMaskV6.getNetwork() == ComboAddress("fe80::92fb:a6ff:fe4a:51da"));
  }
}

static std::string NMGOutputToSorted(const std::string& str)
{
  std::vector<std::string> vect;
  stringtok(vect, str, ", ");
  std::sort(vect.begin(), vect.end());
  std::string result;
  for (const auto& entry : vect) {
    if (!result.empty()) {
      result += " ";
    }
    result += entry;
  }

  return result;
}

BOOST_AUTO_TEST_CASE(test_NetmaskGroup) {

  {
    NetmaskGroup ng;
    BOOST_CHECK_EQUAL(ng.empty(), true);
    BOOST_CHECK_EQUAL(ng.size(), 0U);
    ng.addMask("10.0.1.0");
    BOOST_CHECK_EQUAL(ng.empty(), false);
    BOOST_CHECK_EQUAL(ng.size(), 1U);
    BOOST_CHECK(ng.match(ComboAddress("10.0.1.0")));
    ng.toMasks("127.0.0.0/8, 10.0.0.0/24");
    BOOST_CHECK_EQUAL(ng.size(), 3U);
    BOOST_CHECK(ng.match(ComboAddress("127.0.0.1")));
    BOOST_CHECK(ng.match(ComboAddress("10.0.0.3")));
    BOOST_CHECK(ng.match(ComboAddress("10.0.1.0")));
    BOOST_CHECK(!ng.match(ComboAddress("128.1.2.3")));
    BOOST_CHECK(!ng.match(ComboAddress("10.0.1.1")));
    BOOST_CHECK(!ng.match(ComboAddress("::1")));
    ng.addMask("::1");
    BOOST_CHECK_EQUAL(ng.size(), 4U);
    BOOST_CHECK(ng.match(ComboAddress("::1")));
    BOOST_CHECK(!ng.match(ComboAddress("::2")));
    ng.addMask("fe80::/16");
    BOOST_CHECK_EQUAL(ng.size(), 5U);
    BOOST_CHECK(ng.match(ComboAddress("fe80::1")));
    BOOST_CHECK(!ng.match(ComboAddress("fe81::1")));
    BOOST_CHECK_EQUAL(NMGOutputToSorted(ng.toString()), NMGOutputToSorted("10.0.1.0/32, 127.0.0.0/8, 10.0.0.0/24, ::1/128, fe80::/16"));

    /* negative entries using the explicit flag */
    ng.addMask("172.16.0.0/16", true);
    BOOST_CHECK_EQUAL(ng.size(), 6U);
    BOOST_CHECK(ng.match(ComboAddress("172.16.1.1")));
    BOOST_CHECK(ng.match(ComboAddress("172.16.4.50")));
    ng.addMask("172.16.4.0/24", false);
    BOOST_CHECK_EQUAL(ng.size(), 7U);
    BOOST_CHECK(ng.match(ComboAddress("172.16.1.1")));
    BOOST_CHECK(!ng.match(ComboAddress("172.16.4.50")));
    ng.addMask("fe80::/24", false);
    BOOST_CHECK_EQUAL(ng.size(), 8U);
    BOOST_CHECK(!ng.match(ComboAddress("fe80::1")));
    BOOST_CHECK(!ng.match(ComboAddress("fe81::1")));
    /* not in fe80::/24 but in fe80::/16, should match */
    BOOST_CHECK(ng.match(ComboAddress("fe80:0100::1")));

    /* negative entries using '!' */
    BOOST_CHECK(ng.match(ComboAddress("172.16.10.80")));
    ng.addMask("!172.16.10.0/24");
    BOOST_CHECK_EQUAL(ng.size(), 9U);
    BOOST_CHECK(!ng.match(ComboAddress("172.16.10.80")));
    ng.addMask("2001:db8::/32");
    BOOST_CHECK_EQUAL(ng.size(), 10U);
    ng.addMask("!2001:db8::/64");
    BOOST_CHECK_EQUAL(ng.size(), 11U);
    BOOST_CHECK(!ng.match(ComboAddress("2001:db8::1")));
    /* not in 2001:db8::/64 but in 2001:db8::/32, should match */
    BOOST_CHECK(ng.match(ComboAddress("2001:db8:1::1")));

    BOOST_CHECK_EQUAL(NMGOutputToSorted(ng.toString()), NMGOutputToSorted("10.0.1.0/32, 127.0.0.0/8, 10.0.0.0/24, ::1/128, fe80::/16, 172.16.0.0/16, !172.16.4.0/24, !fe80::/24, !172.16.10.0/24, 2001:db8::/32, !2001:db8::/64"));
  }

  {
    /* this time using Netmask objects instead of strings */
    NetmaskGroup ng;
    BOOST_CHECK_EQUAL(ng.empty(), true);
    BOOST_CHECK_EQUAL(ng.size(), 0U);
    ng.addMask(Netmask("10.0.1.0"));
    BOOST_CHECK_EQUAL(ng.empty(), false);
    BOOST_CHECK_EQUAL(ng.size(), 1U);
    BOOST_CHECK(ng.match(ComboAddress("10.0.1.0")));
    ng.addMask(Netmask("127.0.0.0/8"));
    BOOST_CHECK_EQUAL(ng.size(), 2U);
    ng.addMask(Netmask("10.0.0.0/24"));
    BOOST_CHECK_EQUAL(ng.size(), 3U);
    BOOST_CHECK(ng.match(ComboAddress("127.0.0.1")));
    BOOST_CHECK(ng.match(ComboAddress("10.0.0.3")));
    BOOST_CHECK(ng.match(ComboAddress("10.0.1.0")));
    BOOST_CHECK(!ng.match(ComboAddress("128.1.2.3")));
    BOOST_CHECK(!ng.match(ComboAddress("10.0.1.1")));
    BOOST_CHECK(!ng.match(ComboAddress("::1")));
    ng.addMask(Netmask("::1"));
    BOOST_CHECK_EQUAL(ng.size(), 4U);
    BOOST_CHECK(ng.match(ComboAddress("::1")));
    BOOST_CHECK(!ng.match(ComboAddress("::2")));
    ng.addMask(Netmask("fe80::/16"));
    BOOST_CHECK_EQUAL(ng.size(), 5U);
    BOOST_CHECK(ng.match(ComboAddress("fe80::1")));
    BOOST_CHECK(!ng.match(ComboAddress("fe81::1")));
    BOOST_CHECK_EQUAL(NMGOutputToSorted(ng.toString()), NMGOutputToSorted("10.0.1.0/32, 127.0.0.0/8, 10.0.0.0/24, ::1/128, fe80::/16"));

    /* negative entries using the explicit flag */
    ng.addMask(Netmask("172.16.0.0/16"), true);
    BOOST_CHECK_EQUAL(ng.size(), 6U);
    BOOST_CHECK(ng.match(ComboAddress("172.16.1.1")));
    BOOST_CHECK(ng.match(ComboAddress("172.16.4.50")));
    ng.addMask(Netmask("172.16.4.0/24"), false);
    BOOST_CHECK_EQUAL(ng.size(), 7U);
    BOOST_CHECK(ng.match(ComboAddress("172.16.1.1")));
    BOOST_CHECK(!ng.match(ComboAddress("172.16.4.50")));
    ng.addMask("fe80::/24", false);
    BOOST_CHECK_EQUAL(ng.size(), 8U);
    BOOST_CHECK(!ng.match(ComboAddress("fe80::1")));
    BOOST_CHECK(!ng.match(ComboAddress("fe81::1")));
    /* not in fe80::/24 but in fe80::/16, should match */
    BOOST_CHECK(ng.match(ComboAddress("fe80:0100::1")));

    BOOST_CHECK_EQUAL(NMGOutputToSorted(ng.toString()), NMGOutputToSorted("10.0.1.0/32, 127.0.0.0/8, 10.0.0.0/24, ::1/128, fe80::/16, 172.16.0.0/16, !172.16.4.0/24, !fe80::/24"));
  }
}

BOOST_AUTO_TEST_CASE(test_NetmaskTree) {
  NetmaskTree<int> nmt;
  BOOST_CHECK_EQUAL(nmt.empty(), true);
  BOOST_CHECK_EQUAL(nmt.size(), 0U);
  nmt.insert(Netmask("130.161.252.0/24")).second=0;
  BOOST_CHECK_EQUAL(nmt.empty(), false);
  BOOST_CHECK_EQUAL(nmt.size(), 1U);
  nmt.insert(Netmask("130.161.0.0/16")).second=1;
  BOOST_CHECK_EQUAL(nmt.size(), 2U);
  nmt.insert(Netmask("130.0.0.0/8")).second=2;
  BOOST_CHECK_EQUAL(nmt.size(), 3U);

  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("213.244.168.210")), (void*)0);
  auto found=nmt.lookup(ComboAddress("130.161.252.29"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 0);
  found=nmt.lookup(ComboAddress("130.161.180.1"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 1);

  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.255.255.255"))->second, 2);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.161.252.255"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.161.253.255"))->second, 1);

  found=nmt.lookup(ComboAddress("130.145.180.1"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 2);

  nmt.insert(Netmask("0.0.0.0/0")).second=3;
  BOOST_CHECK_EQUAL(nmt.size(), 4U);
  nmt.insert(Netmask("0.0.0.0/7")).second=4;
  BOOST_CHECK_EQUAL(nmt.size(), 5U);
  nmt.insert(Netmask("0.0.0.0/15")).second=5;
  BOOST_CHECK_EQUAL(nmt.size(), 6U);
  BOOST_CHECK_EQUAL(nmt.lookup(Netmask("0.0.0.0/0"))->second, 3);
  BOOST_CHECK_EQUAL(nmt.lookup(Netmask("0.0.0.0/7"))->second, 4);
  BOOST_CHECK_EQUAL(nmt.lookup(Netmask("0.0.0.0/15"))->second, 5);

  nmt.clear();
  BOOST_CHECK_EQUAL(nmt.empty(), true);
  BOOST_CHECK_EQUAL(nmt.size(), 0U);
  BOOST_CHECK(!nmt.lookup(ComboAddress("130.161.180.1")));

  nmt.insert(Netmask("::1")).second=1;
  BOOST_CHECK_EQUAL(nmt.empty(), false);
  BOOST_CHECK_EQUAL(nmt.size(), 1U);
  nmt.insert(Netmask("::/0")).second=0;
  BOOST_CHECK_EQUAL(nmt.size(), 2U);
  nmt.insert(Netmask("fe80::/16")).second=2;
  BOOST_CHECK_EQUAL(nmt.size(), 3U);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.161.253.255")), (void*)0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::2"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::ffff"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::1"))->second, 1);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("fe80::1"))->second, 2);
}

BOOST_AUTO_TEST_CASE(test_single) {
  NetmaskTree<bool> nmt;
  BOOST_CHECK_EQUAL(nmt.empty(), true);
  BOOST_CHECK_EQUAL(nmt.size(), 0U);
  nmt.insert(Netmask("127.0.0.0/8")).second=1;
  BOOST_CHECK_EQUAL(nmt.empty(), false);
  BOOST_CHECK_EQUAL(nmt.size(), 1U);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("127.0.0.1"))->second, 1);
}

BOOST_AUTO_TEST_CASE(test_scale) {
  string start="192.168.";
  NetmaskTree<int> works;
  BOOST_CHECK_EQUAL(works.size(), 0U);
  for(size_t i=0; i < 256; ++i) {
    for(size_t j=0; j < 256; ++j) {
      works.insert(Netmask(start+std::to_string(i)+"."+std::to_string(j))).second=i*j;
      BOOST_CHECK_EQUAL(works.size(), i*256 + j + 1);
    }
  }

  for(int i=0; i < 256; ++i) {
    for(int j=0; j < 256; ++j) {
      BOOST_CHECK_EQUAL(works.lookup(ComboAddress(start+std::to_string(i)+"."+std::to_string(j)))->second, i*j);
    }
  }

  start="130.161.";
  for(int i=0; i < 256; ++i) {
    for(int j=0; j < 256; ++j) {
      BOOST_CHECK_EQUAL(works.lookup(ComboAddress(start+std::to_string(i)+"."+std::to_string(j))), (void*)0);
    }
  }

  start="2000:123:";
  for(size_t i=0; i < 256; ++i) {
    for(size_t j=0; j < 256; ++j) {
      works.insert(Netmask(start+std::to_string(i)+":"+std::to_string(j)+"::/64")).second=i*j;
      BOOST_CHECK_EQUAL(works.size(), (256*256) + i*256 + j + 1);
    }
  }

  for(int i=0; i < 256; ++i) {
    for(int j=0; j < 256; ++j) {
      BOOST_CHECK_EQUAL(works.lookup(ComboAddress(start+std::to_string(i)+":"+std::to_string(j)+"::"+std::to_string(i)+":"+std::to_string(j)))->second, i*j);
    }
  }

  start="2001:123:";
  for(int i=0; i < 256; ++i) {
    for(int j=0; j < 256; ++j) {
      BOOST_CHECK_EQUAL(works.lookup(ComboAddress(start+std::to_string(i)+":"+std::to_string(j)+"::"+std::to_string(i)+":"+std::to_string(j))), (void*)0);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_removal) {
  std::string prefix = "192.";
  NetmaskTree<int> nmt;
  BOOST_CHECK(nmt.empty());
  BOOST_CHECK_EQUAL(nmt.size(), 0U);

  size_t count = 0;
  for(unsigned int i = 0; i < 256; ++i) {
    for(unsigned int j = 16; j <= 32; ++j) {
      nmt.insert(Netmask(prefix + std::to_string(i) +".127.255/"+std::to_string(j))).second = j;
      count++;
      BOOST_CHECK_EQUAL(nmt.size(), count);
    }
  }

  for(unsigned int i = 0; i < 256; ++i) {
    ComboAddress key(prefix + std::to_string(i) + ".127.255");
    const auto result = nmt.lookup(key);
    BOOST_CHECK_EQUAL(result->first.getBits(), 32);
    BOOST_CHECK_EQUAL(result->first.getMaskedNetwork().toString(), key.toString());
    BOOST_CHECK_EQUAL(result->second, 32);
  }

  for(int i = 0; i < 256; ++i) {
    for(int j = 32; j >= 16; --j) {
      ComboAddress key(prefix + std::to_string(i) + ".127.255");
      nmt.erase(Netmask(key, j));
      count--;
      BOOST_CHECK_EQUAL(nmt.size(), count);
      const auto result = nmt.lookup(key);

      if (j > 16) {
        BOOST_REQUIRE(result != nullptr);
        BOOST_CHECK_EQUAL(result->first.getBits(), j-1);
        BOOST_CHECK_EQUAL(result->first.getMaskedNetwork().toString(), Netmask(key, j-1).getMaskedNetwork().toString());
        BOOST_CHECK_EQUAL(result->second, j - 1);
      }
      else {
        BOOST_CHECK(result == nullptr);
      }
    }
  }

  BOOST_CHECK_EQUAL(nmt.size(), 0U);
  BOOST_CHECK(nmt.empty());
}

BOOST_AUTO_TEST_CASE(test_iterator) {
  NetmaskTree<int> masks_set1;
  std::set<Netmask> masks_set2;

  // create sets. the std::set entries are normalized to match internal behavior
  // of NetmaskTree
  for(int i=0; i < 256; ++i) {
    std::stringstream ss;
    Netmask mask;

    ss << i << "." << i << "." << i << "." << i;
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << (255-i) << "." << (i/2) << "." << (i/3) << "." << (i/5);
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << (i/5) << "." << (i/3) << "." << (i/2) << "." << (255-i);
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << (i/2) << "." << (i/4) << "." << (255-i) << ".0/" << (i%24);
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << std::hex << "2001:" << i << i << ":" << i << i << "::/64";
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << std::hex << "2001:" << (i/5) << (i/3) << ":" << (i/2) << (255-i) << "::/64";
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << std::hex << "2001:" << (255-i) << (i/2) << ":" << (i/3) << (i/5) << "::/64";
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << std::hex << "20" << i/2 << ":" << i/3 << i/7 << "::" << i << (i > 0 ? i-1 : i + 1);
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << std::hex << "20" << i << ":" << i << i << "::/" << std::dec << (i%48);
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());
  }
  for(int i=0; i <= 32; ++i) {
    std::stringstream ss;
    Netmask mask;

    ss << "85.85.85.85/" << i;
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << "170.170.170.170/" << i;
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());
  }
  for(int i=0; i <= 128; ++i) {
    std::stringstream ss;
    Netmask mask;

    ss << "5555:5555:5555:5555:5555:5555:5555:5555/" << i;
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());

    ss.str("");
    ss << "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa/" << i;
    mask = Netmask(ss.str());
    masks_set1.insert(mask).second=i;
    masks_set2.insert(mask.getNormalized());
  }


  // check set equality using iterators
  BOOST_CHECK_EQUAL(masks_set1.size(), masks_set2.size());
  BOOST_CHECK_EQUAL((size_t)std::distance(masks_set1.begin(), masks_set1.end()),
                    (size_t)std::distance(masks_set2.begin(), masks_set2.end()));
  for (auto entry: masks_set1) {
    Netmask mask = entry.first.getNormalized();

    BOOST_CHECK(masks_set2.find(mask) != masks_set2.end());
  }
  for (const Netmask& mask: masks_set2) {
    BOOST_CHECK(masks_set1.lookup(mask) != nullptr);
  }

  // create a copy of the NetmaskTree (check copy by assignment)
  NetmaskTree<int> masks_set1_cp1 = masks_set1;

  // taint the old version
  masks_set1.insert("1.2.3.4");
  masks_set1.erase("1.1.1.1");

  // check set equality using iterators
  BOOST_CHECK_EQUAL(masks_set1_cp1.size(), masks_set2.size());
  BOOST_CHECK_EQUAL((size_t)std::distance(masks_set1_cp1.begin(), masks_set1_cp1.end()),
                    (size_t)std::distance(masks_set2.begin(), masks_set2.end()));
  for (auto entry: masks_set1_cp1) {
    Netmask mask = entry.first.getNormalized();

    BOOST_CHECK(masks_set2.find(mask) != masks_set2.end());
  }
  for (const Netmask& mask: masks_set2) {
    BOOST_CHECK(masks_set1_cp1.lookup(mask) != nullptr);
  }

  // create a copy of the NetmaskTree (check copy constructor)
  NetmaskTree<int> masks_set1_cp2(masks_set1_cp1);

  // taint the old version
  masks_set1_cp1.insert("2.3.4.5");
  masks_set1_cp1.erase("2.2.2.2");

  // check set equality using iterators
  BOOST_CHECK_EQUAL(masks_set1_cp2.size(), masks_set2.size());
  BOOST_CHECK_EQUAL((size_t)std::distance(masks_set1_cp2.begin(), masks_set1_cp2.end()),
                    (size_t)std::distance(masks_set2.begin(), masks_set2.end()));
  for (auto entry: masks_set1_cp2) {
    Netmask mask = entry.first.getNormalized();

    BOOST_CHECK(masks_set2.find(mask) != masks_set2.end());
  }
  for (const Netmask& mask: masks_set2) {
    BOOST_CHECK(masks_set1_cp2.lookup(mask) != nullptr);
  }

  // swap contents of the NetmaskTree
  NetmaskTree<int> masks_set1_cp3;
  masks_set1_cp3.swap(masks_set1_cp2);

  // taint the old version
  masks_set1_cp2.insert("3.4.5.6");
  masks_set1_cp2.erase("3.3.3.3");

  // check set equality using iterators
  BOOST_CHECK_EQUAL(masks_set1_cp3.size(), masks_set2.size());
  BOOST_CHECK_EQUAL((size_t)std::distance(masks_set1_cp3.begin(), masks_set1_cp3.end()),
                    (size_t)std::distance(masks_set2.begin(), masks_set2.end()));
  for (auto entry: masks_set1_cp3) {
    Netmask mask = entry.first.getNormalized();

    BOOST_CHECK(masks_set2.find(mask) != masks_set2.end());
  }
  for (const Netmask& mask: masks_set2) {
    BOOST_CHECK(masks_set1_cp3.lookup(mask) != nullptr);
  }

  // copy contents to an std::set
  std::set<NetmaskTree<int>::node_type> masks_set1_cp4(masks_set1_cp3.begin(), masks_set1_cp3.end());

  // check set equality
  BOOST_CHECK_EQUAL(masks_set1_cp4.size(), masks_set2.size());
  for (auto entry: masks_set1_cp4) {
    Netmask mask = entry.first.getNormalized();

    BOOST_CHECK(masks_set2.find(mask) != masks_set2.end());
  }
  for (const Netmask& mask: masks_set2) {
    Netmask maskl = mask.getNormalized();
    bool found = false;
    for (auto entry: masks_set1_cp4) {
      Netmask maskr = entry.first.getNormalized();

      if (maskl == maskr)
        found = true;
    }
    BOOST_CHECK(found);
  }

  // create a copy of the NetmaskTree
  NetmaskTree<int> masks_set1_cp5(masks_set1_cp3);

  // erase select values
  {
    Netmask mask;

    mask = Netmask("16.16.16.16");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("223.16.10.6");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("12.21.32.191");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("64.32.127.0/8");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("2001:ffff:ffff::/64");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("2001:192a:407f::/64");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("2001:bf20:15c::/64");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("2010:a4::201f");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("2010:1010::/16");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("85.85.85.85");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("170.170.170.170");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("5555:5555:5555:5555:5555:5555:5555:5555");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());

    mask = Netmask("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa");
    masks_set1_cp5.erase(mask);
    masks_set2.erase(mask.getNormalized());
  }

  // check set equality using iterators
  BOOST_CHECK_EQUAL(masks_set1_cp5.size(), masks_set2.size());
  BOOST_CHECK_EQUAL((size_t)std::distance(masks_set1_cp5.begin(), masks_set1_cp5.end()),
                    (size_t)std::distance(masks_set2.begin(), masks_set2.end()));
  for (auto entry: masks_set1_cp5) {
    Netmask mask = entry.first.getNormalized();

    BOOST_CHECK(masks_set2.find(mask) != masks_set2.end());
  }
  for (const Netmask& mask: masks_set2) {
    BOOST_CHECK(masks_set1_cp5.lookup(mask) != nullptr);
  }
}

BOOST_AUTO_TEST_CASE(test_ComboAddress_caContainerToString) {
  ComboAddress ca1("192.0.2.1:53");
  ComboAddress ca2("192.0.2.2:5300");
  ComboAddress ca3("[2001:db8:53::3]:53");
  ComboAddress ca4("[2001:db8:53::4]:5300");

  set<ComboAddress> caSet({ca1, ca2, ca3, ca4});
  vector<ComboAddress> caVector({ca1, ca2, ca3, ca4});

  string caSetStr = ComboAddress::caContainerToString(caSet, false);
  string caVectorStr = ComboAddress::caContainerToString(caVector, false);
  BOOST_CHECK_EQUAL(caSetStr, "192.0.2.1,192.0.2.2,2001:db8:53::3,2001:db8:53::4");
  BOOST_CHECK_EQUAL(caVectorStr, "192.0.2.1,192.0.2.2,2001:db8:53::3,2001:db8:53::4");

  caSetStr = ComboAddress::caContainerToString(caSet, true);
  caVectorStr = ComboAddress::caContainerToString(caVector, true);
  BOOST_CHECK_EQUAL(caSetStr, "192.0.2.1,192.0.2.2:5300,2001:db8:53::3,[2001:db8:53::4]:5300");
  BOOST_CHECK_EQUAL(caVectorStr, "192.0.2.1,192.0.2.2:5300,2001:db8:53::3,[2001:db8:53::4]:5300");

  caSetStr = ComboAddress::caContainerToString(caSet, true, 0);
  caVectorStr = ComboAddress::caContainerToString(caVector, true, 0);
  BOOST_CHECK_EQUAL(caSetStr, "192.0.2.1:53,192.0.2.2:5300,[2001:db8:53::3]:53,[2001:db8:53::4]:5300");
  BOOST_CHECK_EQUAL(caVectorStr, "192.0.2.1:53,192.0.2.2:5300,[2001:db8:53::3]:53,[2001:db8:53::4]:5300");
}

BOOST_AUTO_TEST_CASE(test_parseIPAndPort)
{
  struct {
    std::string str;
    uint16_t port;
    std::string result;
    bool ex;
  } tests[] = {
    { "", 0, "", true },
    { "1.2.3.a", 53, "", true },
    { "1::g3", 99, "", true },
    { "1.2.3.4", 0, "1.2.3.4:0", false },
    { "1.2.3.4", 999, "1.2.3.4:999", false },
    { "1::", 999, "[1::]:999", false },
    { "1::33:99", 0, "[1::33:99]", false },
    { "[1::33]:99", 0, "[1::33]:99", false },
    { "1:33::99", 0, "1:33::99", false },
    { "[1:33::]:99", 0, "[1:33::]:99", false },
    { "2003:1234::f561", 53, "[2003:1234::f561]:53", false },
    { "2003:1234::f561:53", 54, "[2003:1234::f561:53]:54", false },
  };

  for (const auto& t : tests) {
    if (t.ex) {
      BOOST_CHECK_THROW(parseIPAndPort(t.str, t.port), PDNSException);
    } else {
      ComboAddress a = parseIPAndPort(t.str, t.port);
      BOOST_CHECK_EQUAL(a.toStringWithPort(), ComboAddress(t.result).toStringWithPort());
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()
