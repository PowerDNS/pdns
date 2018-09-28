#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <bitset>
#include "iputils.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_nmtree)

BOOST_AUTO_TEST_CASE(test_basic) {
  NetmaskTree<int> nmt;
  nmt.insert(Netmask("130.161.252.0/24")).second=0;
  nmt.insert(Netmask("130.161.0.0/16")).second=1;
  nmt.insert(Netmask("130.0.0.0/8")).second=2;

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

  nmt.clear();
  BOOST_CHECK(!nmt.lookup(ComboAddress("130.161.180.1")));

  nmt.insert(Netmask("::1")).second=1;
  nmt.insert(Netmask("::/0")).second=0;
  nmt.insert(Netmask("fe80::/16")).second=2;
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.161.253.255")), (void*)0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::2"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::ffff"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::1"))->second, 1);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("fe80::1"))->second, 2);
}

BOOST_AUTO_TEST_CASE(test_single) {
  NetmaskTree<bool> nmt;
  nmt.insert(Netmask("127.0.0.0/8")).second=1;
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("127.0.0.1"))->second, 1);
}

BOOST_AUTO_TEST_CASE(test_scale) {
  string start="192.168.";
  NetmaskTree<int> works;
  for(int i=0; i < 256; ++i) {
    for(int j=0; j < 256; ++j) {
      works.insert(Netmask(start+std::to_string(i)+"."+std::to_string(j))).second=i*j;
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
  for(int i=0; i < 256; ++i) {
    for(int j=0; j < 256; ++j) {
      works.insert(Netmask(start+std::to_string(i)+":"+std::to_string(j)+"::/64")).second=i*j;
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
  NetmaskTree<int> nmt(true);

  size_t count = 0;
  for(unsigned int i = 0; i < 256; ++i) {
    for(unsigned int j = 16; j <= 32; ++j) {
      nmt.insert(Netmask(prefix + std::to_string(i) +".127.255/"+std::to_string(j))).second = j;
      count++;
    }
  }

  BOOST_CHECK_EQUAL(nmt.size(), count);

  for(unsigned int i = 0; i < 256; ++i) {
    ComboAddress key(prefix + std::to_string(i) + ".127.255");
    const auto result = nmt.lookup(key);
    BOOST_CHECK_EQUAL(result->first.getBits(), 32);
    BOOST_CHECK_EQUAL(result->first.getMaskedNetwork().toString(), key.toString());
    BOOST_CHECK_EQUAL(result->second, 32);
  }

  for(unsigned int i = 0; i < 256; ++i) {
    for(unsigned int j = 32; j >= 16; --j) {
      ComboAddress key(prefix + std::to_string(i) + ".127.255");
      nmt.erase(Netmask(key, j));
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

  BOOST_CHECK_EQUAL(nmt.size(), 0);
  BOOST_CHECK(nmt.empty());
}

BOOST_AUTO_TEST_SUITE_END()
