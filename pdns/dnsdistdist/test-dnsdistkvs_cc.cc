
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-kvs.hh"

BOOST_AUTO_TEST_SUITE(dnsdistkvs_cc)

#ifdef HAVE_LMDB
BOOST_AUTO_TEST_CASE(test_LMDB) {

  auto lmdb = make_unique<LMDBKVStore>("/data/Dumps/lmdb", "db-name");
  auto key = make_unique<KeyValueLookupKeySourceIP>();

  DNSName qname("powerdns.com.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  ComboAddress lc("127.0.0.1:53");
  ComboAddress rem("127.0.0.1:42");
  struct dnsheader dh;
  memset(&dh, 0, sizeof(dh));
  size_t bufferSize = 0;
  size_t queryLen = 0;
  bool isTcp = false;
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  DNSQuestion dq(&qname, qtype, qclass, qname.wirelength(), &lc, &rem, &dh, bufferSize, queryLen, isTcp, &queryRealTime);

  DTime dt;
  dt.set();
  for (size_t idx = 0; idx < 10000000; idx++) {
    std::string value = lmdb->getValue(key->getKey(dq));
    BOOST_CHECK_EQUAL(value, "this is the value of the tag");
  }
  cerr<<dt.udiff()/1000/1000<<endl;
}
#endif /* HAVE_LMDB */

BOOST_AUTO_TEST_SUITE_END()
