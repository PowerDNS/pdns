
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <thread>
#include <boost/test/unit_test.hpp>

#include "dnsdist-rules.hh"

static DNSQuestion getDQ(const DNSName* providedName = nullptr)
{
  static const DNSName qname("powerdns.com.");
  static const ComboAddress lc("127.0.0.1:53");
  static const ComboAddress rem("192.0.2.1:42");
  static struct timespec queryRealTime;
  static PacketBuffer packet(sizeof(dnsheader));

  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  auto proto = dnsdist::Protocol::DoUDP;
  gettime(&queryRealTime, true);

  DNSQuestion dq(providedName ? providedName : &qname, qtype, qclass, &lc, &rem, packet, proto, &queryRealTime);
  return dq;
}

BOOST_AUTO_TEST_SUITE(dnsdistluarules_cc)

BOOST_AUTO_TEST_CASE(test_MaxQPSIPRule) {
  size_t maxQPS = 10;
  size_t maxBurst = maxQPS;
  unsigned int expiration = 300;
  unsigned int cleanupDelay = 60;
  unsigned int scanFraction = 10;
  MaxQPSIPRule rule(maxQPS, maxBurst, 32, 64, expiration, cleanupDelay, scanFraction);

  DNSName qname("powerdns.com.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  ComboAddress lc("127.0.0.1:53");
  ComboAddress rem("192.0.2.1:42");
  PacketBuffer packet(sizeof(dnsheader));
  auto proto = dnsdist::Protocol::DoUDP;
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  DNSQuestion dq(&qname, qtype, qclass, &lc, &rem, packet, proto, &queryRealTime);

  for (size_t idx = 0; idx < maxQPS; idx++) {
    /* let's use different source ports, it shouldn't matter */
    rem = ComboAddress("192.0.2.1:" + std::to_string(idx));
    BOOST_CHECK_EQUAL(rule.matches(&dq), false);
    BOOST_CHECK_EQUAL(rule.getEntriesCount(), 1U);
  }

  /* maxQPS + 1, we should be blocked */
  BOOST_CHECK_EQUAL(rule.matches(&dq), true);
  BOOST_CHECK_EQUAL(rule.getEntriesCount(), 1U);

  /* remove all entries that have not been updated since 'now' + 1,
     so all of them */
  expiredTime.tv_sec += 1;
  rule.cleanup(expiredTime);

  /* we should have been cleaned up */
  BOOST_CHECK_EQUAL(rule.getEntriesCount(), 0U);

  struct timespec beginInsertionTime;
  gettime(&beginInsertionTime);
  /* we should not be blocked anymore */
  BOOST_CHECK_EQUAL(rule.matches(&dq), false);
  /* and we be back */
  BOOST_CHECK_EQUAL(rule.getEntriesCount(), 1U);


  /* Let's insert a lot of different sources now */
  for (size_t idxByte3 = 0; idxByte3 < 256; idxByte3++) {
    for (size_t idxByte4 = 0; idxByte4 < 256; idxByte4++) {
      rem = ComboAddress("10.0." + std::to_string(idxByte3) + "." + std::to_string(idxByte4));
      BOOST_CHECK_EQUAL(rule.matches(&dq), false);
    }
  }
  struct timespec endInsertionTime;
  gettime(&endInsertionTime);

  /* don't forget the existing entry */
  size_t total = 1 + 256 * 256;
  BOOST_CHECK_EQUAL(rule.getEntriesCount(), total);

  /* make sure all entries are still valid */
  struct timespec notExpiredTime = beginInsertionTime;
  notExpiredTime.tv_sec -= 1;

  size_t scanned = 0;
  auto removed = rule.cleanup(notExpiredTime, &scanned);
  BOOST_CHECK_EQUAL(removed, 0U);
  /* the first entry should still have been valid, we should not have scanned more */
  BOOST_CHECK_EQUAL(scanned, 1U);
  BOOST_CHECK_EQUAL(rule.getEntriesCount(), total);

  /* make sure all entries are _not_ valid anymore */
  expiredTime = endInsertionTime;
  expiredTime.tv_sec += 1;

  removed = rule.cleanup(expiredTime, &scanned);
  BOOST_CHECK_EQUAL(removed, (total / scanFraction) + 1);
  /* we should not have scanned more than scanFraction */
  BOOST_CHECK_EQUAL(scanned, removed);
  BOOST_CHECK_EQUAL(rule.getEntriesCount(), total - removed);

  rule.clear();
  BOOST_CHECK_EQUAL(rule.getEntriesCount(), 0U);
  removed = rule.cleanup(expiredTime, &scanned);
  BOOST_CHECK_EQUAL(removed, 0U);
  BOOST_CHECK_EQUAL(scanned, 0U);
}

BOOST_AUTO_TEST_CASE(test_poolOutstandingRule) {
  auto dq = getDQ();

  ServerPool sp{};
  auto ds1 = std::make_shared<DownstreamState>(ComboAddress("192.0.2.1:53"));
  auto ds2 = std::make_shared<DownstreamState>(ComboAddress("192.0.2.2:53"));

  /* increase the outstanding count of both */
  ds1->outstanding = 400;
  ds2->outstanding = 30;

  sp.addServer(ds1);
  sp.addServer(ds2);

  BOOST_CHECK_EQUAL(sp.poolLoad(), 400+30);

  auto localPool = g_pools.getCopy();
  addServerToPool(localPool, "test", ds1);
  addServerToPool(localPool, "test", ds2);
  g_pools.setState(localPool);

  PoolOutstandingRule pOR1("test", 10);
  BOOST_CHECK_EQUAL(pOR1.matches(&dq), true);

  PoolOutstandingRule pOR2("test", 1000);
  BOOST_CHECK_EQUAL(pOR2.matches(&dq), false);
}

BOOST_AUTO_TEST_SUITE_END()
