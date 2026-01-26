
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-metrics.hh"
#include "dnsdist-rings.hh"

Rings g_rings;
shared_ptr<BPFFilter> g_defaultBPFFilter{nullptr};

#ifndef DISABLE_DYNBLOCKS

BOOST_AUTO_TEST_SUITE(dnsdistdynblocks_hh)

struct TestFixture
{
  TestFixture()
  {
    g_rings.reset();
    Rings::RingsConfiguration config{
      .capacity = 10000U,
      .numberOfShards = 10U,
    };
    g_rings.init(config);
  }
  ~TestFixture()
  {
    g_rings.reset();
  }
};

static size_t s_samplingRate{10};

struct TestFixtureWithSampling
{
  TestFixtureWithSampling()
  {
    g_rings.reset();
    Rings::RingsConfiguration config{
      .capacity = 10000U,
      .numberOfShards = 10U,
      .samplingRate = s_samplingRate,
    };
    g_rings.init(config);
  }
  ~TestFixtureWithSampling()
  {
    g_rings.reset();
  }
};

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_QueryRate, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 0;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* block above 50 qps for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setQueryRate(std::move(rule));
  }

  {
    /* insert 45 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
      /* we do not care about the response during that test, but we want to make sure
         these do not interfere with the computation */
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfQueries);
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 qps from a given client in the last 10s
       this should trigger the rule this time */
    size_t numberOfQueries = (50 * numberOfSeconds) + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

  {
    /* clear the rings and dynamic blocks */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    /* Insert 100 qps from a given client in the last 10s
       this should trigger the rule */
    size_t numberOfQueries = 100;

    for (size_t timeIdx = 0; timeIdx < numberOfSeconds; timeIdx++) {
      for (size_t idx = 0; idx < numberOfQueries; idx++) {
        struct timespec when = now;
        when.tv_sec -= (9 - timeIdx);
        g_rings.insertQuery(when, requestor1, qname, qtype, size, dnsHeader, protocol);
        g_rings.insertResponse(when, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
      }
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries * numberOfSeconds);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);

    /* now we clean up the dynamic blocks, simulating an admin removing the block */
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();
    /* we apply the rules again, but as if we were 20s in the future.
       Since we have a time windows of 10s nothing should be added,
       regardless of the number of queries
    */
    struct timespec later = now;
    later.tv_sec += 20;
    dbrg.apply(later);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);

    /* just in case */
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    /* we apply the rules again, this tile as if we were 5s in the future.
       Since we have a time windows of 10s, and 100 qps over 5s then 0 qps over 5s
       is more than 50qps over 10s, the block should be added
    */
    later = now;
    later.tv_sec += 5;
    dbrg.apply(later);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);

    /* clean up */
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    /* we apply the rules again, this tile as if we were 6s in the future.
       Since we have a time windows of 10s, and 100 qps over 4s then 0 qps over 6s
       is LESS than 50qps over 10s, the block should NOT be added
    */
    later = now;
    later.tv_sec += 6;
    dbrg.apply(later);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_QueryRate_RangeV6, TestFixture)
{
  /* Check that we correctly group IPv6 addresses from the same /64 subnet into the same
     dynamic block entry, if instructed to do so */
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("2001:db8::1");
  ComboAddress backend("2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 0;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);
  dbrg.setMasks(32, 64, 0);

  {
    /* block above 50 qps for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setQueryRate(std::move(rule));
  }

  {
    /* insert 45 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
      /* we do not care about the response during that test, but we want to make sure
         these do not interfere with the computation */
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfQueries);
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(requestor1, 128, 16)) == nullptr);
  }

  {
    /* insert just above 50 qps from several clients in the same /64 IPv6 range in the last 10s,
       this should trigger the rule this time */
    size_t numberOfQueries = (50 * numberOfSeconds) + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      ComboAddress requestor("2001:db8::" + std::to_string(idx));
      g_rings.insertQuery(now, requestor, qname, qtype, size, dnsHeader, protocol);
      g_rings.insertResponse(now, requestor, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);

    {
      /* beginning of the range should be blocked */
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(requestor1, 128, 16))->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      BOOST_CHECK_EQUAL(block.blocks, 0U);
      BOOST_CHECK_EQUAL(block.warning, false);
    }

    {
      /* end of the range should be blocked as well */
      ComboAddress end("2001:0db8:0000:0000:ffff:ffff:ffff:ffff");
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(end, 128, 16))->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      BOOST_CHECK_EQUAL(block.blocks, 0U);
      BOOST_CHECK_EQUAL(block.warning, false);
    }

    {
      /* outside of the range should NOT */
      ComboAddress out("2001:0db8:0000:0001::0");
      BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(out, 128, 16)) == nullptr);
    }
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_QueryRate_V4Ports, TestFixture)
{
  /* Check that we correctly split IPv4 addresses based on port ranges, when instructed to do so */
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1:42");
  ComboAddress backend("192.0.2.254");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  unsigned int responseTime = 0;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);
  /* split v4 by ports using a  /2 (0 - 16383, 16384 - 32767, 32768 - 49151, 49152 - 65535) */
  dbrg.setMasks(32, 128, 2);

  {
    /* block above 50 qps for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setQueryRate(std::move(rule));
  }

  {
    /* insert 45 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
      /* we do not care about the response during that test, but we want to make sure
         these do not interfere with the computation */
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfQueries);
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(requestor1, 128, 16)) == nullptr);
  }

  {
    /* insert just above 50 qps from several clients in the same IPv4 port range in the last 10s,
       this should trigger the rule this time */
    size_t numberOfQueries = (50 * numberOfSeconds) + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      ComboAddress requestor("192.0.2.1:" + std::to_string(idx));
      g_rings.insertQuery(now, requestor, qname, qtype, size, dnsHeader, protocol);
      g_rings.insertResponse(now, requestor, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);

    {
      /* beginning of the port range should be blocked */
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(ComboAddress("192.0.2.1:0"), 32, 16))->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      BOOST_CHECK_EQUAL(block.blocks, 0U);
      BOOST_CHECK_EQUAL(block.warning, false);
    }

    {
      /* end of the range should be blocked as well */
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(ComboAddress("192.0.2.1:16383"), 32, 16))->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      BOOST_CHECK_EQUAL(block.blocks, 0U);
      BOOST_CHECK_EQUAL(block.warning, false);
    }

    {
      /* outside of the range should not */
      BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(ComboAddress("192.0.2.1:16384"), 32, 16)) == nullptr);
    }

    /* we (again) insert just above 50 qps from several clients the same IPv4 port range, this should update the block which will
       check by looking at the blocked counter */
    {
      auto* block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(ComboAddress("192.0.2.1:0"), 32, 16));
      BOOST_REQUIRE(block != nullptr);
      BOOST_CHECK_EQUAL(block->second.blocks, 0U);
      block->second.blocks = 42U;
    }

    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      ComboAddress requestor("192.0.2.1:" + std::to_string(idx));
      g_rings.insertQuery(now, requestor, qname, qtype, size, dnsHeader, protocol);
      g_rings.insertResponse(now, requestor, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);

    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    {
      /* previous address/port should still be blocked */
      auto* block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(ComboAddress("192.0.2.1:0"), 32, 16));
      BOOST_REQUIRE(block != nullptr);
      BOOST_CHECK_EQUAL(block->second.blocks, 42U);
    }

    /* but not a different one */
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(ComboAddress("192.0.2.1:16384"), 32, 16)) == nullptr);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_QueryRate_responses, TestFixture)
{
  /* check that the responses are not accounted as queries when a
     rcode rate rule is defined (sounds very specific but actually happened) */
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 0;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  /* 100k entries, one shard */
  g_rings.reset();
  Rings::RingsConfiguration config{
    .capacity = 1000000U,
  };
  g_rings.init(config);

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* block above 50 qps for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setQueryRate(std::move(rule));
  }
  {
    DynBlockRulesGroup::DynBlockRule rule("Exceeded ServFail rate", 60, 50, 40, 5, DNSAction::Action::Drop);
    dbrg.setRCodeRate(RCode::ServFail, std::move(rule));
  }

  {
    /* insert 45 qps (including responses) from a given client for the last 100s
       this should not trigger the rule */
    size_t numberOfQueries = 45;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t timeIdx = 0; timeIdx < 100; timeIdx++) {
      struct timespec when = now;
      when.tv_sec -= (99 - timeIdx);
      for (size_t idx = 0; idx < numberOfQueries; idx++) {
        g_rings.insertQuery(when, requestor1, qname, qtype, size, dnsHeader, protocol);
        /* we do not care about the response during that test, but we want to make sure
           these do not interfere with the computation */
        g_rings.insertResponse(when, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
      }
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfQueries * 100);
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries * 100);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_QTypeRate, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* block above 50 qps for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setQTypeRate(QType::AAAA, std::move(rule));
  }

  {
    /* insert 45 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 qps from a given client in the last 10s
       but for the wrong QType */
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, QType::A, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    // insert just above 50 qps from a given client in the last 10s
    // this should trigger the rule this time
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_RCodeRate, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 100 * 1000; /* 100ms */
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";
  const uint16_t rcode = RCode::ServFail;

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* block above 50 ServFail/s for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setRCodeRate(rcode, std::move(rule));
  }

  {
    /* insert 45 ServFail/s from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfResponses = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 FormErr/s from a given client in the last 10s */
    size_t numberOfResponses = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = RCode::FormErr;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 ServFail/s from a given client in the last 10s
       this should trigger the rule this time */
    size_t numberOfResponses = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_RCodeRate_With_Sampling, TestFixtureWithSampling)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 100 * 1000; /* 100ms */
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";
  const uint16_t rcode = RCode::ServFail;

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* block above 50 ServFail/s for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setRCodeRate(rcode, std::move(rule));
  }

  {
    /* insert 45 ServFail/s from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfResponses = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses / s_samplingRate);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 FormErr/s from a given client in the last 10s */
    size_t numberOfResponses = 50 * numberOfSeconds + s_samplingRate;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = RCode::FormErr;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_GE(g_rings.getNumberOfResponseEntries(), (numberOfResponses / s_samplingRate));

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 ServFail/s from a given client in the last 10s
       this should trigger the rule this time */
    size_t numberOfResponses = 50 * numberOfSeconds + s_samplingRate;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_GE(g_rings.getNumberOfResponseEntries(), (numberOfResponses / s_samplingRate));

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_REQUIRE(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_RCodeRatio, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 100 * 1000; /* 100ms */
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  time_t numberOfSeconds = 10;
  unsigned int blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query ratio";
  const uint16_t rcode = RCode::ServFail;

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* block above 0.2 ServFail/Total ratio over numberOfSeconds seconds, no warning, minimum number of queries should be at least 51 */
    DynBlockRulesGroup::DynBlockRatioRule rule(reason, blockDuration, 0.2, 0.0, numberOfSeconds, action, 51);
    dbrg.setRCodeRatio(rcode, std::move(rule));
  }

  {
    /* insert 20 ServFail and 80 NoErrors from a given client in the last 10s
       this should not trigger the rule */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < 20; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    dnsHeader.rcode = RCode::NoError;
    for (size_t idx = 0; idx < 80; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 100U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just 50 FormErrs and nothing else, from a given client in the last 10s */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = RCode::FormErr;
    for (size_t idx = 0; idx < 50; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 50U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert 21 ServFails and 79 NoErrors from a given client in the last 10s
       this should trigger the rule this time */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < 21; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    dnsHeader.rcode = RCode::NoError;
    for (size_t idx = 0; idx < 79; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 100U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_REQUIRE(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(block.until.tv_sec, now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

  {
    /* insert 11 ServFails and 39 NoErrors from a given client in the last 10s
       this should NOT trigger the rule since we don't have more than 50 queries */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < 11; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    dnsHeader.rcode = RCode::NoError;
    for (size_t idx = 0; idx < 39; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 50U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_ResponseByteRate, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 100;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 100 * 1000; /* 100ms */
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";
  const uint16_t rcode = RCode::NoError;

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* block above 10kB/s for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 10000, 0, numberOfSeconds, action);
    dbrg.setResponseByteRate(std::move(rule));
  }

  {
    /* insert 99 answers of 100 bytes per second from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfResponses = 99 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 100 answers of 100 bytes per second from a given client in the last 10s */
    size_t numberOfResponses = 100 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    dnsHeader.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_CacheMissRatio, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  ComboAddress cacheHit;
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 100 * 1000; /* 100ms */
  struct timespec now{};
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  time_t numberOfSeconds = 10;
  unsigned int blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded cache-miss ratio";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  /* block above 0.5 Cache-Miss/Total ratio over numberOfSeconds seconds, no warning, minimum number of queries should be at least 51, global cache hit at least 80% */
  dnsdist::metrics::g_stats.cacheHits.store(80);
  dnsdist::metrics::g_stats.cacheMisses.store(20);
  {
    DynBlockRulesGroup::DynBlockCacheMissRatioRule rule(reason, blockDuration, 0.5, 0.0, numberOfSeconds, action, 51, 0.8);
    dbrg.setCacheMissRatio(std::move(rule));
  }

  {
    /* insert 50 cache misses and 50 cache hits from a given client in the last 10s
       this should not trigger the rule */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < 20; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    for (size_t idx = 0; idx < 80; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, cacheHit, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 100U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert 51 cache misses and 49 hits from a given client in the last 10s
       this should trigger the rule this time */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < 51; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    for (size_t idx = 0; idx < 49; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, cacheHit, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 100U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_REQUIRE(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(block.until.tv_sec, now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

  {
    /* insert 40 misses and 10 hits from a given client in the last 10s
       this should NOT trigger the rule since we don't have more than 50 queries */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < 40; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    for (size_t idx = 0; idx < 10; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, cacheHit, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 50U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  /* the global cache-hit rate is too low, should not trigger */
  dnsdist::metrics::g_stats.cacheHits.store(60);
  dnsdist::metrics::g_stats.cacheMisses.store(40);
  {
    /* insert 51 cache misses and 49 hits from a given client in the last 10s */
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < 51; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, backend, outgoingProtocol);
    }
    for (size_t idx = 0; idx < 49; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dnsHeader, cacheHit, outgoingProtocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 100U);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_REQUIRE(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_Warning, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  {
    /* warn above 20 qps for numberOfSeconds seconds, block above 50 qps */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 20, numberOfSeconds, action);
    dbrg.setQueryRate(std::move(rule));
  }

  {
    /* insert 20 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 20 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 20 qps from a given client in the last 10s
       this should trigger the warning rule this time */
    size_t numberOfQueries = 20 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);

    {
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == DNSAction::Action::NoOp);
      BOOST_CHECK_EQUAL(block.blocks, 0U);
      BOOST_CHECK_EQUAL(block.warning, true);
      /* let's increment the number of blocks so we can check that the counter
         is preserved when the block is upgraded to a non-warning one */
      block.blocks++;
    }

    /* now inserts 50 qps for the same duration, we should reach the blocking threshold */
    numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);

    {
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      /* this should have been preserved */
      BOOST_CHECK_EQUAL(block.blocks, 1U);
      BOOST_CHECK_EQUAL(block.warning, false);
      block.blocks++;
    }

    /* 30s later, with the same amount of qps the duration of the block
       should be increased. */
    now.tv_sec += 30;
    numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);

    {
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      /* should have been updated */
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      /* this should have been preserved */
      BOOST_CHECK_EQUAL(block.blocks, 2U);
      BOOST_CHECK_EQUAL(block.warning, false);
    }
  }

  {
    /* insert directly just above 50 qps from a given client in the last 10s
       this should trigger the blocking rule right away this time */
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);

    {
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      BOOST_CHECK_EQUAL(block.blocks, 0U);
      BOOST_CHECK_EQUAL(block.warning, false);
    }
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesGroup_Ranges, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);
  /* include 192.0.2.0 -> 192.0.2.63 */
  dbrg.includeRange(Netmask("192.0.2.0/26"));
  /* but exclude 192.0.2.42 only */
  dbrg.excludeRange(Netmask("192.0.2.42/32"));

  {
    /* block above 50 qps for numberOfSeconds seconds, no warning */
    DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 50, 0, numberOfSeconds, action);
    dbrg.setQueryRate(std::move(rule));
  }

  {
    /* insert just above 50 qps from the two clients in the last 10s
       this should trigger the rule for the first one but not the second one */
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dnsHeader, protocol);
      g_rings.insertQuery(now, requestor2, qname, qtype, size, dnsHeader, protocol);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries * 2);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1U);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1) != nullptr);
    BOOST_CHECK(dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor2) == nullptr);
    const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }
}

BOOST_FIXTURE_TEST_CASE(test_DynBlockRulesMetricsCache_GetTopN, TestFixture)
{
  dnsheader dnsHeader{};
  memset(&dnsHeader, 0, sizeof(dnsHeader));
  DNSName qname("rings.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock, AddressAndPortRange> emptyNMG;
  SuffixMatchTree<DynBlock> emptySMT;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  g_rings.reset();
  /* 10M entries, only one shard */
  Rings::RingsConfiguration config{
    .capacity = 10000000U,
  };
  g_rings.init(config);

  {
    DynBlockRulesGroup dbrg;
    dbrg.setQuiet(true);
    g_rings.clear();
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();

    {
      /* block above 0 qps for numberOfSeconds seconds, no warning */
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 0, 0, numberOfSeconds, action);
      dbrg.setQueryRate(std::move(rule));
    }

    /* insert one fake query from 255 clients:
     */
    for (size_t idx = 0; idx < 256; idx++) {
      const ComboAddress requestor("192.0.2." + std::to_string(idx));
      g_rings.insertQuery(now, requestor, qname, qtype, size, dnsHeader, protocol);
    }

    /* we apply the rules, all clients should be blocked */
    dbrg.apply(now);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 256U);

    for (size_t idx = 0; idx < 256; idx++) {
      const ComboAddress requestor("192.0.2." + std::to_string(idx));
      const auto& block = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(requestor)->second;
      /* simulate that:
         - .1 does 1 query
         ...
         - .255 does 255 queries
      */
      block.blocks = idx;
    }

    /* now we ask for the top 20 offenders for each reason */
    StopWatch sw;
    sw.start();
    auto top = DynBlockMaintenance::getTopNetmasks(20);
    BOOST_REQUIRE_EQUAL(top.size(), 1U);
    auto offenders = top.at(reason);
    BOOST_REQUIRE_EQUAL(offenders.size(), 20U);
    auto it = offenders.begin();
    for (size_t idx = 236; idx < 256; idx++) {
      BOOST_CHECK_EQUAL(it->first.toString(), Netmask(ComboAddress("192.0.2." + std::to_string(idx))).toString());
      BOOST_CHECK_EQUAL(it->second, idx);
      ++it;
    }

    struct timespec expired = now;
    expired.tv_sec += blockDuration + 1;
    DynBlockMaintenance::purgeExpired(expired);
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
  }

  {
    /* === reset everything for SMT === */
    DynBlockRulesGroup dbrg;
    dbrg.setQuiet(true);
    g_rings.clear();
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();
    dnsdist::DynamicBlocks::clearSuffixDynamicRules();

    {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 0, 0, numberOfSeconds, action);
      dbrg.setSuffixMatchRule(std::move(rule), [](const StatNode& node, const StatNode::Stat& self, const StatNode::Stat& children) {
        (void)node;
        (void)children;
        if (self.queries > 0) {
          return std::tuple<bool, std::optional<std::string>, std::optional<int>>(true, std::nullopt, std::nullopt);
        }
        return std::tuple<bool, std::optional<std::string>, std::optional<int>>(false, std::nullopt, std::nullopt);
      });
    }

    /* insert one fake response for 255 DNS names */
    const ComboAddress requestor("192.0.2.1");
    for (size_t idx = 0; idx < 256; idx++) {
      g_rings.insertResponse(now, requestor, DNSName(std::to_string(idx)) + qname, qtype, 1000 /*usec*/, size, dnsHeader, requestor /* backend, technically, but we don't care */, outgoingProtocol);
    }

    /* we apply the rules, all suffixes should be blocked */
    dbrg.apply(now);

    for (size_t idx = 0; idx < 256; idx++) {
      const DNSName name(DNSName(std::to_string(idx)) + qname);
      const auto* block = dnsdist::DynamicBlocks::getSuffixDynamicRules().lookup(name);
      BOOST_REQUIRE(block != nullptr);
      BOOST_REQUIRE(block->action == action);
      /* simulate that:
         - 1.rings.powerdns.com. got 1 query
         ...
         - 255. does 255 queries
      */
      block->blocks = idx;
    }

    /* now we ask for the top 20 offenders for each reason */
    StopWatch sw;
    sw.start();
    auto top = DynBlockMaintenance::getTopSuffixes(20);
    BOOST_REQUIRE_EQUAL(top.size(), 1U);
    auto suffixes = top.at(reason);
    BOOST_REQUIRE_EQUAL(suffixes.size(), 20U);
    auto it = suffixes.begin();
    for (size_t idx = 236; idx < 256; idx++) {
      BOOST_CHECK_EQUAL(it->first, (DNSName(std::to_string(idx)) + qname));
      BOOST_CHECK_EQUAL(it->second, idx);
      ++it;
    }

    struct timespec expired = now;
    expired.tv_sec += blockDuration + 1;
    DynBlockMaintenance::purgeExpired(expired);
    BOOST_CHECK(dnsdist::DynamicBlocks::getSuffixDynamicRules().getNodes().empty());
  }

  {
    /* === reset everything for SMT, this time we will check that we can override the 'reason' via the visitor function === */
    DynBlockRulesGroup dbrg;
    dbrg.setQuiet(true);
    g_rings.clear();
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();
    dnsdist::DynamicBlocks::clearSuffixDynamicRules();

    {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 0, 0, numberOfSeconds, action);
      dbrg.setSuffixMatchRule(std::move(rule), [](const StatNode& node, const StatNode::Stat& self, const StatNode::Stat& children) {
        (void)node;
        (void)children;
        if (self.queries > 0) {
          return std::tuple<bool, std::optional<std::string>, std::optional<int>>(true, "blocked for a different reason", static_cast<int>(DNSAction::Action::Truncate));
        }
        return std::tuple<bool, std::optional<std::string>, std::optional<int>>(false, std::nullopt, std::nullopt);
      });
    }

    /* insert one fake response for 255 DNS names */
    const ComboAddress requestor("192.0.2.1");
    for (size_t idx = 0; idx < 256; idx++) {
      g_rings.insertResponse(now, requestor, DNSName(std::to_string(idx)) + qname, qtype, 1000 /*usec*/, size, dnsHeader, requestor /* backend, technically, but we don't care */, dnsdist::Protocol::DoUDP);
    }

    /* we apply the rules, all suffixes should be blocked */
    dbrg.apply(now);

    for (size_t idx = 0; idx < 256; idx++) {
      const DNSName name(DNSName(std::to_string(idx)) + qname);
      const auto* block = dnsdist::DynamicBlocks::getSuffixDynamicRules().lookup(name);
      BOOST_REQUIRE(block != nullptr);
      BOOST_REQUIRE(block->action == DNSAction::Action::Truncate);
      /* simulate that:
         - 1.rings.powerdns.com. got 1 query
         ...
         - 255. does 255 queries
      */
      block->blocks = idx;
    }

    /* now we ask for the top 20 offenders for each reason */
    StopWatch sw;
    sw.start();
    auto top = DynBlockMaintenance::getTopSuffixes(20);
    BOOST_REQUIRE_EQUAL(top.size(), 1U);
    auto suffixes = top.at("blocked for a different reason");
    BOOST_REQUIRE_EQUAL(suffixes.size(), 20U);
    auto it = suffixes.begin();
    for (size_t idx = 236; idx < 256; idx++) {
      BOOST_CHECK_EQUAL(it->first, (DNSName(std::to_string(idx)) + qname));
      BOOST_CHECK_EQUAL(it->second, idx);
      ++it;
    }

    struct timespec expired = now;
    expired.tv_sec += blockDuration + 1;
    DynBlockMaintenance::purgeExpired(expired);
    BOOST_CHECK(dnsdist::DynamicBlocks::getSuffixDynamicRules().getNodes().empty());
  }

#ifdef BENCH_DYNBLOCKS
  {
    /* now insert 1M names */
    DynBlockRulesGroup dbrg;
    dbrg.setQuiet(true);
    g_rings.clear();
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();
    dnsdist::DynamicBlocks::clearSuffixDynamicRules();

    {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 0, 0, numberOfSeconds, action);
      dbrg.setSuffixMatchRule(std::move(rule), [](const StatNode& node, const StatNode::Stat& self, const StatNode::Stat& children) {
        if (self.queries > 0) {
          return std::tuple<bool, std::optional<std::string>, std::optional<int>>(true, std::nullopt, std::nullopt);
        }
        return std::tuple<bool, std::optional<std::string>, std::optional<int>>(false, std::nullopt, std::nullopt);
      });
    }

    bool done = false;
    const ComboAddress requestor("192.0.2.1");
    for (size_t idxB = 0; !done && idxB < 256; idxB++) {
      for (size_t idxC = 0; !done && idxC < 256; idxC++) {
        for (size_t idxD = 0; !done && idxD < 256; idxD++) {
          const DNSName victim(std::to_string(idxB) + "." + std::to_string(idxC) + "." + std::to_string(idxD) + qname.toString());
          g_rings.insertResponse(now, requestor, victim, qtype, 1000 /*usec*/, size, dnsHeader, requestor /* backend, technically, but we don't care */, outgoingProtocol);
          if (g_rings.getNumberOfQueryEntries() == 1000000) {
            done = true;
            break;
          }
        }
      }
    }

    /* we apply the rules, all suffixes should be blocked */
    StopWatch sw;
    sw.start();
    dbrg.apply(now);
    cerr << "added 1000000 entries in " << std::to_string(sw.udiff() / 1024) << "ms" << endl;

    sw.start();
    auto top = DynBlockMaintenance::getTopSuffixes(20);
    cerr << "scanned 1000000 entries in " << std::to_string(sw.udiff() / 1024) << "ms" << endl;
    BOOST_CHECK_EQUAL(top.at(reason).size(), 20U);
    BOOST_CHECK_EQUAL(top.size(), 1U);

    struct timespec expired = now;
    expired.tv_sec += blockDuration + 1;
    sw.start();
    DynBlockMaintenance::purgeExpired(expired);
    cerr << "removed 1000000 entries in " << std::to_string(sw.udiff() / 1024) << "ms" << endl;
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getSuffixDynamicRules().getNodes().size(), 0U);
  }
#endif

#ifdef BENCH_DYNBLOCKS
  {
    /* now insert 1M clients */
    DynBlockRulesGroup dbrg;
    dbrg.setQuiet(true);
    g_rings.clear();
    dnsdist::DynamicBlocks::clearClientAddressDynamicRules();
    dnsdist::DynamicBlocks::clearSuffixDynamicRules();
    {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 0, 0, numberOfSeconds, action);
      dbrg.setQueryRate(std::move(rule));
    }

    bool done = false;
    for (size_t idxB = 0; !done && idxB < 256; idxB++) {
      for (size_t idxC = 0; !done && idxC < 256; idxC++) {
        for (size_t idxD = 0; !done && idxD < 256; idxD++) {
          const ComboAddress requestor("192." + std::to_string(idxB) + "." + std::to_string(idxC) + "." + std::to_string(idxD));
          g_rings.insertQuery(now, requestor, qname, qtype, size, dnsHeader, protocol);
          if (g_rings.getNumberOfQueryEntries() == 1000000) {
            done = true;
            break;
          }
        }
      }
    }

    /* we apply the rules, all clients should be blocked */
    StopWatch sw;
    sw.start();
    dbrg.apply(now);
    cerr << "added " << dnsdist::DynamicBlocks::getClientAddressDynamicRules().size() << " entries in " << std::to_string(sw.udiff() / 1024) << "ms" << endl;
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 1000000U);

    sw.start();
    auto top = DynBlockMaintenance::getTopNetmasks(20);
    cerr << "scanned " << dnsdist::DynamicBlocks::getClientAddressDynamicRules().size() << " entries in " << std::to_string(sw.udiff() / 1024) << "ms" << endl;

    struct timespec expired = now;
    expired.tv_sec += blockDuration + 1;
    sw.start();
    DynBlockMaintenance::purgeExpired(expired);
    cerr << "removed 1000000 entries in " << std::to_string(sw.udiff() / 1024) << "ms" << endl;
    BOOST_CHECK_EQUAL(dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(), 0U);
  }
#endif
}

BOOST_AUTO_TEST_CASE(test_NetmaskTree)
{
  NetmaskTree<int, AddressAndPortRange> nmt;
  BOOST_CHECK_EQUAL(nmt.empty(), true);
  BOOST_CHECK_EQUAL(nmt.size(), 0U);
  nmt.insert(AddressAndPortRange(ComboAddress("130.161.252.0"), 24, 0)).second = 0;
  BOOST_CHECK_EQUAL(nmt.empty(), false);
  BOOST_CHECK_EQUAL(nmt.size(), 1U);
  nmt.insert(AddressAndPortRange(ComboAddress("130.161.0.0"), 16, 0)).second = 1;
  BOOST_CHECK_EQUAL(nmt.size(), 2U);
  nmt.insert(AddressAndPortRange(ComboAddress("130.0.0.0"), 8, 0)).second = 2;
  BOOST_CHECK_EQUAL(nmt.size(), 3U);

  BOOST_CHECK(nmt.lookup(ComboAddress("213.244.168.210")) == nullptr);
  auto found = nmt.lookup(ComboAddress("130.161.252.29"));
  BOOST_REQUIRE(found);
  BOOST_CHECK_EQUAL(found->second, 0);
  found = nmt.lookup(ComboAddress("130.161.180.1"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 1);

  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.255.255.255"))->second, 2);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.161.252.255"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("130.161.253.255"))->second, 1);
  BOOST_CHECK_EQUAL(nmt.lookup(AddressAndPortRange(ComboAddress("130.255.255.255"), 32, 16))->second, 2);
  BOOST_CHECK_EQUAL(nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.255"), 32, 16))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(AddressAndPortRange(ComboAddress("130.161.253.255"), 32, 16))->second, 1);

  found = nmt.lookup(ComboAddress("130.145.180.1"));
  BOOST_CHECK(found);
  BOOST_CHECK_EQUAL(found->second, 2);

  nmt.insert(AddressAndPortRange(ComboAddress("0.0.0.0"), 0, 0)).second = 3;
  BOOST_CHECK_EQUAL(nmt.size(), 4U);
  nmt.insert(AddressAndPortRange(ComboAddress("0.0.0.0"), 7, 0)).second = 4;
  BOOST_CHECK_EQUAL(nmt.size(), 5U);
  nmt.insert(AddressAndPortRange(ComboAddress("0.0.0.0"), 15, 0)).second = 5;
  BOOST_CHECK_EQUAL(nmt.size(), 6U);
  BOOST_CHECK_EQUAL(nmt.lookup(AddressAndPortRange(ComboAddress("0.0.0.0"), 0, 0))->second, 3);
  BOOST_CHECK_EQUAL(nmt.lookup(AddressAndPortRange(ComboAddress("0.0.0.0"), 7, 0))->second, 4);
  BOOST_CHECK_EQUAL(nmt.lookup(AddressAndPortRange(ComboAddress("0.0.0.0"), 15, 0))->second, 5);
  BOOST_CHECK_EQUAL(nmt.lookup(AddressAndPortRange(ComboAddress("0.0.0.0"), 32, 0))->second, 5);

  nmt.clear();
  BOOST_CHECK_EQUAL(nmt.empty(), true);
  BOOST_CHECK_EQUAL(nmt.size(), 0U);
  BOOST_CHECK(!nmt.lookup(ComboAddress("130.161.180.1")));

  nmt.insert(AddressAndPortRange(ComboAddress("::1"), 128, 0)).second = 1;
  BOOST_CHECK_EQUAL(nmt.empty(), false);
  BOOST_CHECK_EQUAL(nmt.size(), 1U);
  nmt.insert(AddressAndPortRange(ComboAddress("::"), 0, 0)).second = 0;
  BOOST_CHECK_EQUAL(nmt.size(), 2U);
  nmt.insert(AddressAndPortRange(ComboAddress("fe80::"), 16, 0)).second = 2;
  BOOST_CHECK_EQUAL(nmt.size(), 3U);
  BOOST_CHECK(nmt.lookup(ComboAddress("130.161.253.255")) == nullptr);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::2"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::ffff"))->second, 0);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("::1"))->second, 1);
  BOOST_CHECK_EQUAL(nmt.lookup(ComboAddress("fe80::1"))->second, 2);
}

BOOST_AUTO_TEST_CASE(test_NetmaskTreePort)
{
  {
    /* exact port matching */
    NetmaskTree<int, AddressAndPortRange> nmt;
    BOOST_CHECK_EQUAL(nmt.empty(), true);
    BOOST_CHECK_EQUAL(nmt.size(), 0U);
    nmt.insert(AddressAndPortRange(ComboAddress("130.161.252.42:65534"), 32, 16)).second = 0;
    BOOST_CHECK_EQUAL(nmt.empty(), false);
    BOOST_CHECK_EQUAL(nmt.size(), 1U);

    BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("213.244.168.210"), 32, 16)) == nullptr);

    auto found = nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:65534"), 32, 16));
    BOOST_CHECK(found != nullptr);
    BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:65533"), 32, 16)) == nullptr);
    BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:65535"), 32, 16)) == nullptr);
  }

  {
    /* /15 port matching */
    NetmaskTree<int, AddressAndPortRange> nmt;
    BOOST_CHECK_EQUAL(nmt.empty(), true);
    BOOST_CHECK_EQUAL(nmt.size(), 0U);
    nmt.insert(AddressAndPortRange(ComboAddress("130.161.252.42:0"), 32, 15)).second = 0;
    BOOST_CHECK_EQUAL(nmt.empty(), false);
    BOOST_CHECK_EQUAL(nmt.size(), 1U);

    BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("213.244.168.210"), 32, 16)) == nullptr);

    auto found = nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:0"), 32, 16));
    BOOST_CHECK(found != nullptr);

    found = nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:1"), 32, 16));
    BOOST_CHECK(found != nullptr);

    /* everything else should be a miss */
    for (size_t idx = 2; idx <= 65535; idx++) {
      BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:" + std::to_string(idx)), 32, 16)) == nullptr);
    }

    nmt.clear();
    BOOST_CHECK_EQUAL(nmt.empty(), true);
    BOOST_CHECK_EQUAL(nmt.size(), 0U);
    nmt.insert(AddressAndPortRange(ComboAddress("130.161.252.42:65535"), 32, 15)).second = 0;
    BOOST_CHECK_EQUAL(nmt.empty(), false);
    BOOST_CHECK_EQUAL(nmt.size(), 1U);

    BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("213.244.168.210"), 32, 16)) == nullptr);

    /* everything else should be a miss */
    for (size_t idx = 0; idx <= 65533; idx++) {
      BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:" + std::to_string(idx)), 32, 16)) == nullptr);
    }
    found = nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:65534"), 32, 16));
    BOOST_CHECK(found != nullptr);
    found = nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:65535"), 32, 16));
    BOOST_CHECK(found != nullptr);
  }

  {
    /* /1 port matching */
    NetmaskTree<int, AddressAndPortRange> nmt;
    BOOST_CHECK_EQUAL(nmt.empty(), true);
    BOOST_CHECK_EQUAL(nmt.size(), 0U);
    nmt.insert(AddressAndPortRange(ComboAddress("130.161.252.42:0"), 32, 1)).second = 0;
    BOOST_CHECK_EQUAL(nmt.empty(), false);
    BOOST_CHECK_EQUAL(nmt.size(), 1U);

    BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("213.244.168.210"), 32, 16)) == nullptr);

    for (size_t idx = 0; idx <= 32767; idx++) {
      auto found = nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:" + std::to_string(idx)), 32, 16));
      BOOST_CHECK(found != nullptr);
    }

    /* everything else should be a miss */
    for (size_t idx = 32768; idx <= 65535; idx++) {
      BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("130.161.252.42:" + std::to_string(idx)), 32, 16)) == nullptr);
    }
  }

  {
    /* Check that the port matching does not apply to IPv6, where it does not make sense */

    /* /1 port matching */
    NetmaskTree<int, AddressAndPortRange> nmt;
    BOOST_CHECK_EQUAL(nmt.empty(), true);
    BOOST_CHECK_EQUAL(nmt.size(), 0U);
    nmt.insert(AddressAndPortRange(ComboAddress("[2001:db8::1]:0"), 128, 1)).second = 0;
    BOOST_CHECK_EQUAL(nmt.empty(), false);
    BOOST_CHECK_EQUAL(nmt.size(), 1U);

    /* different IP, no match */
    BOOST_CHECK(nmt.lookup(AddressAndPortRange(ComboAddress("[2001:db8::2]:0"), 128, 16)) == nullptr);

    /* all ports should match */
    for (size_t idx = 1; idx <= 65535; idx++) {
      auto found = nmt.lookup(AddressAndPortRange(ComboAddress("[2001:db8::1]:" + std::to_string(idx)), 128, 16));
      BOOST_CHECK(found != nullptr);
    }
  }
}

BOOST_AUTO_TEST_SUITE_END()
#endif /* DISABLE_DYNBLOCKS */
