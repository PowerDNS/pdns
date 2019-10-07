
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-rings.hh"

Rings g_rings;
GlobalStateHolder<NetmaskTree<DynBlock>> g_dynblockNMG;
GlobalStateHolder<SuffixMatchTree<DynBlock>> g_dynblockSMT;

BOOST_AUTO_TEST_SUITE(dnsdistdynblocks_hh)

BOOST_AUTO_TEST_CASE(test_DynBlockRulesGroup_QueryRate) {
  dnsheader dh;
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  /* block above 50 qps for numberOfSeconds seconds, no warning */
  dbrg.setQueryRate(50, 0, numberOfSeconds, reason, blockDuration, action);

  {
    /* insert 45 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 0U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 qps from a given client in the last 10s
       this should trigger the rule this time */
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);
    const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

}

BOOST_AUTO_TEST_CASE(test_DynBlockRulesGroup_QTypeRate) {
  dnsheader dh;
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  /* block above 50 qps for numberOfSeconds seconds, no warning */
  dbrg.setQTypeRate(QType::AAAA, 50, 0, numberOfSeconds, reason, blockDuration, action);

  {
    /* insert 45 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 0U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 qps from a given client in the last 10s
       but for the wrong QType */
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, QType::A, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 0U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) == nullptr);
  }

  {
    // insert just above 50 qps from a given client in the last 10s
    // this should trigger the rule this time
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);
    const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

}

BOOST_AUTO_TEST_CASE(test_DynBlockRulesGroup_RCodeRate) {
  dnsheader dh;
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  unsigned int responseTime = 100 * 1000; /* 100ms */
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";
  const uint16_t rcode = RCode::ServFail;

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  /* block above 50 ServFail/s for numberOfSeconds seconds, no warning */
  dbrg.setRCodeRate(rcode, 50, 0, numberOfSeconds, reason, blockDuration, action);

  {
    /* insert 45 ServFail/s from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfResponses = 45 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    dh.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dh, backend);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 0U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 FormErr/s from a given client in the last 10s */
    size_t numberOfResponses = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    dh.rcode = RCode::FormErr;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dh, backend);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 0U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 50 ServFail/s from a given client in the last 10s
       this should trigger the rule this time */
    size_t numberOfResponses = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    dh.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dh, backend);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);
    const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

}

BOOST_AUTO_TEST_CASE(test_DynBlockRulesGroup_ResponseByteRate) {
  dnsheader dh;
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 100;
  unsigned int responseTime = 100 * 1000; /* 100ms */
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";
  const uint16_t rcode = RCode::NoError;

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  /* block above 10kB/s for numberOfSeconds seconds, no warning */
  dbrg.setResponseByteRate(10000, 0, numberOfSeconds, reason, blockDuration, action);

  {
    /* insert 99 answers of 100 bytes per second from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfResponses = 99 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    dh.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dh, backend);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 0U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 100 answers of 100 bytes per second from a given client in the last 10s */
    size_t numberOfResponses = 100 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    dh.rcode = rcode;
    for (size_t idx = 0; idx < numberOfResponses; idx++) {
      g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dh, backend);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfResponseEntries(), numberOfResponses);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);
    const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

}

BOOST_AUTO_TEST_CASE(test_DynBlockRulesGroup_Warning) {
  dnsheader dh;
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.2");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock> emptyNMG;

  size_t numberOfSeconds = 10;
  size_t blockDuration = 60;
  const auto action = DNSAction::Action::Drop;
  const std::string reason = "Exceeded query rate";

  DynBlockRulesGroup dbrg;
  dbrg.setQuiet(true);

  /* warn above 20 qps for numberOfSeconds seconds, block above 50 qps */
  dbrg.setQueryRate(50, 20, numberOfSeconds, reason, blockDuration, action);

  {
    /* insert 20 qps from a given client in the last 10s
       this should not trigger the rule */
    size_t numberOfQueries = 20 * numberOfSeconds;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 0U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) == nullptr);
  }

  {
    /* insert just above 20 qps from a given client in the last 10s
       this should trigger the warning rule this time */
    size_t numberOfQueries = 20 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);

    {
      const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
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
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);

    {
      const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      /* this hsould have been preserved */
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
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);

    {
      const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      /* should have been updated */
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      /* this hsould have been preserved */
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
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);

    {
      const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
      BOOST_CHECK_EQUAL(block.reason, reason);
      BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
      BOOST_CHECK(block.domain.empty());
      BOOST_CHECK(block.action == action);
      BOOST_CHECK_EQUAL(block.blocks, 0U);
      BOOST_CHECK_EQUAL(block.warning, false);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_DynBlockRulesGroup_Ranges) {
  dnsheader dh;
  DNSName qname("rings.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress requestor2("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  struct timespec now;
  gettime(&now);
  NetmaskTree<DynBlock> emptyNMG;

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

  /* block above 50 qps for numberOfSeconds seconds, no warning */
  dbrg.setQueryRate(50, 0, numberOfSeconds, reason, blockDuration, action);

  {
    /* insert just above 50 qps from the two clients in the last 10s
       this should trigger the rule for the first one but not the second one */
    size_t numberOfQueries = 50 * numberOfSeconds + 1;
    g_rings.clear();
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);
    g_dynblockNMG.setState(emptyNMG);

    for (size_t idx = 0; idx < numberOfQueries; idx++) {
      g_rings.insertQuery(now, requestor1, qname, qtype, size, dh);
      g_rings.insertQuery(now, requestor2, qname, qtype, size, dh);
    }
    BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), numberOfQueries * 2);

    dbrg.apply(now);
    BOOST_CHECK_EQUAL(g_dynblockNMG.getLocal()->size(), 1U);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor1) != nullptr);
    BOOST_CHECK(g_dynblockNMG.getLocal()->lookup(requestor2) == nullptr);
    const auto& block = g_dynblockNMG.getLocal()->lookup(requestor1)->second;
    BOOST_CHECK_EQUAL(block.reason, reason);
    BOOST_CHECK_EQUAL(static_cast<size_t>(block.until.tv_sec), now.tv_sec + blockDuration);
    BOOST_CHECK(block.domain.empty());
    BOOST_CHECK(block.action == action);
    BOOST_CHECK_EQUAL(block.blocks, 0U);
    BOOST_CHECK_EQUAL(block.warning, false);
  }

}

BOOST_AUTO_TEST_SUITE_END()
