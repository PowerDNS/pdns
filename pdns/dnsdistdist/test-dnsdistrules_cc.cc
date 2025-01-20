
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <thread>
#include <variant>
#include <boost/test/unit_test.hpp>

#include "dnsdist-rules.hh"
#include "dnsdist-rules-factory.hh"

void checkParameterBound(const std::string& parameter, uint64_t value, size_t max)
{
  if (value > max) {
    throw std::runtime_error("The value passed to " + parameter + " is too large, the maximum is " + std::to_string(max));
  }
}

struct RuleParameter
{
  std::string name;
  std::variant<unsigned int, std::string> value;
};

template <typename ParameterType>
ParameterType getRequiredRuleParameter(const std::string& ruleName, std::vector<RuleParameter>& parameters, const std::string& parameterName)
{
  for (auto paramIt = parameters.begin(); paramIt != parameters.end(); ) {
    if (paramIt->name != parameterName) {
      ++paramIt;
      continue;
    }
    auto value = std::get<ParameterType>(paramIt->value);
    parameters.erase(paramIt);
    return value;
  }

  throw std::runtime_error("Missing required parameter '" + parameterName + "' for selector '" + ruleName + "'");
}

template <typename ParameterType>
ParameterType getOptionalRuleParameter(const std::string& ruleName, std::vector<RuleParameter>& parameters, const std::string& parameterName, ParameterType defaultValue)
{
  for (auto paramIt = parameters.begin(); paramIt != parameters.end(); ) {
    if (paramIt->name != parameterName) {
      ++paramIt;
      continue;
    }
    auto value = std::get<ParameterType>(paramIt->value);
    parameters.erase(paramIt);
    return value;
  }

  return defaultValue;
}

class TestMaxQPSIPRule : public DNSRule
{
public:
  TestMaxQPSIPRule(const std::string& ruleName, std::vector<RuleParameter>& parameters):
    d_qps(getRequiredRuleParameter<unsigned int>(ruleName, parameters, "qps")),
    d_burst(getOptionalRuleParameter<unsigned int>(ruleName, parameters, "burst", d_qps)),
    d_ipv4trunc(getOptionalRuleParameter<unsigned int>(ruleName, parameters, "ipv4-truncation", 32))
  {
  }

  bool matches(const DNSQuestion* dnsQuestion) const override
  {
    return true;
  }

  string toString() const override
  {
    return "";
  }
private:
  unsigned int d_qps;
  unsigned int d_burst;
  unsigned int d_ipv4trunc;
};

static std::shared_ptr<DNSRule> buildSelector(const std::string& type, std::vector<RuleParameter>& parameters)
{
  return std::make_shared<TestMaxQPSIPRule>(type, parameters);
}

static DNSQuestion getDQ(const DNSName* providedName = nullptr)
{
  static const DNSName qname("powerdns.com.");
  static PacketBuffer packet(sizeof(dnsheader));
  static InternalQueryState ids;
  ids.origDest = ComboAddress("127.0.0.1:53");
  ids.origRemote = ComboAddress("192.0.2.1:42");
  ids.qname = providedName ? *providedName : qname;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.queryRealTime.start();

  DNSQuestion dq(ids, packet);
  return dq;
}

BOOST_AUTO_TEST_SUITE(dnsdistluarules_cc)

BOOST_AUTO_TEST_CASE(test_MaxQPSIPRule) {
  size_t maxQPS = 10;
  size_t maxBurst = maxQPS;
  unsigned int expiration = 300;
  unsigned int cleanupDelay = 60;
  unsigned int scanFraction = 10;
  auto rule = dnsdist::selectors::getMaxQPSIPSelector(maxQPS, 32, 64, maxBurst, expiration, cleanupDelay, scanFraction, 1);

  InternalQueryState ids;
  ids.qname = DNSName("powerdns.com.");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.origDest = ComboAddress("127.0.0.1:53");
  ids.origRemote = ComboAddress("192.0.2.1:42");
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.queryRealTime.start();
  PacketBuffer packet(sizeof(dnsheader));
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  DNSQuestion dq(ids, packet);

  for (size_t idx = 0; idx < maxQPS; idx++) {
    /* let's use different source ports, it shouldn't matter */
    ids.origRemote = ComboAddress("192.0.2.1:" + std::to_string(idx));
    BOOST_CHECK_EQUAL(rule->matches(&dq), false);
    BOOST_CHECK_EQUAL(rule->getEntriesCount(), 1U);
  }

  /* maxQPS + 1, we should be blocked */
  BOOST_CHECK_EQUAL(rule->matches(&dq), true);
  BOOST_CHECK_EQUAL(rule->getEntriesCount(), 1U);

  /* remove all entries that have not been updated since 'now' + 1,
     so all of them */
  expiredTime.tv_sec += 1;
  rule->cleanup(expiredTime);

  /* we should have been cleaned up */
  BOOST_CHECK_EQUAL(rule->getEntriesCount(), 0U);

  struct timespec beginInsertionTime;
  gettime(&beginInsertionTime);
  /* we should not be blocked anymore */
  BOOST_CHECK_EQUAL(rule->matches(&dq), false);
  /* and we be back */
  BOOST_CHECK_EQUAL(rule->getEntriesCount(), 1U);


  /* Let's insert a lot of different sources now */
  for (size_t idxByte3 = 0; idxByte3 < 256; idxByte3++) {
    for (size_t idxByte4 = 0; idxByte4 < 256; idxByte4++) {
      ids.origRemote = ComboAddress("10.0." + std::to_string(idxByte3) + "." + std::to_string(idxByte4));
      BOOST_CHECK_EQUAL(rule->matches(&dq), false);
    }
  }
  struct timespec endInsertionTime;
  gettime(&endInsertionTime);

  /* don't forget the existing entry */
  size_t total = 1 + 256 * 256;
  BOOST_CHECK_EQUAL(rule->getEntriesCount(), total);

  /* make sure all entries are still valid */
  struct timespec notExpiredTime = beginInsertionTime;
  notExpiredTime.tv_sec -= 1;

  size_t scanned = 0;
  auto removed = rule->cleanup(notExpiredTime, &scanned);
  BOOST_CHECK_EQUAL(removed, 0U);
  /* the first entry should still have been valid, we should not have scanned more */
  BOOST_CHECK_EQUAL(scanned, rule->getNumberOfShards());
  BOOST_CHECK_EQUAL(rule->getEntriesCount(), total);

  /* make sure all entries are _not_ valid anymore */
  expiredTime = endInsertionTime;
  expiredTime.tv_sec += 1;

  removed = rule->cleanup(expiredTime, &scanned);
  BOOST_CHECK_EQUAL(removed, (total / scanFraction) + 1 + rule->getNumberOfShards());
  /* we should not have scanned more than scanFraction */
  BOOST_CHECK_EQUAL(scanned, removed);
  BOOST_CHECK_EQUAL(rule->getEntriesCount(), total - removed);

  rule->clear();
  BOOST_CHECK_EQUAL(rule->getEntriesCount(), 0U);
  removed = rule->cleanup(expiredTime, &scanned);
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

  BOOST_CHECK_EQUAL(sp.poolLoad(), 400U + 30U);

  addServerToPool("test", ds1);
  addServerToPool("test", ds2);

  PoolOutstandingRule pOR1("test", 10);
  BOOST_CHECK_EQUAL(pOR1.matches(&dq), true);

  PoolOutstandingRule pOR2("test", 1000);
  BOOST_CHECK_EQUAL(pOR2.matches(&dq), false);
}

BOOST_AUTO_TEST_CASE(test_payloadSizeRule) {
  auto dnsQuestion = getDQ();

  {
    PayloadSizeRule rule("equal", dnsQuestion.getData().size());
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), true);
    BOOST_CHECK_EQUAL(rule.toString(), "payload size is equal to " + std::to_string(dnsQuestion.getData().size()));
  }

  {
    PayloadSizeRule rule("equal", dnsQuestion.getData().size() + 1);
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), false);
  }

  {
    PayloadSizeRule rule("greater", dnsQuestion.getData().size());
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), false);
    BOOST_CHECK_EQUAL(rule.toString(), "payload size is greater than " + std::to_string(dnsQuestion.getData().size()));
  }

  {
    PayloadSizeRule rule("greater", dnsQuestion.getData().size() - 1);
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), true);
  }

  {
    PayloadSizeRule rule("smaller", dnsQuestion.getData().size());
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), false);
    BOOST_CHECK_EQUAL(rule.toString(), "payload size is smaller than " + std::to_string(dnsQuestion.getData().size()));
  }

  {
    PayloadSizeRule rule("smaller", dnsQuestion.getData().size() + 1);
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), true);
  }

  {
    PayloadSizeRule rule("greaterOrEqual", dnsQuestion.getData().size());
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), true);
    BOOST_CHECK_EQUAL(rule.toString(), "payload size is equal to or greater than " + std::to_string(dnsQuestion.getData().size()));
  }

  {
    PayloadSizeRule rule("greaterOrEqual", dnsQuestion.getData().size() - 1);
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), true);
  }

  {
    PayloadSizeRule rule("greaterOrEqual", dnsQuestion.getData().size() + 1);
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), false);
  }

  {
    PayloadSizeRule rule("smallerOrEqual", dnsQuestion.getData().size());
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), true);
    BOOST_CHECK_EQUAL(rule.toString(), "payload size is equal to or smaller than " + std::to_string(dnsQuestion.getData().size()));
  }

  {
    PayloadSizeRule rule("smallerOrEqual", dnsQuestion.getData().size() + 1);
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), true);
  }

  {
    PayloadSizeRule rule("smallerOrEqual", dnsQuestion.getData().size() - 1);
    BOOST_CHECK_EQUAL(rule.matches(&dnsQuestion), false);
  }

  BOOST_CHECK_THROW(PayloadSizeRule("invalid", 42U), std::runtime_error);

  std::vector<RuleParameter> parameters{
    RuleParameter{ "qps", 5U },
    RuleParameter{ "ipv4-truncation", 24U },
  };
  auto got = buildSelector("TestMaxQPSIPRule", parameters);
}

BOOST_AUTO_TEST_SUITE_END()
