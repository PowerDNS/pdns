
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <thread>
#include <boost/test/unit_test.hpp>

#include "dnsdist.hh"
#include "dnsdist-lua-ffi.hh"
#include "dolog.hh"

uint16_t g_maxOutstanding{std::numeric_limits<uint16_t>::max()};
std::mutex g_luamutex;

static std::shared_ptr<DownstreamState> getSelectedBackendFromPolicy(const ServerPolicy& policy, const ServerPolicy::NumberedServerVector& servers, DNSQuestion& dq)
{
  std::shared_ptr<DownstreamState> selectedBackend{nullptr};

  if (policy.isLua) {
    if (!policy.isFFI) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      selectedBackend = policy.policy(servers, &dq);
    }
    else {
      dnsdist_ffi_dnsquestion_t dnsq(&dq);
      dnsdist_ffi_servers_list_t serversList(servers);
      unsigned int selected = 0;
      {
        std::lock_guard<std::mutex> lock(g_luamutex);
        selected = policy.ffipolicy(&serversList, &dnsq);
      }
      selectedBackend = servers.at(selected).second;
    }
  }
  else {
    selectedBackend = policy.policy(servers, &dq);
  }

  return selectedBackend;
}

static DNSQuestion getDQ(const DNSName* providedName = nullptr)
{
  static const DNSName qname("powerdns.com.");
  static const ComboAddress lc("127.0.0.1:53");
  static const ComboAddress rem("192.0.2.1:42");
  static struct timespec queryRealTime;
  static struct dnsheader dh;

  memset(&dh, 0, sizeof(dh));
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  size_t bufferSize = 0;
  size_t queryLen = 0;
  bool isTcp = false;
  gettime(&queryRealTime, true);

  DNSQuestion dq(providedName ? providedName : &qname, qtype, qclass, qname.wirelength(), &lc, &rem, &dh, bufferSize, queryLen, isTcp, &queryRealTime);
  return dq;
}

BOOST_AUTO_TEST_SUITE(dnsdistlbpolicies)

BOOST_AUTO_TEST_CASE(test_firstAvailable) {
  auto dq = getDQ();

  ServerPolicy pol{"firstAvailable", firstAvailable, false};
  ServerPolicy::NumberedServerVector servers;
  servers.push_back({ 1, std::make_shared<DownstreamState>(ComboAddress("192.0.2.1:53")) });

  /* servers start as 'down' */
  auto server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_CHECK(server == nullptr);

  /* mark the server as 'up' */
  servers.at(0).second->setUp();
  server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_CHECK(server != nullptr);

  /* add a second server, we should still get the first one */
  servers.push_back({ 2, std::make_shared<DownstreamState>(ComboAddress("192.0.2.2:53")) });
  server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(0).second);

  /* mark the first server as 'down', second as 'up' */
  servers.at(0).second->setDown();
  servers.at(1).second->setUp();
  server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);
}

BOOST_AUTO_TEST_CASE(test_leastOutstanding) {
  auto dq = getDQ();

  ServerPolicy pol{"leastOutstanding", leastOutstanding, false};
  ServerPolicy::NumberedServerVector servers;
  servers.push_back({ 1, std::make_shared<DownstreamState>(ComboAddress("192.0.2.1:53")) });

  /* servers start as 'down' */
  auto server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_CHECK(server == nullptr);

  /* mark the server as 'up' */
  servers.at(0).second->setUp();
  server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_CHECK(server != nullptr);

  /* add a second server, we should still get the first one */
  servers.push_back({ 2, std::make_shared<DownstreamState>(ComboAddress("192.0.2.2:53")) });
  server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(0).second);

  /* mark the first server as 'down', second as 'up' */
  servers.at(0).second->setDown();
  servers.at(1).second->setUp();
  server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);

  /* mark both servers as 'up', increase the outstanding count of the first one */
  servers.at(0).second->setUp();
  servers.at(0).second->outstanding = 42;
  servers.at(1).second->setUp();
  server = getSelectedBackendFromPolicy(pol, servers, dq);
  BOOST_REQUIRE(server != nullptr);
  BOOST_CHECK(server == servers.at(1).second);
}

BOOST_AUTO_TEST_CASE(test_wrandom) {
  auto dq = getDQ();

  ServerPolicy pol{"wrandom", wrandom, false};
  ServerPolicy::NumberedServerVector servers;
  std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
  for (size_t idx = 1; idx <= 10; idx++) {
    servers.push_back({ idx + 1, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")) });
    serversMap[servers.at(idx - 1).second] = 0;
    servers.at(idx - 1).second->setUp();
  }

  for (size_t idx = 0; idx < 1000; idx++) {
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }
  uint64_t total = 0;
  for (const auto& entry : serversMap) {
    BOOST_CHECK_GT(entry.second, 0);
    BOOST_CHECK_GT(entry.second, (1000 / servers.size() / 2));
    BOOST_CHECK_LT(entry.second, (1000 / servers.size() * 2));
    total += entry.second;
  }
  BOOST_CHECK_EQUAL(total, 1000);

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->weight, 1);
  }

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->weight, 1);
  }
  /* change the weight of the last server to 100, default is 1 */
  servers.at(servers.size()-1).second->weight = 100;

  for (size_t idx = 0; idx < 1000; idx++) {
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  total = 0;
  uint64_t totalW = 0;
  for (const auto& entry : serversMap) {
    total += entry.second;
    totalW += entry.first->weight;
  }
  BOOST_CHECK_EQUAL(total, 1000);
  auto last = servers.at(servers.size()-1).second;
  const auto got = serversMap[last];
  float expected = (1000 * 1.0 * last->weight) / totalW;
  BOOST_CHECK_GT(got, expected / 2);
  BOOST_CHECK_LT(got, expected * 2);
}

BOOST_AUTO_TEST_CASE(test_whashed) {
  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.push_back(DNSName("powerdns-" + std::to_string(idx) + ".com."));
  }

  ServerPolicy pol{"whashed", whashed, false};
  ServerPolicy::NumberedServerVector servers;
  std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
  for (size_t idx = 1; idx <= 10; idx++) {
    servers.push_back({ idx + 1, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")) });
    serversMap[servers.at(idx - 1).second] = 0;
    servers.at(idx - 1).second->setUp();
  }

  for (const auto& name : names) {
    auto dq = getDQ(&name);
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }
  uint64_t total = 0;
  for (const auto& entry : serversMap) {
    BOOST_CHECK_GT(entry.second, 0);
    BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
    BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
    total += entry.second;
  }
  BOOST_CHECK_EQUAL(total, names.size());

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->weight, 1);
  }

  /* request 1000 times the same name, we should go to the same server every time */
  {
    auto dq = getDQ(&names.at(0));
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    for (size_t idx = 0; idx < 1000; idx++) {
      BOOST_CHECK(getSelectedBackendFromPolicy(pol, servers, dq) == server);
    }
  }

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->weight, 1);
  }
  /* change the weight of the last server to 100, default is 1 */
  servers.at(servers.size()-1).second->setWeight(100);

  for (const auto& name : names) {
    auto dq = getDQ(&name);
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  total = 0;
  uint64_t totalW = 0;
  for (const auto& entry : serversMap) {
    total += entry.second;
    totalW += entry.first->weight;
  }
  BOOST_CHECK_EQUAL(total, names.size());
  auto last = servers.at(servers.size()-1).second;
  const auto got = serversMap[last];
  float expected = (names.size() * 1.0 * last->weight) / totalW;
  BOOST_CHECK_GT(got, expected / 2);
  BOOST_CHECK_LT(got, expected * 2);
}

BOOST_AUTO_TEST_CASE(test_chashed) {
  bool existingVerboseValue = g_verbose;
  g_verbose = false;

  std::vector<DNSName> names;
  names.reserve(1000);
  for (size_t idx = 0; idx < 1000; idx++) {
    names.push_back(DNSName("powerdns-" + std::to_string(idx) + ".com."));
  }

  ServerPolicy pol{"chashed", chashed, false};
  ServerPolicy::NumberedServerVector servers;
  std::map<std::shared_ptr<DownstreamState>, uint64_t> serversMap;
  for (size_t idx = 1; idx <= 10; idx++) {
    servers.push_back({ idx + 1, std::make_shared<DownstreamState>(ComboAddress("192.0.2." + std::to_string(idx) + ":53")) });
    serversMap[servers.at(idx - 1).second] = 0;
    servers.at(idx - 1).second->setUp();
    /* we need to have a weight of at least 1000 to get an optimal repartition with the consistent hashing algo */
    servers.at(idx - 1).second->setWeight(1000);
    /* make sure that the hashes have been computed */
    servers.at(idx - 1).second->hash();
  }

  for (const auto& name : names) {
    auto dq = getDQ(&name);
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }
  uint64_t total = 0;
  for (const auto& entry : serversMap) {
    BOOST_CHECK_GT(entry.second, 0);
    BOOST_CHECK_GT(entry.second, (names.size() / servers.size() / 2));
    BOOST_CHECK_LT(entry.second, (names.size() / servers.size() * 2));
    total += entry.second;
  }
  BOOST_CHECK_EQUAL(total, names.size());

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->weight, 1000);
  }

  /* request 1000 times the same name, we should go to the same server every time */
  {
    auto dq = getDQ(&names.at(0));
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    for (size_t idx = 0; idx < 1000; idx++) {
      BOOST_CHECK(getSelectedBackendFromPolicy(pol, servers, dq) == server);
    }
  }

  /* reset */
  for (auto& entry : serversMap) {
    entry.second = 0;
    BOOST_CHECK_EQUAL(entry.first->weight, 1000);
  }
  /* change the weight of the last server to 100000, others stay at 1000 */
  servers.at(servers.size()-1).second->setWeight(100000);

  for (const auto& name : names) {
    auto dq = getDQ(&name);
    auto server = getSelectedBackendFromPolicy(pol, servers, dq);
    BOOST_REQUIRE(serversMap.count(server) == 1);
    ++serversMap[server];
  }

  total = 0;
  uint64_t totalW = 0;
  for (const auto& entry : serversMap) {
    total += entry.second;
    totalW += entry.first->weight;
  }
  BOOST_CHECK_EQUAL(total, names.size());
  auto last = servers.at(servers.size()-1).second;
  const auto got = serversMap[last];
  float expected = (names.size() * 1.0 * last->weight) / totalW;
  BOOST_CHECK_GT(got, expected / 2);
  BOOST_CHECK_LT(got, expected * 2);

  g_verbose = existingVerboseValue;
}

BOOST_AUTO_TEST_SUITE_END()
